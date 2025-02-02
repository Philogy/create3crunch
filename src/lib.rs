use clap as _;
use clap_num as _;

use alloy_primitives::{hex, Address, FixedBytes};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use console::Term;
use fs4::FileExt;
use ocl::{Buffer, Context, Device, MemFlags, Platform, ProQue, Program, Queue};
use rand::{thread_rng, Rng};
use reqwest::blocking::Client;
use separator::Separatable;
use serde::Serialize;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use terminal_size::{terminal_size, Height};

pub mod pattern;
mod reward;
pub use crate::pattern::Pattern;
pub use reward::Reward;

static KERNEL_SRC: &str = include_str!("./kernels/keccak256.cl");

pub struct Config {
    pub factory: Address,
    pub owner: Address,
    pub init_code_hash: FixedBytes<32>,
    pub work_size: u32,
    pub gpu_device: u8,
    pub max_create3_nonce: u8,
    pub total_zeroes: Option<u8>,
    pub output_file: String,
    pub post_url: Option<String>,
    pub patterns: Vec<Pattern>,
}

pub fn gpu(config: Config) -> ocl::Result<()> {
    println!(
        "Setting up experimental OpenCL miner using device {}...",
        config.gpu_device
    );

    // (create if necessary) and open a file where found salts will be written
    let file = output_file(&config.output_file);

    // create object for computing rewards (relative rarity) for a given address
    let rewards = Reward::new();

    // track how many addresses have been found and information about them
    let mut found: u64 = 0;
    let mut found_list: Vec<String> = vec![];

    // set up a controller for terminal output
    let term = Term::stdout();

    // set up a platform to use
    let platform = Platform::new(ocl::core::default_platform()?);

    // set up the device to use
    let device = Device::by_idx_wrap(platform, config.gpu_device as usize)?;

    // set up the context to use
    let context = Context::builder()
        .platform(platform)
        .devices(device)
        .build()?;

    // set up the program to use
    let program = Program::builder()
        .devices(device)
        .src(mk_kernel_src(&config))
        .build(&context)?;

    // set up the queue to use
    let queue = Queue::new(&context, device, None)?;

    let work_size = config.work_size;
    // set up the "proqueue" (or amalgamation of various elements) to use
    let ocl_pq = ProQue::new(context, queue, program, Some(work_size));
    let work_factor = (work_size as u128) / 1_000_000;

    // create a random number generator
    let mut rng = thread_rng();

    // determine the start time
    let start_time: f64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    // set up variables for tracking performance
    let mut rate: f64 = 0.0;
    let mut cumulative_nonce: u64 = 0;

    // the previous timestamp of printing to the terminal
    let mut previous_time: f64 = 0.0;

    // the last work duration in milliseconds
    let mut work_duration_millis: u64 = 0;

    // begin searching for addresses
    loop {
        // construct the 4-byte message to hash, leaving last 8 of salt empty
        let salt = FixedBytes::<4>::random();

        // build a corresponding buffer for passing the message to the kernel
        let message_buffer = Buffer::builder()
            .queue(ocl_pq.queue().clone())
            .flags(MemFlags::new().read_only())
            .len(4)
            .copy_host_slice(&salt[..])
            .build()?;

        // reset nonce & create a buffer to view it in little-endian
        // for more uniformly distributed nonces, we shall initialize it to a random value
        let mut nonce: [u32; 1] = rng.gen();
        let mut view_buf = [0; 8];

        // build a corresponding buffer for passing the nonce to the kernel
        let mut nonce_buffer = Buffer::builder()
            .queue(ocl_pq.queue().clone())
            .flags(MemFlags::new().read_only())
            .len(1)
            .copy_host_slice(&nonce)
            .build()?;

        // establish a buffer for nonces that result in desired addresses
        let mut solutions: Vec<u64> = vec![0; 2];
        let solutions_buffer = Buffer::builder()
            .queue(ocl_pq.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(solutions.len())
            .copy_host_slice(&solutions)
            .build()?;

        // repeatedly enqueue kernel to search for new addresses
        loop {
            // build the kernel and define the type of each buffer
            let kern = ocl_pq
                .kernel_builder("hashMessage")
                .arg_named("message", None::<&Buffer<u8>>)
                .arg_named("nonce", None::<&Buffer<u32>>)
                .arg_named("solutions", None::<&Buffer<u64>>)
                .build()?;

            // set each buffer
            kern.set_arg("message", Some(&message_buffer))?;
            kern.set_arg("nonce", Some(&nonce_buffer))?;
            kern.set_arg("solutions", &solutions_buffer)?;

            // enqueue the kernel
            unsafe { kern.enq()? };

            // calculate the current time
            let mut now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let current_time = now.as_secs() as f64;

            // we don't want to print too fast
            let print_output = current_time - previous_time > 0.99;
            previous_time = current_time;

            // clear the terminal screen
            if print_output {
                term.clear_screen()?;

                // get the total runtime and parse into hours : minutes : seconds
                let total_runtime = current_time - start_time;
                let total_runtime_hrs = total_runtime as u64 / 3600;
                let total_runtime_mins = (total_runtime as u64 - total_runtime_hrs * 3600) / 60;
                let total_runtime_secs = total_runtime
                    - (total_runtime_hrs * 3600) as f64
                    - (total_runtime_mins * 60) as f64;

                // determine the number of attempts being made per second
                let work_rate: u128 =
                    work_factor * cumulative_nonce as u128 * config.max_create3_nonce as u128;
                if total_runtime > 0.0 {
                    rate = 1.0 / total_runtime;
                }

                // fill the buffer for viewing the properly-formatted nonce
                LittleEndian::write_u64(&mut view_buf, (nonce[0] as u64) << 32);

                // calculate the terminal height, defaulting to a height of ten rows
                let height = terminal_size().map(|(_w, Height(h))| h).unwrap_or(10);

                // display information about the total runtime and work size
                term.write_line(&format!(
                    "total runtime: {}:{:02}:{:02} ({} cycles)\t\t\t\
                     work size per cycle: {}",
                    total_runtime_hrs,
                    total_runtime_mins,
                    total_runtime_secs,
                    cumulative_nonce,
                    work_size.separated_string(),
                ))?;

                // display information about the attempt rate and found solutions
                term.write_line(&format!(
                    "rate: {:.2} million attempts per second\t\t\t\
                     total found this run: {}",
                    work_rate as f64 * rate,
                    found
                ))?;

                // display information about the current search criteria
                term.write_line(&format!(
                    "current search space: {}xxxxxxxx{:08x}\t\t\
                     threshold: {:?} total zeroes",
                    hex::encode(salt),
                    BigEndian::read_u64(&view_buf),
                    config.total_zeroes
                ))?;

                // display recently found solutions based on terminal height
                let rows = if height < 5 { 1 } else { height as usize - 4 };
                let last_rows: Vec<String> = found_list.iter().cloned().rev().take(rows).collect();
                let ordered: Vec<String> = last_rows.iter().cloned().rev().collect();
                let recently_found = &ordered.join("\n");
                term.write_line(recently_found)?;
            }

            // increment the cumulative nonce (does not reset after a match)
            cumulative_nonce += 1;

            // record the start time of the work
            let work_start_time_millis = now.as_secs() * 1000 + now.subsec_nanos() as u64 / 1000000;

            // sleep for 98% of the previous work duration to conserve CPU
            if work_duration_millis != 0 {
                std::thread::sleep(std::time::Duration::from_millis(
                    work_duration_millis * 980 / 1000,
                ));
            }

            // read the solutions from the device
            solutions_buffer.read(&mut solutions).enq()?;

            // record the end time of the work and compute how long the work took
            now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            work_duration_millis = (now.as_secs() * 1000 + now.subsec_nanos() as u64 / 1000000)
                - work_start_time_millis;

            // if at least one solution is found, end the loop
            if solutions[0] != 0 {
                break;
            }

            // if no solution has yet been found, increment the nonce
            nonce[0] += 1;

            // update the nonce buffer with the incremented nonce value
            nonce_buffer = Buffer::builder()
                .queue(ocl_pq.queue().clone())
                .flags(MemFlags::new().read_write())
                .len(1)
                .copy_host_slice(&nonce)
                .build()?;
        }

        // iterate over each solution, first converting to a fixed array

        if solutions[0] != 0 {
            let create1_nonce = solutions[1];
            let create2_nonce = solutions[0].to_le_bytes();
            let mut create2_salt = [0u8; 32];
            create2_salt[0..20].copy_from_slice(&config.owner[..]);
            create2_salt[20..24].copy_from_slice(&salt[..]);
            create2_salt[24..32].copy_from_slice(&create2_nonce);
            let deployer = config
                .factory
                .create2(&create2_salt, &config.init_code_hash);
            let address = deployer.create(create1_nonce.into());

            // count total zero bytes
            let total = address.iter().filter(|&&b| b == 0).count();

            let key = total;
            let reward = rewards.get(&key).unwrap_or("0");
            let salt = hex::encode(create2_salt);
            let contract_salt_nonce = create1_nonce - 1;
            let output = format!(
                "0x{} ({}) => {} => {}",
                salt, contract_salt_nonce, address, reward
            );

            let show = format!("{output} (total zeros: {total})");
            found_list.push(show.to_string());

            file.lock_exclusive().expect("Couldn't lock file.");

            writeln!(&file, "{output}")
                .unwrap_or_else(|_| panic!("Couldn't write to `{}` file.", config.output_file));

            #[allow(unstable_name_collisions)]
            file.unlock().expect("Couldn't unlock file.");

            // If the post_url is set, send a POST request to it in a separate thread
            if let Some(url) = config.post_url.clone() {
                let data = PostData {
                    salt,
                    nonce: contract_salt_nonce,
                    total,
                    address: address.to_string(),
                    reward: reward.to_string(),
                };
                thread::spawn(move || {
                    let client = Client::new();
                    match client.post(url).json(&data).send() {
                        Ok(response) => {
                            println!("Successfully POSTed {}: {:?}", &data.address, response)
                        }
                        Err(e) => eprintln!("Failed to POST result address. Error: {:?}", e),
                    }
                });
            }

            found += 1;
        }
    }
}

#[derive(Serialize)]
struct PostData {
    salt: String,
    nonce: u64,
    address: String,
    total: usize,
    reward: String,
}

#[track_caller]
fn output_file(path: &str) -> File {
    OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open(path)
        .unwrap_or_else(|_| panic!("Could not create or open `{}` file.", path))
}

fn mk_kernel_src(config: &Config) -> String {
    let mut src = String::with_capacity(2048 + KERNEL_SRC.len());

    let factory = config.factory.iter();
    let owner = config.owner.iter();
    let hash = config.init_code_hash.iter();
    let hash = hash.enumerate().map(|(i, x)| (i + 52, x));
    for (i, x) in factory.chain(owner).enumerate().chain(hash) {
        writeln!(src, "#define S_{} {}u", i + 1, x).unwrap();
    }

    let tz = config.total_zeroes.unwrap_or(0);
    writeln!(src, "#define TOTAL_ZEROES {tz}").unwrap();

    let mut conditions = vec![];
    if config.total_zeroes.is_some() {
        conditions.push("hasTotal(digest)");
    }

    // Define pattern matching constants and function if patterns are provided
    if !config.patterns.is_empty() {
        for (i, pattern) in config.patterns.iter().enumerate() {
            for (j, &byte) in pattern.target.as_le_bytes().iter().enumerate() {
                writeln!(src, "#define PATTERN_{}_{} {}u", i, j, byte).unwrap();
            }
            for (j, &byte) in pattern.mask.as_le_bytes().iter().enumerate() {
                writeln!(src, "#define MASK_{}_{} {}u", i, j, byte).unwrap();
            }
        }

        // Generate the pattern_match function
        writeln!(src, "bool pattern_match(const uchar *address) {{").unwrap();
        src.push_str("    return \n");

        for (i, _pattern) in config.patterns.iter().enumerate() {
            if i > 0 {
                src.push_str("        ||\n");
            }
            src.push_str("        (");
            for j in 0..20 {
                if j > 0 {
                    src.push_str(" &&\n            ");
                }
                write!(src, "((address[{j}] & MASK_{i}_{j}) == PATTERN_{i}_{j})").unwrap();
            }
            src.push_str(")");
        }
        src.push_str(";\n}\n");

        conditions.push("pattern_match(digest)");
    }

    let condition = if conditions.is_empty() {
        "false".to_string()
    } else {
        conditions.join(" || ")
    };

    writeln!(src, "#define SUCCESS_CONDITION() ({})", condition).unwrap();

    writeln!(src, "#define MAX_NONCE {}u", config.max_create3_nonce).unwrap();

    src.push_str(KERNEL_SRC);

    src
}
