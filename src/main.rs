use alloy_primitives::{Address, FixedBytes};
use clap::Parser;
use clap_num::maybe_hex;
use create3crunch::{gpu, Config, Pattern};
use std::str::FromStr;

fn parse_worksize(s: &str) -> Result<u32, String> {
    let work_size = maybe_hex::<u32>(s)?;
    if work_size < 0x1540000 {
        return Err("Work size cannot be below 0x1540000".to_string());
    }
    Ok(work_size)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        help = "Address of the CREATE3 factory contract (default = Sub Zero Factory)",
        default_value = "0x000000000000b361194cfe6312ee3210d53c15aa"
    )]
    factory: Address,

    #[arg(
        short,
        long,
        help = "Owner / Caller address (first 20 bytes of the top-level salt will be set to the address)"
    )]
    owner: Address,

    #[arg(
        short,
        long,
        help = "Hash of the factory's deploy proxy initcode (default = Sub Zero Deploy Proxy)",
        default_value = "0x1decbcf04b355d500cbc3bd83c892545b4df34bd5b2c9d91b9f7f8165e2095c3"
    )]
    init_code_hash: FixedBytes<32>,

    #[arg(short, long, help = "GPU Device")]
    gpu_device: u8,

    #[arg(
        short,
        long,
        help = "Minimum amount of total zero bytes for the address to be considered valuable"
    )]
    total_zeros: Option<u8>,

    #[arg(
        short,
        long,
        help = "Specifies the upper bound for the nonces that will be inclusively checked (1 - n), at most 127",
        default_value_t = 32
    )]
    max_create3_nonce: u8,

    #[arg(
        short,
        long,
        help = "Whether to default patterns to being case sensitive",
        default_value_t = false
    )]
    case_sensitive: bool,

    #[arg(
        short,
        long,
        value_parser = parse_worksize,
        default_value_t = 0x4000000,
        help = "Specifies the GPU work size, min. 0x154000"
    )]
    work_size: u32,

    #[arg(
        short = 'p',
        long,
        default_value = "efficient_addresses.txt",
        help = "The file to output efficient addresses to"
    )]
    output_file: String,

    #[arg(long, default_value = None, help = "URL to POST efficient addresses to")]
    post_url: Option<String>,

    #[arg(
        short,
        long = "pattern",
        help = "Custom address patterns to match (e.g., 0xefefxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx). You can use 'x' for wildcard nibbles and define bits inside brackets, e.g., [xxxxxx01]",
        action = clap::ArgAction::Append
    )]
    patterns: Vec<String>,
}

impl TryInto<Config> for Args {
    type Error = String;

    fn try_into(self) -> Result<Config, Self::Error> {
        if self.total_zeros.is_none() && self.patterns.is_empty() {
            return Err("Must specify at least one of total zeros or a custom pattern".to_string());
        }

        let patterns = self
            .patterns
            .into_iter()
            .map(|pattern| {
                let pattern_str = pattern.as_str();
                let stripped = pattern_str.strip_prefix("!");
                let force_capitalize = stripped.is_some();
                let pattern_str = stripped.unwrap_or(pattern_str);
                let mut pattern = Pattern::from_str(pattern_str).map_err(|err| {
                    format!("Error occured when parsing pattern {:?}: {}", pattern, err)
                })?;

                if !(force_capitalize || self.case_sensitive) {
                    pattern.capitalizations = [None; 40];
                }

                Ok(pattern)
            })
            .collect::<Result<Vec<Pattern>, String>>()?;

        Ok(Config {
            factory: self.factory,
            owner: self.owner,
            init_code_hash: self.init_code_hash,
            work_size: self.work_size,
            gpu_device: self.gpu_device,
            total_zeroes: self.total_zeros,
            patterns,
            max_create3_nonce: self.max_create3_nonce,
            output_file: self.output_file,
            post_url: self.post_url,
        })
    }
}

fn main() {
    let args = Args::parse();
    println!("Starting miner with args: {:?}", args);

    gpu(args.try_into().unwrap()).unwrap()
}
