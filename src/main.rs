use alloy_primitives::{Address, FixedBytes};
use clap::Parser;
use clap_num::maybe_hex;
use create3crunch::{gpu, Config, Pattern};

fn parse_worksize(s: &str) -> Result<u32, String> {
    let work_size = maybe_hex::<u32>(s)?;
    if work_size < 0x1540000 {
        return Err("Work size cannot be below 0x15400000".to_string());
    }
    Ok(work_size)
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        help = "Address of the CREATE3 factory contract",
        default_value = "0x000000000000b361194cfe6312ee3210d53c15aa"
    )]
    factory: Address,

    #[arg(
        short,
        long,
        help = "Owner / Caller address (first 20-bytes of the top-level salt will be set to the address)"
    )]
    owner: Address,

    #[arg(
        short,
        long,
        help = "Hash of the factory's deploy proxy initcode",
        default_value = "0x1decbcf04b355d500cbc3bd83c892545b4df34bd5b2c9d91b9f7f8165e2095c3"
    )]
    initcode_hash: FixedBytes<32>,

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
        long,
        help = "Custom address patterns to match (e.g., 0xefefxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx). You can use 'x' for wildcard nibbles.",
        action = clap::ArgAction::Append
    )]
    pattern: Vec<String>,
}

impl TryInto<Config> for Args {
    type Error = String;

    fn try_into(self) -> Result<Config, Self::Error> {
        if self.total_zeros.is_none() && self.pattern.is_empty() {
            return Err("Must specify at least one of total zeros or a custom pattern".to_string());
        }

        // Parse the patterns if provided
        let mut patterns = Vec::new();

        for pattern_str in &self.pattern {
            // Remove '0x' prefix if present (only once)
            let pattern_str = pattern_str.strip_prefix("0x").unwrap_or(pattern_str);

            if pattern_str.len() > 40 {
                return Err("Pattern length cannot exceed 40 characters (20 bytes).".to_string());
            }

            let mut pattern_bytes = [0u8; 20]; // Initialize with zeros
            let mut mask_bytes = [0u8; 20]; // Initialize with zeros

            let chars: Vec<char> = pattern_str.chars().collect();
            let mut i = 0; // byte index
            let mut nibble = 0; // character index

            while i < 20 && nibble < chars.len() {
                let c = chars[nibble];
                let nibble_value = match c {
                    'x' | 'X' => {
                        // Wildcard nibble
                        // Do not set any bits in mask_bytes[i]
                        0
                    }
                    c if c.is_digit(16) => {
                        // Hex digit
                        // Set the corresponding nibble in pattern_bytes[i]
                        if nibble % 2 == 0 {
                            mask_bytes[i] |= 0xF0; // High nibble
                        } else {
                            mask_bytes[i] |= 0x0F; // Low nibble
                        }
                        c.to_digit(16).unwrap() as u8
                    }
                    _ => {
                        return Err(format!(
                            "Invalid character '{}' in pattern at position {}",
                            c, nibble
                        ));
                    }
                };

                if nibble % 2 == 0 {
                    // High nibble
                    pattern_bytes[i] |= nibble_value << 4;
                } else {
                    // Low nibble
                    pattern_bytes[i] |= nibble_value;
                    i += 1; // Move to next byte after completing low nibble
                }

                nibble += 1;
            }

            if nibble % 2 != 0 {
                // If an odd number of nibbles, pad the last low nibble with wildcard
                i += 1;
            }

            if i != 20 {
                return Err(format!(
                    "Pattern must result in exactly 20 bytes but got {} bytes.",
                    i
                ));
            }

            patterns.push(Pattern {
                pattern_bytes,
                mask_bytes,
            });
        }

        Ok(Config {
            factory: self.factory,
            owner: self.owner,
            init_code_hash: self.initcode_hash,
            work_size: self.work_size,
            gpu_device: self.gpu_device,
            total_zeroes_threshold: self.total_zeros,
            patterns,
            max_create3_nonce: self.max_create3_nonce,
            output_file: self.output_file,
            post_url: self.post_url,
        })
    }
}

fn main() {
    let args = Args::parse();

    gpu(args.try_into().unwrap()).unwrap()
}
