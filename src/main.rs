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
        help = "Minimum amount of leading zeros for the solution to be considered valuable"
    )]
    leading_zeros: Option<u8>,

    #[arg(
        short,
        long,
        help = "Minimum amount of total zero bytes for the address to be consiered valuable"
    )]
    total_zeros: Option<u8>,

    #[arg(
        short,
        long,
        help = "Specifies the upper bound for the nonces that will be inclusively checked (1 - n), at most 127",
        default_value_t = 32
    )]
    max_create3_nonce: u8,

    #[arg(short, long, value_parser=parse_worksize, default_value_t=0x4000000, help="Specifies the GPU work size, min. 0x154000")]
    work_size: u32,

    #[arg(
        short = 'p',
        long,
        default_value = "efficient_addresses.txt",
        help = "The file to output efficient addresses to"
    )]
    output_file: String,

    #[arg(
        long,
        default_value = None,
        help = "Url to POST efficient addresses to"
    )]
    post_url: Option<String>,

    #[arg(
        short,
        long,
        help = "Custom address pattern to match (e.g., 0xefefxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx). You can also match bits like this, but only on full bytes: 0xefefxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx[xxxxxx00]"
    )]
    pattern: Option<String>,
}

impl TryInto<Config> for Args {
    type Error = String;

    fn try_into(self) -> Result<Config, Self::Error> {
        if self.leading_zeros.is_none() && self.total_zeros.is_none() && self.pattern.is_none() {
            return Err(
                "Must specify at least one of total zeros, leading zeros, or a custom pattern"
                    .to_string(),
            );
        }

        // Parse the pattern if provided
        let pattern = if let Some(pattern_str) = &self.pattern {
            // Remove '0x' prefix if present
            let pattern_str = pattern_str.trim_start_matches("0x");

            let mut pattern_bytes = [0u8; 20];
            let mut mask_bytes = [0u8; 20];

            let mut i = 0; // byte index
            let mut j = 0; // char index

            let chars: Vec<char> = pattern_str.chars().collect();

            while i < 20 && j < chars.len() {
                if chars[j] == '[' {
                    // Parse bits inside brackets
                    j += 1; // Skip '['
                    let mut bit_index = 7; // Bits from MSB to LSB
                    while j < chars.len() && chars[j] != ']' && bit_index >= 0 {
                        let c = chars[j];
                        match c {
                            '0' | '1' => {
                                if c == '1' {
                                    pattern_bytes[i] |= 1 << bit_index;
                                }
                                mask_bytes[i] |= 1 << bit_index;
                            }
                            'x' | 'X' => {
                                // Wildcard bit, mask bit is 0
                            }
                            _ => {
                                return Err(format!(
                                    "Invalid character '{}' in bit pattern at position {}",
                                    c, j
                                ));
                            }
                        }
                        j += 1;
                        bit_index -= 1;
                    }
                    if bit_index != -1 {
                        return Err(format!(
                            "Bit pattern inside brackets must be exactly 8 bits at position {}",
                            j
                        ));
                    }
                    if j >= chars.len() || chars[j] != ']' {
                        return Err("Unclosed '[' in pattern".to_string());
                    }
                    j += 1; // Skip ']'
                    i += 1; // Move to next byte
                } else {
                    // Parse hex pair
                    if j + 1 >= chars.len() {
                        return Err("Incomplete hex byte in pattern".to_string());
                    }
                    let c1 = chars[j];
                    let c2 = chars[j + 1];
                    if (c1 == 'x' || c1 == 'X') && (c2 == 'x' || c2 == 'X') {
                        pattern_bytes[i] = 0u8;
                        mask_bytes[i] = 0u8;
                    } else if (c1 == 'x' || c1 == 'X') || (c2 == 'x' || c2 == 'X') {
                        return Err(format!(
                            "Invalid hex character in pattern at position {}: '{}{}'",
                            j, c1, c2
                        ));
                    } else {
                        let hex_pair = format!("{}{}", c1, c2);
                        let byte = u8::from_str_radix(&hex_pair, 16).map_err(|_| {
                            format!(
                                "Invalid hex character in pattern at position {}: '{}{}'",
                                j, c1, c2
                            )
                        })?;
                        pattern_bytes[i] = byte;
                        mask_bytes[i] = 0xFF;
                    }
                    j += 2;
                    i += 1;
                }
            }

            if i != 20 {
                return Err(format!(
                    "Pattern must result in exactly 20 bytes but got {} bytes.",
                    i
                ));
            }

            Some(Pattern {
                pattern_bytes,
                mask_bytes,
            })
        } else {
            None
        };

        Ok(Config {
            factory: self.factory,
            owner: self.owner,
            init_code_hash: self.initcode_hash,
            work_size: self.work_size,
            gpu_device: self.gpu_device,
            leading_zeroes_threshold: self.leading_zeros,
            total_zeroes_threshold: self.total_zeros,
            pattern,
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
