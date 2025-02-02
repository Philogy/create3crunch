use alloy_primitives::{uint, U160};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub target: U160,
    pub mask: U160,
    pub capitalize: Option<[bool; 40]>,
}

impl FromStr for Pattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Remove '0x' prefix if present (only once)
        let zerox_sanitized = s.strip_prefix("0x").unwrap_or(s);

        let mut target = U160::ZERO;
        let mut mask = U160::ZERO;
        let mut capitalize = [false; 40];
        let mut addr_char_index = 0usize;
        let mut rel_bit_offset = 0usize;
        let mut in_bit_group = false;

        for (i, c) in zerox_sanitized.char_indices() {
            match c {
                '[' => {
                    if in_bit_group {
                        return Err(format!("Nesting opening bracket at pos {}", i));
                    }
                    in_bit_group = true;
                    rel_bit_offset = 4;
                }
                ']' => {
                    if !in_bit_group {
                        return Err(format!("Standalone closing bracket at pos {}", i));
                    }
                    if rel_bit_offset != 0 {
                        return Err(format!(
                            "Incomplete bit group, {} bit(s) missing at pos {}",
                            rel_bit_offset, i
                        ));
                    }
                    in_bit_group = false;
                    addr_char_index += 1;
                }
                '0' | '1' | 'x' if in_bit_group => {
                    if rel_bit_offset == 0 {
                        addr_char_index += 1;
                        rel_bit_offset = 4;
                    }
                    rel_bit_offset -= 1;

                    let target_bit = U160::from(c == '1');
                    let mask_bit = U160::from(c != 'x');
                    let bit_offset = (39 - addr_char_index) * 4 + rel_bit_offset;

                    target |= target_bit << bit_offset;
                    mask |= mask_bit << bit_offset;
                }
                '0'..='9' | 'a'..='f' | 'A'..='F' | 'x' => {
                    if in_bit_group {
                        return Err(format!("Invalid char {:?} for bit group at pos {}, bit group pattern must be in the form e.g. ...[01x0xx110x10]...", c, i));
                    }
                    if addr_char_index == 40 {
                        return Err(format!("Pattern too long"));
                    }

                    let mask_nibble = if c == 'x' { U160::ZERO } else { uint!(0xfU160) };
                    let (target_nibble, uppercase_nibble) = match c {
                        '0'..='9' => (U160::from((c as u8) - ('0' as u8)), false),
                        'a'..='f' => (U160::from((c as u8) - ('a' as u8) + 10), false),
                        'A'..='F' => (U160::from((c as u8) - ('A' as u8) + 10), true),
                        'x' => (U160::ZERO, false),
                        _ => unreachable!(),
                    };

                    let nibble_offset = (39 - addr_char_index) * 4;
                    target |= target_nibble << nibble_offset;
                    mask |= mask_nibble << nibble_offset;
                    capitalize[addr_char_index] = uppercase_nibble;
                    addr_char_index += 1;
                }
                _ => {
                    return Err(format!("Invalid character {:?} found at pos {}", c, i));
                }
            }
        }

        if in_bit_group {
            return Err(format!("Last bit group not closed"));
        }

        if addr_char_index != 40 {
            if addr_char_index > 40 {
                unreachable!();
            }
            return Err(format!(
                "Pattern too short, length: {}, expected: 40",
                addr_char_index
            ));
        }

        println!("target: {:b}", target);
        println!("mask: {:b}", mask);

        Ok(Pattern {
            target,
            mask,
            capitalize: Some(capitalize),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::uint;

    #[test]
    fn test_basic_pattern() {
        assert_eq!(
            Pattern::from_str("0x00000000000000xxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Ok(Pattern {
                target: uint!(0x0000000000000000000000000000000000000000U160),
                mask: uint!(0xffffffffffffff00000000000000000000000000U160),
                capitalize: Some([false; 40])
            })
        )
    }

    #[test]
    fn test_capitalization() {
        assert_eq!(
            Pattern::from_str("0xAfDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx07xxbaD"),
            Ok(Pattern {
                target: uint!(0xAFD0000000000000000000000000000000700BADU160),
                mask: uint!(0xfff000000000000000000000000000000ff00fffU160),
                capitalize: Some([
                    true, false, true, false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, true
                ])
            })
        )
    }

    #[test]
    fn test_bit_groups() {
        assert_eq!(
            Pattern::from_str("0xAfDxxx[01x0xx110x10]xxxxxxxxxxxxxxxxxxxxxxxx07xxbaD"),
            Ok(Pattern {
                target: uint!(0xAFD0004320000000000000000000000000700BADU160),
                mask: uint!(0xfff000d3b000000000000000000000000ff00fffU160),
                capitalize: Some([
                    true, false, true, false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, true
                ])
            })
        )
    }
}
