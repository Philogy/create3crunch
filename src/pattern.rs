use alloy_primitives::{uint, Address, U160};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub target: U160,
    pub mask: U160,
    pub capitalizations: [Option<bool>; 40],
}

impl Pattern {
    pub fn matches_bits(&self, addr: &Address) -> bool {
        let target_addr: Address = self.target.into();
        *addr & self.mask.into() == target_addr
    }

    pub fn matches_capitalization(&self, addr: &Address) -> bool {
        let heap_checksum = addr.to_checksum(None);
        let checksum = heap_checksum.strip_prefix("0x").unwrap();
        checksum
            .char_indices()
            .all(|(i, c)| match self.capitalizations[i] {
                None => true,
                Some(expecting_upper) => expecting_upper == c.is_uppercase(),
            })
    }

    pub fn matches(&self, addr: &Address) -> bool {
        self.matches_bits(addr) && self.matches_capitalization(addr)
    }
}

impl FromStr for Pattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Remove '0x' prefix if present (only once)
        let zerox_sanitized = s.strip_prefix("0x").unwrap_or(s);

        let mut target = U160::ZERO;
        let mut mask = U160::ZERO;
        let mut capitalizations = [None; 40];
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
                    let (target_nibble, capitalize) = match c {
                        '0'..='9' => (U160::from((c as u8) - ('0' as u8)), None),
                        'a'..='f' => (U160::from((c as u8) - ('a' as u8) + 10), Some(false)),
                        'A'..='F' => (U160::from((c as u8) - ('A' as u8) + 10), Some(true)),
                        'x' => (U160::ZERO, None),
                        _ => unreachable!(),
                    };

                    let nibble_offset = (39 - addr_char_index) * 4;
                    target |= target_nibble << nibble_offset;
                    mask |= mask_nibble << nibble_offset;
                    capitalizations[addr_char_index] = capitalize;
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

        Ok(Pattern {
            target,
            mask,
            capitalizations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::uint;

    struct CapBuilder([Option<bool>; 40]);

    impl CapBuilder {
        fn new() -> Self {
            Self([None; 40])
        }

        fn set(mut self, i: usize, b: bool) -> Self {
            self.0[i] = Some(b);
            self
        }

        fn build(self) -> [Option<bool>; 40] {
            self.0
        }
    }

    #[test]
    fn test_basic_pattern() {
        assert_eq!(
            Pattern::from_str("0x00000000000000xxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Ok(Pattern {
                target: uint!(0x0000000000000000000000000000000000000000U160),
                mask: uint!(0xffffffffffffff00000000000000000000000000U160),
                capitalizations: [None; 40]
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
                capitalizations: CapBuilder::new()
                    .set(0, true)
                    .set(1, false)
                    .set(2, true)
                    .set(37, false)
                    .set(38, false)
                    .set(39, true)
                    .build()
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
                capitalizations: CapBuilder::new()
                    .set(0, true)
                    .set(1, false)
                    .set(2, true)
                    .set(37, false)
                    .set(38, false)
                    .set(39, true)
                    .build()
            })
        )
    }
}
