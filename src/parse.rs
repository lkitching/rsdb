use std::num::{ParseFloatError, ParseIntError};
use std::fmt;
use std::fmt::Formatter;
use crate::register::{RegisterFormat, RegisterInfo};
use crate::types::{Value, Byte64, Byte128};

#[derive(Debug)]
pub enum ValueParseError {
    InvalidFloat(ParseFloatError),
    InvalidInt(ParseIntError),
    InvalidVector(ParseVectorError)
}

#[derive(Debug)]
pub struct ParseVectorError {
    error: String
}

impl From<ParseFloatError> for ValueParseError {
    fn from(e: ParseFloatError) -> Self {
        Self::InvalidFloat(e)
    }
}

impl From<ParseIntError> for ValueParseError {
    fn from(e: ParseIntError) -> Self {
        Self::InvalidInt(e)
    }
}

impl From<ParseVectorError> for ValueParseError {
    fn from(e: ParseVectorError) -> Self {
        Self::InvalidVector(e)
    }
}

impl fmt::Display for ValueParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFloat(e) => write!(f, "Invalid floating point value: {}", e),
            Self::InvalidInt(e) => write!(f, "Invalid integral: {}", e),
            Self::InvalidVector(e) => write!(f, "Invalid vector: {}", e.error)
        }
    }
}

trait FromStrRadix : Sized {
    fn parse_radix(s: &str, radix: u32) -> Result<Self, ParseIntError>;
}

macro_rules! impl_from_str_radix {
    ($ty:ty) => {
        impl FromStrRadix for $ty {
            fn parse_radix(s: &str, radix: u32) -> Result<Self, ParseIntError> {
                Self::from_str_radix(s, radix)
            }
        }
    };
}

impl_from_str_radix!(u8);
impl_from_str_radix!(u16);
impl_from_str_radix!(u32);
impl_from_str_radix!(u64);

fn to_integral<I: FromStrRadix>(s: &str, radix: u32) -> Result<I, ParseIntError> {
    if radix == 16 && (s.starts_with("0x") || s.starts_with("0X")) {
        I::parse_radix(&s[2..], radix)
    } else {
        I::parse_radix(s, radix)
    }
}

fn parse_vector<const N: usize>(s: &str) -> Result<[u8; N], ParseVectorError> {
    if !s.starts_with("[") || !s.ends_with("]") {
        return Err(ParseVectorError { error: String::from("Invalid vector format - expected [byte, byte,...,byte]")});
    }

    let s = &s[1..s.len() - 1].trim();
    let digits = s.split(",").map(|ds| ds.trim());

    let mut bytes = [0u8; N];
    let mut i = 0;

    for digit in digits {
        if i >= N {
            return Err(ParseVectorError { error: format!("Invalid vector - expected at most {} bytes", N) });
        }

        match to_integral(digit, 16) {
            Ok(b) => {
                bytes[i] = b;
                i += 1;
            },
            Err(_e) => {
                return Err(ParseVectorError { error: format!("Invalid byte {}", digit) });
            }
        }
    }

    if i != N {
        return Err(ParseVectorError { error: format!("Invalid vector - expected {} bytes, got {}", N, i) });
    }

    Ok(bytes)
}


pub fn parse_register_value(info: &RegisterInfo, s: &str) -> Result<Value, ValueParseError> {
    match info.format {
        RegisterFormat::UInt => {
            match info.size {
                1 => {
                    let n: u8 = to_integral(s, 16)?;
                    Ok(n.into())
                },
                2 => {
                    let n: u16 = to_integral(s, 16)?;
                    Ok(n.into())
                },
                4 => {
                    let n: u32 = to_integral(s, 16)?;
                    Ok(n.into())
                },
                8 => {
                    let n: u64 = to_integral(s, 16)?;
                    Ok(n.into())
                },
                _ => {
                    panic!("Invalid UInt register size {}", info.size);
                }
            }
        },
        RegisterFormat::DoubleFloat => {
            let f: f64 = s.parse()?;
            Ok(f.into())
        },
        RegisterFormat::LongDouble => {
            // NOTE: parsing/formatting is not yet implemented for f128
            // so just parse to an f64 and upcast
            let f: f64 = s.parse()?;
            Ok((f as f128).into())
        },
        RegisterFormat::Vector => {
            match info.size {
                8 => {
                    let bytes = parse_vector::<8>(s)?;
                    Ok(Byte64::from_le_bytes(bytes).into())
                },
                16 => {
                    let bytes = parse_vector::<16>(s)?;
                    Ok(Byte128::from_le_bytes(bytes).into())
                },
                _ => {
                    panic!("Invalid Vector register size {}", info.size);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::parse::{parse_vector, to_integral};

    #[test]
    fn to_integral_no_prefix() {
        let r: u32 = to_integral("cafecafe", 16).expect("Failed to parse");
        assert_eq!(0xcafecafe, r);
    }

    #[test]
    fn to_integral_with_prefix() {
        let r: u32 = to_integral("0xdeadbeef", 16).expect("Failed to parse");
        assert_eq!(0xdeadbeef, r);

        let r: u32 = to_integral("0Xabcdef01", 16).expect("Failed to parse");
        assert_eq!(0xabcdef01, r);
    }

    #[test]
    fn parse_vector_valid() {
        let v = parse_vector::<2>("[0x01, 0xab]").expect("Failed to parse");
        assert_eq!([0x01, 0xab], v);
    }

    #[test]
    fn parse_vector_invalid_missing_opening_bracket() {
        let r = parse_vector::<2>("0x0a, 0xff]");
        assert!(r.is_err());
    }

    #[test]
    fn parse_vector_invalid_missing_closing_bracket() {
        let r = parse_vector::<2>("[0x26,0x11");
        assert!(r.is_err());
    }

    #[test]
    fn parse_vector_invalid_too_many_bytes() {
        let r = parse_vector::<2>("[0x00, 0x35, 0xfa]");
        assert!(r.is_err());
    }

    #[test]
    fn parse_vector_invalid_insufficient_bytes() {
        let r = parse_vector::<2>("[0xab]");
        assert!(r.is_err());
    }

    #[test]
    fn parse_vector_invalid_invalid_byte() {
        let r = parse_vector::<2>("[0x2a, 0xjj]");
        assert!(r.is_err());
    }
}