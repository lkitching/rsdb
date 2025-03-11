use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Byte64 {
    bytes: [u8; 8]
}

impl Byte64 {
    pub fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self { bytes }
    }

    pub fn to_le_bytes(self) -> [u8; 8] {
        self.bytes
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Byte128 {
    bytes: [u8; 16]
}

impl Byte128 {
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn to_le_bytes(self) -> [u8; 16] {
        self.bytes
    }
}

fn format_bytes(bytes: &[u8], fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    let byte_strs: Vec<String> = bytes.iter().map(|b| format!("{:#04x}", b)).collect();
    write!(fmt, "[{}]", byte_strs.join(", "))
}

impl fmt::Display for Byte64 {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(self.bytes.as_slice(), fmt)
    }
}

impl fmt::Display for Byte128 {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes(self.bytes.as_slice(), fmt)
    }
}

macro_rules! derive_to_byte128 {
    ($ty:ty, $len:expr) => {
        impl From<$ty> for Byte128 {
            fn from(value: $ty) -> Self {
                let value_bytes = value.to_le_bytes();
                let mut bytes = [0u8; 16];
                bytes[0..$len].copy_from_slice(value_bytes.as_slice());
                Self::from_le_bytes(bytes)
            }
        }
    };
}

derive_to_byte128!(u8, 1);
derive_to_byte128!(u16, 2);
derive_to_byte128!(u32, 4);
derive_to_byte128!(u64, 8);
derive_to_byte128!(i8, 1);
derive_to_byte128!(i16, 2);
derive_to_byte128!(i32, 4);
derive_to_byte128!(i64, 8);
derive_to_byte128!(f32, 4);
derive_to_byte128!(f64, 8);
derive_to_byte128!(f128, 16);
derive_to_byte128!(Byte64, 8);

#[derive(Copy, Clone, Debug)]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    F128(f128),
    Byte64(Byte64),
    Byte128(Byte128)
}

impl fmt::Display for Value {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(n) => write!(fmt, "{:#04x}", n),
            Self::U16(n) => write!(fmt, "{:#06x}", n),
            Self::U32(n) => write!(fmt, "{:#010x}", n),
            Self::U64(n) => write!(fmt, "{:#018x}", n),
            Self::I8(n) => write!(fmt, "{:#04x}", n),
            Self::I16(n) => write!(fmt, "{:#06x}", n),
            Self::I32(n) => write!(fmt, "{:#010x}", n),
            Self::I64(n) => write!(fmt, "{:#018x}", n),
            Self::F32(f) => write!(fmt, "{}", f),
            Self::F64(f) => write!(fmt, "{}", f),
            Self::F128(f) => {
                // NOTE: formatting is not yet implemented for f128
                // cast to f64 and format the result
                write!(fmt, "{}", *f as f64)
            },
            Self::Byte64(bytes) => bytes.fmt(fmt),
            Self::Byte128(bytes) => bytes.fmt(fmt)
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RegisterValueError;

macro_rules! derive_value_from {
    ($ty:ty, $constructor:ident) => {
        impl From<$ty> for Value {
            fn from(value: $ty) -> Self { Self::$constructor(value) }
        }

        impl TryFrom<Value> for $ty {
            type Error = RegisterValueError;
            fn try_from(value: Value) -> Result<Self, Self::Error> {
                match value {
                    Value::$constructor(v) => {
                        Ok(v)
                    },
                    _ => Err(RegisterValueError)
                }
            }
        }
    };
}

derive_value_from!(u8, U8);
derive_value_from!(u16, U16);
derive_value_from!(u32, U32);
derive_value_from!(u64, U64);
derive_value_from!(i8, I8);
derive_value_from!(i16, I16);
derive_value_from!(i32, I32);
derive_value_from!(i64, I64);
derive_value_from!(f32, F32);
derive_value_from!(f64, F64);
derive_value_from!(f128, F128);
derive_value_from!(Byte64, Byte64);
derive_value_from!(Byte128, Byte128);

pub unsafe trait FromBytesRaw {
    unsafe fn from_bytes_raw(bytes: *const u8) -> Self;
}

macro_rules! derive_from_bytes_raw {
    ($t:ty, $len:expr) => {
        unsafe impl FromBytesRaw for $t {
            unsafe fn from_bytes_raw(bytes: *const u8) -> Self {
                let mut a: [u8; $len] = [0; $len];
                let mut b = bytes;

                for i in 0..$len {
                    unsafe { a[i] = *b; }
                    b = b.add(1)
                }

                Self::from_le_bytes(a)
            }
        }
    };
}

derive_from_bytes_raw!(u8, 1);
derive_from_bytes_raw!(u16, 2);
derive_from_bytes_raw!(u32, 4);
derive_from_bytes_raw!(u64, 8);
derive_from_bytes_raw!(i8, 1);
derive_from_bytes_raw!(i16, 2);
derive_from_bytes_raw!(i32, 4);
derive_from_bytes_raw!(i64, 8);
derive_from_bytes_raw!(f32, 4);
derive_from_bytes_raw!(f64, 8);
derive_from_bytes_raw!(f128, 16);
derive_from_bytes_raw!(Byte64, 8);
derive_from_bytes_raw!(Byte128, 16);

// TODO: don't need copy super trait?
pub trait ToBytes : Copy {
    fn to_bytes(self) -> Vec<u8>;
}

macro_rules! derive_to_bytes {
    ($t:ty) => {
        impl ToBytes for $t {
            fn to_bytes(self) -> Vec<u8> {
                let a = Self::to_le_bytes(self);
                Vec::from(a)
            }
        }
    };
}

derive_to_bytes!(u8);
derive_to_bytes!(u16);
derive_to_bytes!(u32);
derive_to_bytes!(u64);
derive_to_bytes!(i8);
derive_to_bytes!(i16);
derive_to_bytes!(i32);
derive_to_bytes!(i64);
derive_to_bytes!(f32);
derive_to_bytes!(f64);
derive_to_bytes!(f128);
derive_to_bytes!(Byte64);
derive_to_bytes!(Byte128);

impl ToBytes for Value {
    fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::U8(v) => { v.to_bytes() },
            Self::U16(v) => { v.to_bytes() },
            Self::U32(v) => { v.to_bytes() },
            Self::U64(v) => { v.to_bytes() },
            Self::I8(v) => { v.to_bytes() },
            Self::I16(v) => { v.to_bytes() },
            Self::I32(v) => { v.to_bytes() },
            Self::I64(v) => { v.to_bytes() },
            Self::F32(v) => { v.to_bytes() },
            Self::F64(v) => { v.to_bytes() },
            Self::F128(v) => { v.to_bytes() },
            Self::Byte64(v) => { v.to_bytes() },
            Self::Byte128(v) => { v.to_bytes() },
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RegisterSizeError;

pub trait TryWiden {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError>;
}

impl TryWiden for u8 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            2 => { Ok((self as u16).into()) },
            4 => { Ok((self as u32).into()) },
            8 => { Ok((self as u64).into()) },
            16 => { Ok(Byte128::from(self).into()) },
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for u16 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        let v = match size {
            2 => { self.into() },
            4 => { (self as u32).into() },
            8 => { (self as u64).into() },
            16 => { Byte128::from(self).into() },
            _ => { return Err(RegisterSizeError); }
        };
        Ok(v)
    }
}

impl TryWiden for u32 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            4 => { Ok(self.into()) },
            8 => { Ok((self as u64).into()) },
            16 => { Ok(Byte128::from(self).into()) },
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for u64 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            8 => Ok(self.into()),
            16 => Ok(Byte128::from(self).into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for i8 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            2 => Ok((self as i16).into()),
            4 => Ok((self as i32).into()),
            8 => Ok((self as i64).into()),
            16 => Ok(Byte128::from(self).into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for i16 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            2 => Ok(self.into()),
            4 => Ok((self as i32).into()),
            8 => Ok((self as i64).into()),
            16 => Ok(Byte128::from(self).into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for i32 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            4 => Ok(self.into()),
            8 => Ok((self as i64).into()),
            16 => Ok(Byte128::from(self).into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for i64 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            8 => Ok(self.into()),
            16 => Ok(Byte128::from(self).into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for f32 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            4 => Ok(self.into()),
            8 => Ok((self as f64).into()),
            16 => {
                // NOTE: should only happen for vector float registers!
                // copy bits to byte128
                Ok(Byte128::from(self).into())
            }
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for f64 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            8 => Ok(self.into()),
            16 => {
                // NOTE: should only happen for vector float registers
                // copy bits to byte128
                Ok(Byte128::from(self).into())
            }
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for f128 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            16 => {
                // should never happen?
                Ok(self.into())
            }
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for Byte64 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            8 => Ok(self.into()),
            16 => Ok(Byte128::from(self).into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for Byte128 {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match size {
            16 => Ok(self.into()),
            _ => Err(RegisterSizeError)
        }
    }
}

impl TryWiden for Value {
    fn try_widen(self, size: usize) -> Result<Value, RegisterSizeError> {
        match self {
            Self::U8(n) => n.try_widen(size),
            Self::U16(n) => n.try_widen(size),
            Self::U32(n) => n.try_widen(size),
            Self::U64(n) => n.try_widen(size),
            Self::I8(n) => n.try_widen(size),
            Self::I16(n) => n.try_widen(size),
            Self::I32(n) => n.try_widen(size),
            Self::I64(n) => n.try_widen(size),
            Self::F32(n) => n.try_widen(size),
            Self::F64(n) => n.try_widen(size),
            Self::F128(n) => n.try_widen(size),
            Self::Byte64(bs) => bs.try_widen(size),
            Self::Byte128(bs) => bs.try_widen(size),
        }
    }
}