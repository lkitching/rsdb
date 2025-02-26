#[derive(Copy, Clone, Debug)]
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

#[derive(Copy, Clone, Debug)]
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

// TODO: use nightly compiler and https://doc.rust-lang.org/nightly/std/primitive.f128.html?
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub struct f128 {
    bytes: [u8; 16]
}

impl f128 {
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn to_le_bytes(self) -> [u8; 16] {
        self.bytes
    }
}

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

pub unsafe trait FromBytesRaw {
    unsafe fn from_bytes_raw(bytes: *const u8) -> Self;
}

macro_rules! derive_from_bytes_raw {
    ($t:ty, $len:expr) => {
        unsafe impl FromBytesRaw for ($t) {
            unsafe fn from_bytes_raw(bytes: *const u8) -> Self {
                let mut a: [u8; ($len)] = [0; ($len)];
                let mut b = bytes;

                for i in 0..($len) {
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
        impl ToBytes for ($t) {
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
