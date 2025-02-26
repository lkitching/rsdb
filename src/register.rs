use core::mem::{self, offset_of, transmute};
use std::ffi::c_void;
use std::ptr;
use libc::{user, user_fpregs_struct, user_regs_struct, pid_t, PTRACE_GETREGS, PTRACE_GETFPREGS, ptrace, size_t, PTRACE_POKEUSER, PTRACE_PEEKUSER, c_ulonglong};

use registers_macro::{registers};
use crate::error::{errno, set_errno, Error};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegisterFormat {
    UInt, DoubleFloat, LongDouble, Vector
}

#[derive(Copy, Clone, Debug)]
pub enum RegisterType {
    GeneralPurpose,
    GeneralPurposeSub,
    FloatingPoint,
    Debug
}

type DwarfId = i32;

#[derive(Clone, Debug)]
pub struct RegisterInfo {
    id: RegisterId,
    name: &'static str,
    dwarf_id: DwarfId,
    size: usize,
    offset: usize,
    ty: RegisterType,
    format: RegisterFormat
}

registers![
    gpr64(rax, 0),
    gpr64(rdx, 1),
    gpr64(rcx, 2),
    gpr64(rbx, 3),
    gpr64(rsi, 4),
    gpr64(rdi, 5),
    gpr64(rbp, 6),
    gpr64(rsp, 7),
    gpr64(r8, 8),
    gpr64(r9, 9),
    gpr64(r10, 10),
    gpr64(r11, 11),
    gpr64(r12, 12),
    gpr64(r13, 13),
    gpr64(r14, 14),
    gpr64(r15, 15),
    gpr64(rip, 16),
    gpr64(eflags, 49),
    gpr64(cs, 51),
    gpr64(fs, 54),
    gpr64(gs, 55),
    gpr64(ss, 52),
    gpr64(ds, 53),
    gpr64(es, 50),
    gpr64(orig_rax, -1),

    gpr32(eax, rax), gpr32(edx, rdx),
    gpr32(ecx, rcx), gpr32(ebx, rbx),
    gpr32(esi, rsi), gpr32(edi, rdi),
    gpr32(ebp, rbp), gpr32(esp, rsp),
    gpr32(r8d, r8), gpr32(r9d, r9),
    gpr32(r10d, r10), gpr32(r11d, r11),
    gpr32(r12d, r12), gpr32(r13d, r13),
    gpr32(r14d, r14), gpr32(r15d, r15),

    gpr16(ax, rax), gpr16(dx, rdx),
    gpr16(cx, rcx), gpr16(bx, rbx),
    gpr16(si, rsi), gpr16(di, rdi),
    gpr16(bp, rbp), gpr16(sp, rsp),
    gpr16(r8w, r8), gpr16(r9w, r9),
    gpr16(r10w, r10), gpr16(r11w, r11),
    gpr16(r12w, r12), gpr16(r13w, r13),
    gpr16(r14w, r14), gpr16(r15w, r15),

    gpr8h(ah, rax), gpr8h(dh, rdx),
    gpr8h(ch, rcx), gpr8h(bh, rbx),

    gpr8l(al, rax), gpr8l(dl, rdx),
    gpr8l(cl, rcx), gpr8l(bl, rbx),
    gpr8l(sil, rsi), gpr8l(dil, rdi),
    gpr8l(bpl, rbp), gpr8l(spl, rsp),
    gpr8l(r8b, r8), gpr8l(r9b, r9),
    gpr8l(r10b, r10), gpr8l(r11b, r11),
    gpr8l(r12b, r12), gpr8l(r13b, r13),
    gpr8l(r14b, r14), gpr8l(r15b, r15),

    fpr(fcw, 65, cwd),
    fpr(fsw, 66, swd),
    fpr(ftw, -1, ftw),
    fpr(fop, -1, fop),
    fpr(frip, -1, rip),
    fpr(frdp, -1, rdp),
    fpr(mxcsr, 64, mxcsr),
    fpr(mxcsrmask, -1, mxcr_mask),

    fp_st(0), fp_st(1), fp_st(2), fp_st(3),
    fp_st(4), fp_st(5), fp_st(6), fp_st(7),

    fp_mm(0), fp_mm(1), fp_mm(2), fp_mm(3),
    fp_mm(4), fp_mm(5), fp_mm(6), fp_mm(7),

    fp_xmm(0), fp_xmm(1), fp_xmm(2), fp_xmm(3),
    fp_xmm(4), fp_xmm(5), fp_xmm(6), fp_xmm(7),
    fp_xmm(8), fp_xmm(9), fp_xmm(10), fp_xmm(11),
    fp_xmm(12), fp_xmm(13), fp_xmm(14), fp_xmm(15),

    dr(0), dr(1), dr(2), dr(3),
    dr(4), dr(5), dr(6), dr(7)
];

fn register_info_by<F: Fn(&&RegisterInfo) -> bool>(f: F) -> &'static RegisterInfo {
    REGISTER_INFOS.iter().find(f).expect("Failed to find register info")
}

pub fn register_info_by_id(id: RegisterId) -> &'static RegisterInfo {
    register_info_by(|r| r.id == id)
}

pub fn register_info_by_name(name: &str) -> &'static RegisterInfo {
    register_info_by(|r| r.name == name)
}

pub fn register_info_by_dwarf(dwarf_id: DwarfId) -> &'static RegisterInfo {
    register_info_by(|r| r.dwarf_id == dwarf_id)
}

pub fn debug_register_infos() -> impl Iterator<Item=&'static RegisterInfo> {
    // WARNING: This relies on debug registers being defined together in order!
    REGISTER_INFOS.iter().skip_while(|info| info.id != RegisterId::dr0).take(8)
}

#[derive(Copy, Clone, Debug)]
struct Byte64 {
    bytes: [u8; 8]
}

impl Byte64 {
    fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self { bytes }
    }

    fn to_le_bytes(self) -> [u8; 8] {
        self.bytes
    }
}

#[derive(Copy, Clone, Debug)]
struct Byte128 {
    bytes: [u8; 16]
}

impl Byte128 {
    fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    fn to_le_bytes(self) -> [u8; 16] {
        self.bytes
    }
}

// TODO: use nightly compiler and https://doc.rust-lang.org/nightly/std/primitive.f128.html?
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
struct f128 {
    bytes: [u8; 16]
}

impl f128 {
    fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    fn to_le_bytes(self) -> [u8; 16] {
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

unsafe trait FromBytesRaw {
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
trait ToBytes : Copy {
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

impl ToBytes for u8 {
    fn to_bytes(self) -> Vec<u8> {
        let a = Self::to_le_bytes(self);
        Vec::from(a)
    }
}
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

pub struct Registers {
    pid: pid_t,
    data: libc::user
}

impl Registers {
    pub fn new(pid: pid_t) -> Self {
        Self {
            pid,
            data: unsafe { mem::zeroed() }
        }
    }

    pub fn read_all(&mut self) -> Result<(), Error> {
        if unsafe { ptrace(PTRACE_GETREGS, self.pid, ptr::null::<c_void>(), &self.data.regs as *const user_regs_struct as *const c_void) } < 0 {
            return Err(Error::from_errno("Could not read GPR registers"));
        }

        if unsafe { ptrace(PTRACE_GETFPREGS, self.pid, ptr::null::<c_void>(), &self.data.i387 as *const user_fpregs_struct as *const c_void) } < 0 {
            return Err(Error::from_errno("Could not read FPR registers"));
        }

        for (index, debug_reg) in debug_register_infos().enumerate() {
            set_errno(0);
            let offset = debug_reg.offset as size_t;
            let data = unsafe { ptrace(PTRACE_PEEKUSER, self.pid, offset as *const size_t as *const c_void, ptr::null::<c_void>()) };
            if errno() != 0 {
                return Err(Error::from_errno("Could not read debug register"));
            }

            // can use transmute here?
            self.data.u_debugreg[index] = c_ulonglong::from_le_bytes(data.to_le_bytes());
        }


        Ok(())
    }

    /// Writes the given word to the user area for this process
    /// offset must be word-aligned i.e. on an 8-byte boundary
    pub fn write_user_area(&mut self, offset: size_t, word: u64) -> Result<(), Error> {
        if unsafe { ptrace(PTRACE_POKEUSER, self.pid, &offset as *const size_t as *const c_void, &word as *const u64 as *const c_void) } < 0 {
            return Err(Error::from_errno("Could not write to user area"));
        }
        Ok(())
    }

    pub fn read(&self, info: &RegisterInfo) -> Value {
        let user_p = &self.data as *const user;
        let reg_data_p = unsafe {
            let user_start_p: *const u8 = transmute(user_p);
            user_start_p.add(info.offset)
        };

        match info.format {
            RegisterFormat::UInt => {
                match info.size {
                    1 => {
                        let b = unsafe { u8::from_bytes_raw(reg_data_p) };
                        Value::U8(b)
                    },
                    2 => {
                        let n = unsafe { u16::from_bytes_raw(reg_data_p) };
                        Value::U16(n)
                    },
                    4 => {
                        let n = unsafe { u32::from_bytes_raw(reg_data_p) };
                        Value::U32(n)
                    },
                    8 => {
                        let n = unsafe { u64::from_bytes_raw(reg_data_p) };
                        Value::U64(n)
                    },
                    other => {
                        // should never happen
                        // if it does this is an error in the register definitions
                        panic!("Unexpected register size {} for uint register info {:?}", other, info);
                    }
                }
            },
            RegisterFormat::DoubleFloat => {
                assert_eq!(info.size, 8, "Unexpected size for double float register");
                let f = unsafe { f64::from_bytes_raw(reg_data_p) };
                Value::F64(f)
            },
            RegisterFormat::LongDouble => {
                assert_eq!(info.size, 16, "Unexpected size for long double register");
                let f = unsafe { f128::from_bytes_raw(reg_data_p) };
                Value::F128(f)
            },
            RegisterFormat::Vector => {
                match info.size {
                    8 => {
                        let bytes = unsafe { Byte64::from_bytes_raw(reg_data_p) };
                        Value::Byte64(bytes)
                    },
                    16 => {
                        let bytes = unsafe { Byte128::from_bytes_raw(reg_data_p) };
                        Value::Byte128(bytes)
                    },
                    other => {
                        // error in register definitions
                        panic!("Unexpected register size {} for vector register info: {:?}", other, info);
                    }
                }
            }
        }
    }

    pub fn read_by_id_as<T: TryFrom<Value>>(&self, id: RegisterId) -> T {
        unimplemented!()
    }

    pub fn write(&mut self, info: &RegisterInfo, value: Value) -> Result<(), Error> {
        let bytes = value.to_bytes();

        assert_eq!(info.size, bytes.len(), "mismatched register and value sizes");

        let user_p = &mut self.data as *mut user;
        let reg_data_p = unsafe {
            let user_start_p: *mut u8 = transmute(user_p);
            user_start_p.add(info.offset)
        };

        // write bytes at register offset in user data
        let mut p = reg_data_p;
        for b in bytes.iter() {
            unsafe {
                *p = *b;
                p = p.add(1)
            }
        }

        // save register state
        // NOTE: write_user_area is a member of Process in sdb!
        // TODO: handle types smaller or larger than 1 word!
        let word = {
            let a: [u8; 8] = bytes.try_into().expect("Unsupported size");
            u64::from_le_bytes(a)
        };
        self.write_user_area(info.offset, word)
    }

    pub fn write_by_id<T: TryInto<Value>>(&mut self, id: RegisterId, v: T) {
        unimplemented!()
    }
}
