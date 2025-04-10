use core::mem::{self, offset_of, transmute};
use libc::{user, user_fpregs_struct, user_regs_struct, pid_t, size_t, c_ulonglong};

use registers_macro::{registers};
use crate::error::{Error};
use crate::types::*;
use crate::interop::ptrace;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegisterFormat {
    UInt, DoubleFloat, LongDouble, Vector
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegisterType {
    GeneralPurpose,
    GeneralPurposeSub,
    FloatingPoint,
    Debug
}

type DwarfId = i32;

#[derive(Clone, Debug)]
pub struct RegisterInfo {
    pub id: RegisterId,
    pub name: &'static str,
    pub dwarf_id: DwarfId,
    pub size: usize,
    pub offset: usize,
    pub ty: RegisterType,
    pub format: RegisterFormat
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

pub fn find_register_info_by_name(name: &str) -> Option<&'static RegisterInfo> {
    REGISTER_INFOS.iter().find(|r| r.name == name)
}

pub fn register_info_by_dwarf(dwarf_id: DwarfId) -> &'static RegisterInfo {
    register_info_by(|r| r.dwarf_id == dwarf_id)
}

pub fn debug_register_infos() -> impl Iterator<Item=&'static RegisterInfo> {
    // WARNING: This relies on debug registers being defined together in order!
    REGISTER_INFOS.iter().skip_while(|info| info.id != RegisterId::dr0).take(8)
}

fn widen<T: TryWiden>(register_info: &RegisterInfo, v: T) -> Result<Value, RegisterSizeError> {
    v.try_widen(register_info.size)
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
        ptrace::get_regs(self.pid, &mut self.data.regs)?;
        ptrace::get_fp_regs(self.pid, &mut self.data.i387)?;

        for (index, debug_reg) in debug_register_infos().enumerate() {
            let offset = debug_reg.offset as size_t;
            let data = ptrace::peek_user(self.pid, offset).map_err(|e| e.with_context("Could not read debug register"))?;

            // can use transmute here?
            self.data.u_debugreg[index] = c_ulonglong::from_le_bytes(data.to_le_bytes());
        }


        Ok(())
    }

    /// Writes the given word to the user area for this process
    /// offset must be word-aligned i.e. on an 8-byte boundary
    pub fn write_user_area(&mut self, offset: size_t, word: usize) -> Result<(), Error> {
        ptrace::poke_user(self.pid, offset, word)
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
                // NOTE: book reads directly into a long double here
                // long double floating point registers only use the lower 80 bits though(?)
                // c++ behaviour might be different so just read the bytes directly here and
                // convert at a higher level
                //let f = unsafe { f128::from_bytes_raw(reg_data_p) };
                // Value::F128(f)
                let bytes = unsafe { Byte128::from_bytes_raw(reg_data_p) };
                Value::Byte128(bytes)
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

    fn write_fprs(&mut self) -> Result<(), Error> {
        ptrace::set_fp_regs(self.pid, &self.data.i387)
    }

    fn write_gprs(&mut self) -> Result<(), Error> {
        ptrace::set_regs(self.pid, &self.data.regs)
    }

    pub fn read_by_id_as<T: TryFrom<Value,Error=RegisterValueError>>(&self, id: RegisterId) -> T {
        let reg_info = register_info_by_id(id);
        let reg_value = self.read(reg_info);
        reg_value.try_into().expect(&format!("Invalid target type for register {}", reg_info.name))
    }

    pub fn write(&mut self, info: &RegisterInfo, value: Value) -> Result<(), Error> {
        // widen data type to match register size
        let wide = widen(info, value).expect("Register write called with mismatched register and value sizes");
        let bytes = wide.to_bytes();

        assert_eq!(info.size, bytes.len(), "mismatched register and value sizes");

        // find offset of the register data within the user struct
        let user_p = &mut self.data as *mut user;
        let user_start_p: *mut u8 = unsafe { transmute(user_p) };
        let reg_data_p = unsafe { user_start_p.add(info.offset) };

        // write bytes at register offset in user data
        let mut p = reg_data_p;
        for b in bytes.iter() {
            unsafe {
                *p = *b;
                p = p.add(1)
            }
        }

        // save register state
        if info.ty == RegisterType::FloatingPoint {
            // register is a floating point register, save all registers at once
            self.write_fprs()
        } else {
            // NOTE: floating point registers are the ONLY registers wider than 8 bytes
            // so we should never need to write more than 1 word here
            assert!(info.size <= 8, "Unexpectedly large non floating-point register {}", info.name);

            // poke data into user area directly for non floating-point registers
            // offset within user area must be aligned on an 8-byte boundary
            // calculate the aligned offset within the user struct and read the word to save from there
            // clear lower 3 bits to align on 8-byte boundary
            let aligned_offset = info.offset & !0b111;
            let aligned_p = unsafe { user_start_p.add(aligned_offset) };
            let word = unsafe { usize::from_bytes_raw(aligned_p as *const u8) };
            self.write_user_area(aligned_offset, word)
        }
    }

    pub fn write_by_id<T: Into<Value>>(&mut self, id: RegisterId, v: T) -> Result<(), Error> {
        let reg_info = register_info_by_id(id);
        self.write(reg_info, v.into())
    }

    pub fn get_pc(&self) -> VirtualAddress {
        let addr = self.read_by_id_as(RegisterId::rip);
        VirtualAddress::new(addr)
    }
}

pub type DebugControlRegister = u64;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DebugRegisterIndex {
    index: u8
}

impl DebugRegisterIndex {
    fn new_unchecked(index: u8) -> Self { Self { index }}
    pub fn values() -> impl Iterator<Item=Self> {
        (0..4).map(|i| Self::new_unchecked(i))
    }

    pub fn find_free_debug_register(control: DebugControlRegister) -> Option<Self> {
        for i in Self::values() {
            if !i.is_enabled(control) {
                return Some(i);
            }
        }
        None
    }

    pub fn enabled_mask(&self) -> DebugControlRegister {
        0b11 << (self.index * 2)
    }

    pub fn is_enabled(&self, control: DebugControlRegister) -> bool {
        control & self.enabled_mask() > 0
    }

    pub fn register_id(&self) -> RegisterId {
        match self.index {
            0 => RegisterId::dr0,
            1 => RegisterId::dr1,
            2 => RegisterId::dr2,
            3 => RegisterId::dr3,
            _ => panic!("Invalid debug register index")
        }
    }

    pub fn clear_mask(&self) -> DebugControlRegister {
        // first two bits enable register locally and globally
        // second four bits encode the mode (r, rw, x) and size
        let m = (0b11 << (self.index * 2)) | (0b1111 << (self.index * 4 + 16));
        !m
    }

    // returns the new debug control register contents with all bits for this
    // debug register cleared
    pub fn clear_control(&self, control: DebugControlRegister) -> DebugControlRegister {
        control & self.clear_mask()
    }

    pub fn configure_mask(&self, mode: StoppointMode, size: usize) -> DebugControlRegister {
        let mode_flag = Self::encode_hardware_stoppoint_mode(mode);
        let size_flag = Self::encode_hardware_stoppoint_size(size);

        let enable_bit: u64 = 1 << (self.index * 2);
        let mode_bits: u64 = mode_flag << (self.index * 4 + 16);
        let size_bits: u64 = size_flag << (self.index * 4 + 18);

        enable_bit | mode_bits | size_bits
    }

    fn encode_hardware_stoppoint_mode(mode: StoppointMode) -> u64 {
        match mode {
            StoppointMode::Write => 0b01,
            StoppointMode::ReadWrite => 0b11,
            StoppointMode::Execute => 0b00
        }
    }

    fn encode_hardware_stoppoint_size(size: usize) -> u64 {
        match size {
            1 => 0b00,
            2 => 0b01,
            4 => 0b11,
            8 => 0b10,
            _ => panic!("Invalid stoppoint size {}", size)
        }
    }
}
