use std::{mem, ptr};

use libc::{c_void, pid_t, user_fpregs_struct, user_regs_struct, c_long, size_t, PTRACE_SINGLESTEP};
use libc::{ptrace, PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_GETFPREGS, PTRACE_PEEKUSER, PTRACE_POKEUSER, PTRACE_SETREGS, PTRACE_SETFPREGS};
use libc::{PTRACE_PEEKDATA, PTRACE_POKEDATA};
use crate::error::*;
use crate::types::VirtualAddress;

pub fn traceme() -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_TRACEME, 0, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
        Err(Error::from_errno("Tracing failed"))
    } else {
        Ok(())
    }
}

pub fn attach(pid: pid_t) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_ATTACH, pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
        Err(Error::from_errno("Could not attach"))
    } else {
        Ok(())
    }
}

pub fn cont(pid: pid_t) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_CONT, pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
        Err(Error::from_errno("Could not resume"))
    } else {
        Ok(())
    }
}

pub fn detach(pid: pid_t) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_DETACH, pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
        Err(Error::from_errno("Failed to detach"))
    } else {
        Ok(())
    }
}

pub fn get_regs(pid: pid_t, regs: &mut user_regs_struct) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_GETREGS, pid, ptr::null::<c_void>(), regs as *mut user_regs_struct as *mut c_void) } < 0 {
        Err(Error::from_errno("Could not read GPR registers"))
    } else {
        Ok(())
    }
}

pub fn get_fp_regs(pid: pid_t, regs: &mut user_fpregs_struct) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_GETFPREGS, pid, ptr::null::<c_void>(), regs as *mut user_fpregs_struct as *mut c_void) } < 0 {
        Err(Error::from_errno("Could not read FPR registers"))
    } else {
        Ok(())
    }
}

pub fn set_regs(pid: pid_t, regs: &user_regs_struct) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_SETREGS, pid, ptr::null::<c_void>(), regs as *const user_regs_struct as *const c_void) } < 0 {
        Err(Error::from_errno("Could not write general purpose registers"))
    } else {
        Ok(())
    }
}

pub fn set_fp_regs(pid: pid_t, regs: &user_fpregs_struct) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_SETFPREGS, pid, ptr::null::<c_void>(), regs as *const user_fpregs_struct as *const c_void) } < 0 {
        Err(Error::from_errno("Could not write floating point registers"))
    } else {
        Ok(())
    }
}

pub fn peek_user(pid: pid_t, offset: size_t) -> Result<usize, Error> {
    set_errno(0);
    let data = unsafe { ptrace(PTRACE_PEEKUSER, pid, offset as *const size_t as *const c_void, ptr::null::<c_void>()) };
    if errno() != 0 {
        Err(Error::from_errno("Could not read from user area"))
    } else {
        let word: usize = unsafe { mem::transmute(data) };
        Ok(word)
    }
}

pub fn poke_user(pid: pid_t, offset: size_t, word: usize) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_POKEUSER, pid, offset as *const size_t as *const c_void, word as *const c_void) } < 0 {
        Err(Error::from_errno("Could not write to user area"))
    } else {
        Ok(())
    }
}

pub fn peek_data(pid: pid_t, address: VirtualAddress) -> Result<usize, Error> {
    set_errno(0);
    let address: usize = address.into();
    let data = unsafe { ptrace(PTRACE_PEEKDATA, pid, address as *const c_void, ptr::null::<c_void>()) };
    if errno() != 0 {
        Err(Error::from_errno("Could not read data"))
    } else {
        let word: usize = unsafe { mem::transmute(data) };
        Ok(word)
    }
}

pub fn poke_data(pid: pid_t, address: VirtualAddress, word: usize) -> Result<(), Error> {
    let address: usize = address.into();
    if unsafe { ptrace(PTRACE_POKEDATA, pid, address as *const c_void, word as *const c_void) } < 0 {
        Err(Error::from_errno("Failed to write data"))
    } else {
        Ok(())
    }
}

pub fn single_step(pid: pid_t) -> Result<(), Error> {
    if unsafe { ptrace(PTRACE_SINGLESTEP, pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
        Err(Error::from_errno("Failed to single step"))
    } else {
        Ok(())
    }
}