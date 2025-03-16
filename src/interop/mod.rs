pub mod ptrace;

use std::os::fd::RawFd;
use std::ffi::{CString};
use std::ptr;

use libc::{self, c_char, pid_t, c_ulong, c_int};
use crate::error::Error;

pub fn dup2(src_fd: RawFd, dest_fd: RawFd) -> Result<(), Error> {
    if unsafe { libc::dup2(src_fd, dest_fd) } < 0 {
        Err(Error::from_errno("Failed to duplicate file descriptor"))
    } else {
        Ok(())
    }
}

pub fn execlp0<P: Into<Vec<u8>>>(path: P) -> Result<(), Error> {
    let path_s = CString::new(path).expect("Invalid CString");
    if unsafe { libc::execlp(path_s.as_ptr(), path_s.as_ptr(), ptr::null::<c_char>()) } < 0 {
        Err(Error::from_errno("exec failed"))
    } else {
        Ok(())
    }
}

pub enum ForkResult {
    InParent(pid_t),
    InChild
}
pub fn fork() -> Result<ForkResult, Error> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(Error::from_errno("fork failed"))
    } else if pid == 0 {
        Ok(ForkResult::InChild)
    } else {
        Ok(ForkResult::InParent(pid))
    }
}

pub fn personality(persona: c_int) -> Result<(), Error> {
    // NOTE: personality function returns previous persona on success but
    // it isn't needed (yet?)
    // WARNING: personality function is declared to take a c_ulong parameter but all the constants
    // are defined as c_int(?!)
    if unsafe { libc::personality(persona as c_ulong) } < 0 {
        Err(Error::from_errno("Failed to set personality"))
    } else {
        Ok(())
    }
}