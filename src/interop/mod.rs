pub mod ptrace;

use std::os::fd::RawFd;
use std::ffi::{CString, CStr};
use std::ptr;

use libc::{self, c_char, pid_t, c_ulong, c_int, c_void, size_t, off_t, strsignal, MAP_FAILED};
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

pub fn wait_pid(pid: pid_t, options: c_int) -> Result<c_int, Error> {
    let mut status = -1;
    if unsafe { libc::waitpid(pid, &mut status, options) } < 0 {
        Err(Error::from_errno("waitpid failed"))
    } else {
        Ok(status)
    }
}

pub fn str_signal(sig: c_int) -> String {
    let s = unsafe { strsignal(sig) };
    unsafe { CStr::from_ptr(s) }.to_str().expect("Failed to read CStr").to_owned()
}

pub fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Error> {
    if unsafe { libc::setpgid(pid, pgid) } < 0 {
        Err(Error::from_errno("Could not set process group id"))
    } else { Ok(()) }
}

pub fn mmap(addr: *mut c_void, length: size_t, prot: c_int, flags: c_int, fd: RawFd, offset: off_t) -> Result<*const c_void, Error> {
    let p = unsafe { libc::mmap(addr, length, prot, flags, fd, offset )};
    if p == MAP_FAILED {
        Err(Error::from_errno("mmap failed"))
    } else {
        Ok(p)
    }
}