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

#[link(name = "iberty")]
extern "C" {
    fn __cxa_demangle(mangled_name: *const c_char, output_buffer: *mut c_char, length: *mut size_t, status: *mut c_int) -> *mut c_char;
}

pub fn cxa_demangle(mangled_name: &str) -> Result<String, Error> {
    let c_name = CString::new(mangled_name).expect("Failed to create CString");
    let mut status = 0;

    let demangled_ptr = unsafe { __cxa_demangle(c_name.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut status as *mut c_int) };
    match status {
        0 => {
            // demangle succeeded
            // return value should point to a C-style string allocated by malloc
            // this must be freed by us
            assert!(!demangled_ptr.is_null(), "Expected demangled name to be allocated on success");
            let demangled_s = unsafe { CStr::from_ptr(demangled_ptr) };
            let demangled_result = demangled_s.to_str().map(|s| s.to_string()).map_err(|_e| Error::from_message(String::from("Invalid UTF-8 for demangled name")));

            unsafe { libc::free(demangled_ptr as *mut c_void); }
            demangled_result
        },
        -1 => {
            // memory allocation failed
            Err(Error::from_message(String::from("Name demangling failed: allocation failure")))
        },
        -2 => {
            // mangled name is invalid
            Err(Error::from_message(String::from("Name demangling failed: manged name invalid")))
        },
        -3 => {
            // one of the arguments is invalid
            panic!("Invalid arguments to __cxa_demangle");
        }
        _ => {
            panic!("Unexpected return value from __cxa_demangle: {}", status)
        }
    }
}