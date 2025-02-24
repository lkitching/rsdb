use std::fmt::{Display, Formatter};
use std::ffi::{CStr, CString};
use std::io;

use libc::{c_int, __errno_location};

pub fn perror(msg: &str) {
    let msg_s = CString::new(msg).expect("Failed to create CString");
    unsafe {
        libc::perror(msg_s.as_ptr())
    }
}

pub fn errno() -> c_int {
    unsafe {
        let loc = __errno_location();
        *loc
    }
}

pub fn set_errno(errno: c_int) {
    unsafe {
        let loc = __errno_location();
        *loc = errno
    }
}

pub fn strerror(errno: c_int) -> String {
    unsafe {
        let str_p = libc::strerror(errno);
        let str_c = CStr::from_ptr(str_p);
        str_c.to_string_lossy().to_string()
    }
}

#[derive(Debug)]
pub enum Error {
    Message(String),
    ErrnoStr(&'static str, c_int),
    IOError(io::Error)
}

impl Error {
    pub fn from_message(message: String) -> Self {
        Self::Message(message)
    }

    pub fn from_errno(prefix: &'static str) -> Self {
        Self::ErrnoStr(prefix, errno())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IOError(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(msg) => {
                write!(f, "{}", msg)
            },
            Self::ErrnoStr(prefix, errno) => {
                write!(f, "{}: {}", prefix, strerror(*errno))
            },
            Self::IOError(e) => {
                e.fmt(f)
            }
        }
    }
}
