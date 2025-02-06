use std::ffi::{CString};
use libc;

pub fn perror(msg: &str) {
    let msg_s = CString::new(msg).expect("Failed to create CString");
    unsafe {
        libc::perror(msg_s.as_ptr())
    }
}