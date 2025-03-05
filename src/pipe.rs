use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{RawFd};

use libc::{self, c_void, c_int, size_t, O_CLOEXEC, pipe2, close};

use crate::error::{Error};

pub struct Pipe {
    fds: [c_int; 2]
}

impl Pipe {
    const READ_FD: usize = 0;
    const WRITE_FD: usize = 1;

    pub fn create(close_on_exec: bool) -> Result<Self, Error> {
        let mut file_descriptors = [0; 2];
        let flags = if close_on_exec { O_CLOEXEC } else { 0 };
        if unsafe { pipe2(file_descriptors.as_mut_ptr(), flags) < 0 } {
            Err(Error::from_errno("Pipe creation failed"))
        } else {
            Ok(Self { fds: file_descriptors } )
        }
    }

    fn close_fd(&mut self, index: usize) {
        if self.fds[index] != -1 {
            unsafe { close(self.fds[index]); }
            self.fds[index] = -1;
        }
    }

    pub fn close_read(&mut self) {
        self.close_fd(Self::READ_FD)
    }

    pub fn close_write(&mut self) {
        self.close_fd(Self::WRITE_FD)
    }

    pub fn release_read(&mut self) -> c_int {
        mem::replace(&mut self.fds[Self::READ_FD], -1)
    }

    pub fn release_write(&mut self) -> c_int {
        mem::replace(&mut self.fds[Self::WRITE_FD], -1)
    }

    pub fn read_fd(&self) -> RawFd {
        self.fds[Self::READ_FD]
    }

    pub fn write_fd(&self) -> RawFd {
        self.fds[Self::WRITE_FD]
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.close_read();
        self.close_write();
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = unsafe { libc::read(self.fds[Self::READ_FD], buf.as_mut_ptr() as *mut c_void, buf.len() as size_t) };
        if read < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes_written = unsafe { libc::write(self.fds[Self::WRITE_FD], buf.as_ptr() as *const c_void, buf.len() as size_t) };
        if bytes_written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // nothing to do
        Ok(())
    }
}