use std::fmt;
use std::str::{FromStr};
use std::ptr;
use std::ffi::{CString, CStr};
use std::fmt::Formatter;
use std::num::ParseIntError;

use libc::{pid_t, fork, PTRACE_DETACH, WIFEXITED, WIFSIGNALED};
use libc::{ptrace, PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_CONT, c_void, c_char, c_int, execlp, waitpid, kill, SIGSTOP, SIGCONT, WEXITSTATUS, WTERMSIG, WIFSTOPPED, WSTOPSIG, strsignal};

use crate::error::{Error};
use crate::process::PIDParseError::OutOfRange;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated
}

#[derive(Debug)]
pub struct Process {
    pid: pid_t,
    state: ProcessState,
    terminate_on_end: bool
}

pub struct StopReason {
    reason: ProcessState,
    info: c_int
}

#[derive(Copy, Clone, Debug)]
pub struct PID(pid_t);

#[derive(Debug)]
pub enum PIDParseError {
    InvalidInt(ParseIntError),
    OutOfRange
}

impl FromStr for PID {
    type Err = PIDParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pid = s.parse::<pid_t>().map_err(PIDParseError::InvalidInt)?;
        if pid > 0 {
            Ok(PID(pid))
        } else {
            Err(OutOfRange)
        }
    }
}

impl StopReason {
    fn from_status(wait_status: c_int) -> Self {
        if WIFEXITED(wait_status) {
            Self {
                reason: ProcessState::Exited,
                info: WEXITSTATUS(wait_status)
            }
        } else if WIFSIGNALED(wait_status) {
            Self {
                reason: ProcessState::Terminated,
                info: WTERMSIG(wait_status)
            }
        } else if WIFSTOPPED(wait_status) {
            Self {
                reason: ProcessState::Stopped,
                info: WSTOPSIG(wait_status)
            }
        } else {
            panic!("Unknown status for process");
        }
    }
}

fn signal_description(signal: c_int) -> String {
    unsafe {
        let description_p = strsignal(signal);
        let description = CStr::from_ptr(description_p);
        String::from_utf8_lossy(description.to_bytes()).to_string()
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.reason {
            ProcessState::Running => {
                write!(f, "running")
            },
            ProcessState::Exited => {
                write!(f, "exited with status {}", self.info)
            },
            ProcessState::Terminated => {
                write!(f, "terminated with signal {}", signal_description(self.info))
            },
            ProcessState::Stopped => {
                write!(f, "stopped with signal {}", signal_description(self.info))
            }
        }
    }
}

impl Process {
    pub fn launch(path: &str) -> Result<Self, Error> {
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(Error::from_errno("fork failed"))
        }

        if pid == 0 {
            // in child process
            // execute debuggee
            if unsafe { ptrace(PTRACE_TRACEME, 0, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
                return Err(Error::from_errno("Tracing failed"));
            }

            let path_s = CString::new(path).expect("Invalid CString");
            if unsafe { execlp(path_s.as_ptr(), path_s.as_ptr(), ptr::null::<c_char>()) } < 0 {
                return Err(Error::from_errno("exec failed"));
            }

            // if execlp succeeds then this line should not be reached
            unreachable!()
        } else {
            // in parent
            // create handle for child proces and wait
            let mut proc = Self { pid, state: ProcessState::Stopped, terminate_on_end: true };
            proc.wait_on_signal()?;
            Ok(proc)
        }
    }

    pub fn attach(pid: PID) -> Result<Self, Error> {
        if unsafe { ptrace(PTRACE_ATTACH, pid.0, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
            return Err(Error::from_errno("Could not attach"));
        }

        let mut proc = Self { pid: pid.0, state: ProcessState::Stopped, terminate_on_end: false };
        proc.wait_on_signal()?;
        Ok(proc)
    }

    pub fn resume(&mut self) -> Result<(), Error> {
        if unsafe { ptrace(PTRACE_CONT, self.pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
            Err(Error::from_errno("Could not resume"))
        } else {
            self.state = ProcessState::Running;
            Ok(())
        }
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason, Error> {
        let wait_status = {
            let mut status = -1;
            let options = 0;
            if unsafe { waitpid(self.pid, &mut status, options) } < 0 {
                return Err(Error::from_errno("waitpid failed"));
            }
            status
        };
        let stop_reason = StopReason::from_status(wait_status);
        self.state = stop_reason.reason;
        Ok(stop_reason)
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid != 0 {
            if self.state == ProcessState::Running {
                // request process to stop if running
                unsafe {
                    // NOTE: error from kill ignored
                    kill(self.pid, SIGSTOP);

                    let mut status = -1;
                    waitpid(self.pid, &mut status, 0);
                }
            }

            // detach from process
            unsafe {
                // NOTE: errors ignored
                ptrace(PTRACE_DETACH, self.pid, ptr::null::<c_void>(), ptr::null::<c_void>());
                kill(self.pid, SIGCONT);
            }

            // kill process if we spawned it initially
            if self.terminate_on_end {
                unsafe {
                    kill(self.pid, SIGCONT);

                    let mut status = -1;
                    waitpid(self.pid, &mut status, 0);
                }
            }
        }
    }
}