use std::fmt;
use std::str::{FromStr};
use std::ptr;
use std::ffi::{CString, CStr};
use std::fmt::Formatter;
use std::num::ParseIntError;
use std::io::{Read, Write};
use std::os::fd::{RawFd};

use libc::{pid_t, fork, PTRACE_DETACH, WIFEXITED, WIFSIGNALED, SIGKILL, STDOUT_FILENO, dup2};
use libc::{ptrace, PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_CONT, c_void, c_char, c_int, execlp, waitpid, kill, SIGSTOP, SIGCONT, WEXITSTATUS, WTERMSIG, WIFSTOPPED, WSTOPSIG, strsignal};

use crate::error::{self, Error};
use crate::pipe::Pipe;
use crate::process::PIDParseError::OutOfRange;
use crate::register::{Registers};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated
}

//#[derive(Debug)]
pub struct Process {
    pid: pid_t,
    state: ProcessState,
    terminate_on_end: bool,
    is_attached: bool,
    registers: Registers
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

fn exit_with_perror(channel: &mut Pipe, prefix: &str) -> ! {
    // write error message to pipe
    let msg = format!("{}: {}", prefix, error::strerror(error::errno()));

    let _r = channel.write(msg.as_bytes());
    std::process::exit(-1);
}

#[derive(Copy, Clone, Debug)]
pub enum StdoutReplacement {
    None,
    Fd(RawFd)
}

impl Process {
    pub fn launch(path: &str, debug: bool, stdout_replacement: StdoutReplacement) -> Result<Self, Error> {
        // create pipe to communicate with child process
        let mut pipe = Pipe::create(true)?;

        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(Error::from_errno("fork failed"))
        }

        if pid == 0 {
            // in child process

            //close read side of pipe
            pipe.close_read();

            // replace stdout with given file hande if specified
            if let StdoutReplacement::Fd(fd) = stdout_replacement {
                if unsafe { dup2(fd, STDOUT_FILENO) } < 0 {
                    exit_with_perror(&mut pipe, "stdout replacement failed");
                }
            }

            // configure debugging if required
            if debug {
                if unsafe { ptrace(PTRACE_TRACEME, 0, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
                    exit_with_perror(&mut pipe, "Tracing failed");
                }
            }

            // execute debuggee
            let path_s = CString::new(path).expect("Invalid CString");
            if unsafe { execlp(path_s.as_ptr(), path_s.as_ptr(), ptr::null::<c_char>()) } < 0 {
                exit_with_perror(&mut pipe, "exec failed");
            }

            // if execlp succeeds then this line should not be reached
            unreachable!()
        } else {
            // in parent
            pipe.close_write();

            // wait for child process to write to pipe
            // pipe is closed on exec so this will be empty if exec succeeds
            // otherwise an error message should be written by the child
            let mut msg = String::new();
            let bytes_written = pipe.read_to_string(&mut msg)?;

            if bytes_written > 0 {
                // wait for child to exit
                unsafe { waitpid(pid, ptr::null_mut(), 0); }
                return Err(Error::from_message(msg));
            }

            // create handle for child proces and wait if debugging
            let mut proc = Self { pid, state: ProcessState::Stopped, terminate_on_end: true, is_attached: debug, registers: Registers::new(pid) };

            if debug {
                proc.wait_on_signal()?;
            }

            Ok(proc)
        }
    }

    pub fn attach(pid: PID) -> Result<Self, Error> {
        if unsafe { ptrace(PTRACE_ATTACH, pid.0, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
            return Err(Error::from_errno("Could not attach"));
        }

        let mut proc = Self { pid: pid.0, state: ProcessState::Stopped, terminate_on_end: false, is_attached: true, registers: Registers::new(pid.0) };
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

        if self.is_attached && self.state == ProcessState::Stopped {
            self.read_all_registers()?;
        }

        Ok(stop_reason)
    }

    fn read_all_registers(&mut self) -> Result<(), Error> {
        self.registers.read_all()
    }

    pub fn write_user_area(&mut self, offset: usize, word: u64) -> Result<(), Error> {
        self.registers.write_user_area(offset, word)
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn registers(&self) -> &Registers { &self.registers }
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

            // detach from process if required
            if self.is_attached {
                unsafe {
                    // NOTE: errors ignored
                    ptrace(PTRACE_DETACH, self.pid, ptr::null::<c_void>(), ptr::null::<c_void>());
                    kill(self.pid, SIGCONT);
                }
            }


            // kill process if we spawned it initially
            if self.terminate_on_end {
                unsafe {
                    kill(self.pid, SIGKILL);

                    let mut status = -1;
                    waitpid(self.pid, &mut status, 0);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{self, BufReader, BufRead};
    use std::fs::File;
    use std::path::{PathBuf};
    use libc::{ESRCH};
    use super::*;
    use crate::error::{errno};

    fn process_exists(pid: pid_t) -> bool {
        let ret = unsafe { kill(pid, 0) };
        ret != -1 && errno() != ESRCH
    }

    fn get_process_status(pid: pid_t) -> io::Result<char> {
        let mut path = PathBuf::new();
        path.push("/proc");
        path.push(pid.to_string());
        path.push("stat");

        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        let proc_name_end = line.rfind(')').expect("Failed to find process name");

        // status should follow a space after the closing parenthesis around the process name
        // NOTE: rfind returns a byte index
        let status_indicator_index = proc_name_end + 2;
        Ok(line.as_bytes()[status_indicator_index] as char)
    }

    #[test]
    fn process_launch_succeeds() {
        let r = Process::launch("yes", true, StdoutReplacement::None).expect("Failed to start process");
        assert!(process_exists(r.pid()), "Process does not exist");
    }

    #[test]
    fn process_launch_no_such_program() {
        let r = Process::launch("you_do_not_have_to_be_good", true, StdoutReplacement::None);
        assert!(r.is_err(), "Expected error launching non-existant process");
    }

    #[test]
    fn process_attach_success() {
        let target = Process::launch("target/debug/run_endlessly", false, StdoutReplacement::None).expect("Failed to launch process");
        let _proc = Process::attach(PID(target.pid())).expect("Failed to attach to process");
        let status = get_process_status(target.pid()).expect("Failed to read process status");
        assert_eq!('t', status, "Unexpected process status");
    }

    #[test]
    fn process_resume_launched_success() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");
        proc.resume().expect("Failed to resume");

        let status = get_process_status(proc.pid()).expect("Failed to get process status");
        assert!(status == 'R' || status == 'S', "Unexpected process status after resume");
    }

    #[test]
    fn process_resume_attached_success() {
        let target = Process::launch("target/debug/run_endlessly", false, StdoutReplacement::None).expect("Failed to launch process");

        let mut proc = Process::attach(PID(target.pid())).expect("Failed to attach to process");
        proc.resume().expect("Failed to resume");

        let status = get_process_status(proc.pid()).expect("Failed to get process status");
        assert!(status == 'R' || status == 'S');
    }

    #[test]
    fn process_resume_already_terminated() {
        let mut proc = Process::launch("target/debug/end_immediately", true, StdoutReplacement::None).expect("Failed to launch process");
        proc.resume().expect("Failed to resume");
        let _reason = proc.wait_on_signal().expect("Failed to wait");
        let result = proc.resume();
        assert!(result.is_err(), "Expected error waiting on terminated process");
    }
}