use std::env;
use std::process::{self, ExitCode};
use std::ffi::{CString};
use std::ptr;

use libc::{self, pid_t, ptrace, PTRACE_ATTACH, fork, PTRACE_TRACEME, execlp, waitpid, PTRACE_CONT, c_char, c_void};
use rustyline;

fn perror(msg: &str) {
    let msg_s = CString::new(msg).expect("Failed to create CString");
    unsafe {
        libc::perror(msg_s.as_ptr())
    }
}

fn attach(args: &[String]) -> pid_t {
    if args.len() == 3 && args[1].as_str() == "-p" {
        // passing PID
        match args[2].parse::<pid_t>() {
            Ok(pid) if pid > 0 => {
                if unsafe { ptrace(PTRACE_ATTACH, pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
                    perror("Could not attach");
                    return -1;
                }
                pid
            },
            _ => {
                eprintln!("Invalid PID");
                -1
            }
        }
    } else {
        // passing program name
        let pid = unsafe { fork() };
        if pid < 0 {
            perror("fork failed");
            return -1;
        }

        if pid == 0 {
            // in child process
            // execute debuggee
            if unsafe { ptrace(PTRACE_TRACEME, 0, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
                perror("Tracing failed");
                return -1;
            }

            let program_path = args[1].as_str();
            let program_path_s = CString::new(program_path).expect("Invalid CString");
            if unsafe { execlp(program_path_s.as_ptr(), program_path_s.as_ptr(), ptr::null::<c_char>()) } < 0 {
                perror("Exec failed");
                return -1;
            }

            // if execlp succeeds then this line should not be reached
            unreachable!()
        }

        // in parent so return pid
        pid
    }
}

fn resume(pid: pid_t) {
    if unsafe { ptrace(PTRACE_CONT, pid, ptr::null::<c_void>(), ptr::null::<c_void>()) } < 0 {
        //eprintln!("Couldn't continue");
        perror("Couldn't continue");
        process::exit(-1)
    }
}

fn wait_on_signal(pid: pid_t) {
    let mut wait_status = -1;
    let options = 0;
    if unsafe { waitpid(pid, &mut wait_status, options) } < 0 {
        perror("waitpid failed");
        process::exit(-1);
    }
}

fn handle_command(pid: pid_t, line: &str) {
    let mut args = line.split(' ');
    let command = args.next().expect("Expected at least one segment");

    if "continue".starts_with(command) {
        resume(pid);
        wait_on_signal(pid);
    } else {
        eprintln!("Unknown command");
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        eprintln!("No arguments given");
        ExitCode::from(1)
    } else {
        let pid = attach(args.as_slice());

        // wait for inferior process
        let mut wait_status = -1;
        let options = 0;
        if unsafe { waitpid(pid, &mut wait_status, options) } < 0 {
            perror("waitpid failed");
            return ExitCode::from(1);
        }

        let mut rl = rustyline::DefaultEditor::new().unwrap();
        loop {
            let line = rl.readline("rsdb> ").expect("Failed to read line");

            let command_line = if line.is_empty() {
                rl.history().iter().next()
            } else {
                rl.add_history_entry(line.clone()).expect("Failed to add history line");
                Some(&line)
            };

            if let Some(cmd) = command_line {
                handle_command(pid, cmd.as_str())
            }
        }
    }
}
