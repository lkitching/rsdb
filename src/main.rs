use std::env;

use libc::{signal, SIGINT, pid_t, c_int, kill, SIGSTOP, sighandler_t};

mod debugger;

use debugger::{Debugger, DebuggerError};
use librsdb::process::{self, StdoutReplacement};

static mut PID: Option<pid_t> = None;

fn handle_sigint(_signum: c_int) {
    unsafe {
        // send stop signal to inferior process on SIGINT
        if let Some(pid) = PID {
            kill(pid, SIGSTOP);
        }
    }
}

fn attach(args: &[String]) -> Result<Debugger, DebuggerError> {
    match args.len() {
        0 => Err(DebuggerError::UsageError),
        2 if args[0] == "-p" => {
            // passing PID
            let pid = args[1].parse::<process::PID>()?;
            let debugger = Debugger::attach(pid)?;
            Ok(debugger)
        },
        _ => {
            let program_path = args[0].as_str();
            let debugger = Debugger::launch(program_path, true, StdoutReplacement::None)?;
            println!("Launched process with PID {}", debugger.process().pid());
            Ok(debugger)
        }
    }
}

fn main() -> Result<(), DebuggerError> {
    let args: Vec<String> = env::args().collect();

    // NOTE: first argument should be program name
    let mut debugger = attach(&args[1..])?;

    // install signal handler for SIGINT
    unsafe {
        PID = Some(debugger.process().pid());
        signal(SIGINT, handle_sigint as sighandler_t);
    }
    debugger.main_loop()
}
