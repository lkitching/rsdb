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
    if args.len() == 3 && args[1].as_str() == "-p" {
        // passing PID
        let pid = args[2].parse::<process::PID>()?;
        //let proc = Process::attach(pid)?;
        let debugger = Debugger::attach(pid)?;
        Ok(debugger)
    } else {
        let program_path = args[1].as_str();
        //let proc = Process::launch(program_path, true, StdoutReplacement::None)?;
        let debugger = Debugger::launch(program_path, true, StdoutReplacement::None)?;
        println!("Launched process with PID {}", debugger.process().pid());
        Ok(debugger)
    }
}

fn main() -> Result<(), DebuggerError> {
    let args: Vec<String> = env::args().collect();

    let mut debugger = attach(args.as_slice())?;

    // install signal handler for SIGINT
    unsafe {
        PID = Some(debugger.process().pid());
        signal(SIGINT, handle_sigint as sighandler_t);
    }
    debugger.main_loop()
}
