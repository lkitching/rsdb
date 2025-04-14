use std::env;

use libc::{signal, SIGINT, pid_t, c_int, kill, SIGSTOP, sighandler_t};

mod debugger;

use debugger::{Debugger, DebuggerError};

static mut PID: Option<pid_t> = None;

fn handle_sigint(_signum: c_int) {
    unsafe {
        // send stop signal to inferior process on SIGINT
        if let Some(pid) = PID {
            kill(pid, SIGSTOP);
        }
    }
}

fn main() -> Result<(), DebuggerError> {
    let args: Vec<String> = env::args().collect();

    let mut debugger = Debugger::launch(args.as_slice())?;

    // install signal handler for SIGINT
    unsafe {
        PID = Some(debugger.process().pid());
        signal(SIGINT, handle_sigint as sighandler_t);
    }
    debugger.main_loop()
}
