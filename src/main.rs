use std::env;
use std::fmt;

use rustyline;

use librsdb::process::{PIDParseError, Process, ProcessError, PID, StopReason};

#[derive(Debug)]
enum Error {
    InputError(String),
    ProcessError(ProcessError),
    InvalidCommand(String),
    UsageError
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputError(ref msg) => {
                write!(f, "{}", msg)
            },
            Self::ProcessError(e) => {
                write!(f, "{:?}", e)
            },
            Self::InvalidCommand(command) => {
                write!(f, "Invalid command: {}", command)
            },
            Self::UsageError => {
                write!(f, "Usage: rsdb -p [pid] command")
            }
        }
    }
}

impl From<ProcessError> for Error {
    fn from(e: ProcessError) -> Self { Error::ProcessError(e) }
}

impl From<PIDParseError> for Error {
    fn from(e: PIDParseError) -> Self {
        Self::InputError(format!("Invalid PID: {:?}", e))
    }
}

fn attach(args: &[String]) -> Result<Process, Error> {
    if args.len() == 3 && args[1].as_str() == "-p" {
        // passing PID
        let pid = args[2].parse::<PID>()?;
        let proc = Process::attach(pid)?;
        Ok(proc)
    } else {
        let program_path = args[1].as_str();
        let proc = Process::launch(program_path)?;
        Ok(proc)
    }
}

fn print_stop_reason(process: &Process, reason: &StopReason) {
    println!("Process {} {}", process.pid(), reason)
}

fn handle_command(process: &mut Process, line: &str) -> Result<(), Error> {
    let mut args = line.split(' ');
    let command = args.next().expect("Expected at least one segment");

    if "continue".starts_with(command) {
        process.resume()?;
        let reason = process.wait_on_signal()?;
        print_stop_reason(process, &reason);
        Ok(())
    } else {
        Err(Error::InvalidCommand(command.to_string()))
    }
}

fn main_loop(mut proc: Process) -> ! {
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
            let command_result = handle_command(&mut proc, cmd.as_str());
            if let Err(e) = command_result {
                eprintln!("{}", e)
            }
        }
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        eprintln!("No arguments given");
        Err(Error::UsageError)
    } else {
        let proc = attach(args.as_slice())?;
        main_loop(proc);
    }
}
