use std::env;
use std::fmt;

use rustyline;

use librsdb::error::{Error};
use librsdb::types::{Value};
use librsdb::process::{PIDParseError, Process, PID, StopReason, StdoutReplacement};
use librsdb::register::{find_register_info_by_name, RegisterType, REGISTER_INFOS, RegisterInfo};
use librsdb::parse::{parse_register_value};

#[derive(Debug)]
enum DebuggerError {
    InputError(String),
    InteropError(Error),
    InvalidCommand(String),
    UsageError
}

impl fmt::Display for DebuggerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputError(ref msg) => {
                write!(f, "{}", msg)
            },
            Self::InteropError(e) => {
                write!(f, "{}", e)
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

impl From<Error> for DebuggerError {
    fn from(e: Error) -> Self { DebuggerError::InteropError(e) }
}

impl From<PIDParseError> for DebuggerError {
    fn from(e: PIDParseError) -> Self {
        Self::InputError(format!("Invalid PID: {:?}", e))
    }
}

fn attach(args: &[String]) -> Result<Process, DebuggerError> {
    if args.len() == 3 && args[1].as_str() == "-p" {
        // passing PID
        let pid = args[2].parse::<PID>()?;
        let proc = Process::attach(pid)?;
        Ok(proc)
    } else {
        let program_path = args[1].as_str();
        let proc = Process::launch(program_path, true, StdoutReplacement::None)?;
        Ok(proc)
    }
}

fn print_stop_reason(process: &Process, reason: &StopReason) {
    println!("Process {} {}", process.pid(), reason)
}

fn print_help(args: &[&str]) {
    match args.first() {
        None => {
            eprintln!("Available commands:");
            eprintln!("  continue   - Resume the process");
            eprintln!("  register   - Commands for operating on registers");
        },
        Some(s) if "register".starts_with(s) => {
            eprintln!("Available commands:");
            eprintln!("  read");
            eprintln!("  read <register>");
            eprintln!("  read all");
            eprintln!("  write <register> <value>");
        },
        Some(_s) => {
            eprintln!("No help available on that");
        }
    }
}

fn print_register_info(register: &RegisterInfo, value: Value) {
   println!("{}:\t{}", register.name, value);
}

fn handle_register_read(args: &[&str], process: &Process) {
    match args.first() {
        None => {
            // display all general-purpose registers except 'orig_rax'
            let gprs = REGISTER_INFOS.iter().filter(|r| r.ty == RegisterType::GeneralPurpose && r.name != "orig_rax");
            for register in gprs {
                let value = process.registers().read(register);
                print_register_info(register, value);
            }
        },
        Some(&"all") => {
            for register in REGISTER_INFOS.iter() {
                let value = process.registers().read(register);
                print_register_info(register, value);
            }
        },
        Some(reg_name) => {
            match find_register_info_by_name(*reg_name) {
                Some(register) => {
                    let value = process.registers().read(register);
                    print_register_info(register, value);
                },
                None => {
                    eprintln!("No such register {}", args[0])
                }
            }
        }
    }
}

fn handle_register_write(args: &[&str], process: &mut Process) {
    if args.len() < 2 {
        print_help(["register"].as_slice())
    } else {
        let name = args[0];
        let value_str = args[1];
        match find_register_info_by_name(name) {
            Some(register) => {
                match parse_register_value(register, value_str) {
                    Ok(value) => {
                        let write_result = process.registers_mut().write(register, value);
                        if let Err(e) = write_result {
                            eprintln!("Failed to write register {}: {}", name, e)
                        }
                    },
                    Err(parse_err) => {
                        eprintln!("Invalid register value: {}", parse_err)
                    }
                }
            },
            None => {
                eprintln!("No such register {}", name);
            }
        }
    }
}

fn handle_register_command(args: &[&str], process: &mut Process) {
    if args.is_empty() {
        print_help(["register"].as_slice());
    } else if args[0].starts_with("read") {
        handle_register_read(&args[1..], process);
    } else if args[0].starts_with("write") {
        handle_register_write(&args[1..], process);
    } else {
        print_help(["register"].as_slice())
    }
}

fn handle_command(process: &mut Process, line: &str) -> Result<(), DebuggerError> {
    let mut args = line.split(' ');
    let command = args.next().expect("Expected at least one segment");
    let command_args: Vec<&str> = args.collect();

    if "continue".starts_with(command) {
        process.resume()?;
        let reason = process.wait_on_signal()?;
        print_stop_reason(process, &reason);
        Ok(())
    } else if "register".starts_with(command) {
        handle_register_command(command_args.as_slice(), process);
        Ok(())
    }
    else if "help".starts_with(command) {
        print_help(command_args.as_slice());
        Ok(())
    }
    else {
        Err(DebuggerError::InvalidCommand(command.to_string()))
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

fn main() -> Result<(), DebuggerError> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        eprintln!("No arguments given");
        Err(DebuggerError::UsageError)
    } else {
        let proc = attach(args.as_slice())?;
        main_loop(proc);
    }
}
