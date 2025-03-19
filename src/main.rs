use std::env;
use std::fmt;
use std::str::{FromStr};

use rustyline;

use librsdb::error::{Error};
use librsdb::parse;
use librsdb::types::{Value, VirtualAddress};
use librsdb::process::{PIDParseError, Process, PID, StopReason, StdoutReplacement};
use librsdb::register::{find_register_info_by_name, RegisterType, REGISTER_INFOS, RegisterInfo};
use librsdb::parse::{parse_register_value};
use librsdb::stoppoint_collection::StopPoint;

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
        println!("Launched process with PID {}", proc.pid());
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
            eprintln!("  breakpoint - Commands for operating on breakpoints");
            eprintln!("  continue   - Resume the process");
            eprintln!("  register   - Commands for operating on registers");
            eprintln!("  step       - Step over a single instruction");
            eprintln!("  memory     - Commands for operating on memory")
        },
        Some(s) if "register".starts_with(s) => {
            eprintln!("Available commands:");
            eprintln!("  read");
            eprintln!("  read <register>");
            eprintln!("  read all");
            eprintln!("  write <register> <value>");
        },
        Some(s) if "breakpoint".starts_with(s) => {
            eprintln!("Available commands:");
            eprintln!("  list");
            eprintln!("  delete <id>");
            eprintln!("  disable <id>");
            eprintln!("  enable <id>");
            eprintln!("  set <address>");
        }
        Some(s) if "memory".starts_with(s) => {
            eprintln!("Available commands:");
            eprintln!("  read <address>");
            eprintln!("  read <address> <num_bytes>");
            eprintln!("  write <address> <bytes>");
        }
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

fn handle_breakpoint_command(args: &[&str], process: &mut Process) -> Result<(), Error> {
    if args.is_empty() {
        print_help(["breakpoint"].as_slice());
        return Ok(());
    }

    let command = args[0];

    if "list".starts_with(command) {
        if process.breakpoint_sites().is_empty() {
            println!("No breakpoints set");
        } else {
            println!("Current breakpoints:");
            for bp in process.breakpoint_sites().iter() {
                println!("{}: address = {}, {}", bp.id(), bp.address(), if bp.is_enabled() { "enabled" } else { "disabled" });
            }
        }
        return Ok(());
    }

    if args.len() < 2 {
        print_help(["breakpoint"].as_slice());
    }

    if "set".starts_with(command) {
        match VirtualAddress::from_str(args[1]) {
            Ok(addr) => {
                let bp = process.create_breakpoint_site(addr)?;
                bp.enable()?;
            },
            Err(e) => {
                eprintln!("Breakpoint command expected address in hexadecimal: {}", e);
            }
        }
    } else if "enable".starts_with(command) {
        let id = parse::to_integral(args[1], 16).expect("Invalid id");
        let bp = process.breakpoint_sites_mut().get_by_id_mut(id)?;
        bp.enable()?;
    } else if "disable".starts_with(command) {
        let id = parse::to_integral(args[1], 16).expect("Invalid id");
        let bp = process.breakpoint_sites_mut().get_by_id_mut(id)?;
        bp.disable()?;
    } else if "delete".starts_with(command) {
        let id = parse::to_integral(args[1], 16).expect("Invalid id");
        process.breakpoint_sites_mut().remove_by_id(id);
    } else {
        eprintln!("Unknown breakpoint command {}", command);
        print_help(["register"].as_slice())
    }

    // TODO: create type for UI errors?
    // this returns ok even if command was invalid
    Ok(())
}

fn handle_memory_read_command(args: &[&str], process: &mut Process) -> Result<(), DebuggerError> {
    let addr: VirtualAddress = parse::to_integral(&args[0], 16).map_err(|e| DebuggerError::InvalidCommand(format!("Invalid address: {}", e)))?;

    let num_bytes = if args.len() > 1 {
        parse::to_integral(&args[1], 10).map_err(|e| DebuggerError::InvalidCommand(format!("Invalid number of bytes: {}", e)))?
    } else {
        32usize
    };

    let data = process.read_memory(addr, num_bytes)?;

    // display data in 16-byte chunks
    let mut chunk_address = addr;
    for chunk in data.chunks(16) {
        let bytes: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("{}: {}", chunk_address, bytes.join(" "));
        chunk_address += chunk.len() as isize;
    }

    Ok(())
}

fn handle_memory_write_command(args: &[&str], process: &mut Process) -> Result<(), DebuggerError> {
    if args.len() != 2 {
        print_help(["memory"].as_slice());
        return Ok(())
    }

    let addr: VirtualAddress = parse::to_integral(&args[0], 16).map_err(|e| DebuggerError::InvalidCommand(format!("Invalid address: {}", e)))?;
    let data = parse::parse_vector(&args[1]).map_err(|e| DebuggerError::InvalidCommand(format!("Invalid data format: {}", e)))?;

    process.write_memory(addr, data.as_slice())?;
    Ok(())
}

fn handle_memory_command(args: &[&str], process: &mut Process) -> Result<(), DebuggerError> {
    if args.len() < 2 {
        print_help(["memory"].as_slice());
        return Ok(());
    }

    let memory_command = args[0];
    let command_args = &args[1..];
    if "read".starts_with(memory_command) {
        handle_memory_read_command(command_args, process)
    } else if "write".starts_with(memory_command) {
        handle_memory_write_command(command_args, process)
    } else {
        print_help(["memory"].as_slice());
        Ok(())
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
    } else if "breakpoint".starts_with(command) {
        handle_breakpoint_command(command_args.as_slice(), process)?;
        Ok(())
    } else if "step".starts_with(command) {
        let reason = process.step_instruction()?;
        print_stop_reason(process, &reason);
        Ok(())
    } else if "memory".starts_with(command) {
        handle_memory_command(command_args.as_slice(), process)
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
