use crate::debugger::{Debugger, DebuggerError};
use super::{Command, CommandParseError, CommandType};

use librsdb::types::{Value};
use librsdb::process::{Process};
use librsdb::parse::parse_register_value;
use librsdb::register::{RegisterInfo, REGISTER_INFOS, RegisterType, find_register_info_by_name};

pub struct RegisterCommandHandler { }
impl Command for RegisterCommandHandler {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let cmd = parse_register_command(args)?;
        handle_register_command(cmd, debugger.process_mut())
    }

    fn describe(&self) {
        eprintln!("Available commands:");
        eprintln!("  read");
        eprintln!("  read <register>");
        eprintln!("  read all");
        eprintln!("  write <register> <value>");
    }

    fn summary(&self) -> &str { "Commands for operating on registers" }
}

fn print_register_info(register: &RegisterInfo, value: Value) {
    println!("{}:\t{}", register.name, value);
}

enum RegisterReadCommand {
    GeneralPurpose,
    All,
    Specific(&'static RegisterInfo)
}

fn parse_register_read_command(args: &[&str]) -> Result<RegisterReadCommand, CommandParseError> {
    match args.first() {
        None => Ok(RegisterReadCommand::GeneralPurpose),
        Some(&"all") => Ok(RegisterReadCommand::All),
        Some(reg_name) => {
            match find_register_info_by_name(*reg_name) {
                Some(register) => Ok(RegisterReadCommand::Specific(register)),
                None => Err(CommandParseError::message(format!("No such register {}", reg_name)))
            }
        }
    }
}

fn handle_register_command(cmd: RegisterCommand, process: &mut Process) -> Result<(), DebuggerError> {
    match cmd {
        RegisterCommand::Read(read_cmd) => {
            match read_cmd {
                RegisterReadCommand::GeneralPurpose => {
                    let gprs = REGISTER_INFOS.iter().filter(|r| r.ty == RegisterType::GeneralPurpose && r.name != "orig_rax");
                    for register in gprs {
                        let value = process.registers().read(register);
                        print_register_info(register, value);
                    }
                },
                RegisterReadCommand::All => {
                    for register in REGISTER_INFOS.iter() {
                        let value = process.registers().read(register);
                        print_register_info(register, value);
                    }
                },
                RegisterReadCommand::Specific(register) => {
                    let value = process.registers().read(register);
                    print_register_info(register, value);
                }
            }
        },
        RegisterCommand::Write(register, value) => {
            let write_result = process.registers_mut().write(register, value);
            if let Err(e) = write_result {
                eprintln!("Failed to write register {}: {}", register.name, e)
            }
        }
    }

    Ok(())
}

fn parse_register_write_command(args: &[&str]) -> Result<RegisterCommand, CommandParseError> {
    if args.len() < 2 {
        Err(CommandParseError::show_help(CommandType::Register))
    } else {
        let name = args[0];
        let value_str = args[1];
        match find_register_info_by_name(name) {
            Some(register) => {
                match parse_register_value(register, value_str) {
                    Ok(value) => {
                        Ok(RegisterCommand::Write(register, value))
                    },
                    Err(parse_err) => {
                        Err(CommandParseError::message(format!("Invalid register value: {}", parse_err)))
                    }
                }
            },
            None => {
                Err(CommandParseError::message(format!("No such register {}", name)))
            }
        }
    }
}

enum RegisterCommand {
    Read(RegisterReadCommand),
    Write(&'static RegisterInfo, Value)
}

fn parse_register_command(args: &[&str]) -> Result<RegisterCommand, CommandParseError> {
    if args.is_empty() {
        Err(CommandParseError::show_help(CommandType::Register))
    } else if args[0].starts_with("read") {
        let read_cmd = parse_register_read_command(&args[1..])?;
        Ok(RegisterCommand::Read(read_cmd))
    } else if args[0].starts_with("write") {
        parse_register_write_command(&args[1..])
    } else {
        Err(CommandParseError::show_help(CommandType::Register))
    }
}

