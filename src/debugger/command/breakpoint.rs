use std::str::FromStr;
use librsdb::breakpoint_site::{BreakpointScope, BreakpointType};
use crate::debugger::{Debugger, DebuggerError};
use super::{Command, CommandType, CommandParseError};

use librsdb::types::{VirtualAddress};
use librsdb::process::{Process};
use librsdb::stoppoint_collection::StopPoint;
use librsdb::parse;

enum BreakpointCommand {
    List,
    Set(VirtualAddress, BreakpointType),
    Enable(u32),
    Disable(u32),
    Delete(u32)
}

fn parse_breakpoint_command(args: &[&str]) -> Result<BreakpointCommand, CommandParseError> {
    if args.is_empty() {
        return Err(CommandParseError::show_help(CommandType::Breakpoint));
    }

    let command = args[0];

    if "list".starts_with(command) {
        return Ok(BreakpointCommand::List);
    }

    if args.len() < 2 {
        return Err(CommandParseError::show_help(CommandType::Breakpoint));
    }

    fn parse_id(id_str: &str) -> Result<u32, CommandParseError> {
        parse::to_integral(id_str, 16).map_err(|e| CommandParseError::message(format!("Invalid id: {}", e)))
    }

    if "set".starts_with(command) {
        let address = VirtualAddress::from_str(args[1])
            .map_err(|e| CommandParseError::message(format!("Breakpoint command expected address in hexadecimal: {}", e)))?;
        let breakpoint_type = if args.len() >= 3 {
            if args[2] == "-h" {
                BreakpointType::Hardware
            } else {
                return Err(CommandParseError::message(String::from("Invalid breakpoint command argument")));
            }
        } else {
            BreakpointType::Software
        };

        Ok(BreakpointCommand::Set(address, breakpoint_type))
    } else if "enable".starts_with(command) {
        let id = parse_id(args[1])?;
        Ok(BreakpointCommand::Enable(id))
    } else if "disable".starts_with(command) {
        let id = parse_id(args[1])?;
        Ok(BreakpointCommand::Disable(id))
    } else if "delete".starts_with(command) {
        let id = parse_id(args[1])?;
        Ok(BreakpointCommand::Delete(id))
    } else {
        Err(CommandParseError::new(format!("Unknown breakpoint command {}", command), CommandType::Breakpoint))
    }
}

fn handle_breakpoint_command(cmd: BreakpointCommand, process: &mut Process) -> Result<(), DebuggerError> {
    match cmd {
        BreakpointCommand::List => {
            if process.breakpoint_sites().is_empty() {
                println!("No breakpoints set");
            } else {
                println!("Current breakpoints:");
                for bp in process.breakpoint_sites().iter().filter(|bp| bp.is_external()) {
                    println!("{}: address = {}, {}", bp.id(), bp.address(), if bp.is_enabled() { "enabled" } else { "disabled" });
                }
            }
        },
        BreakpointCommand::Set(addr, breakpoint_type) => {
            let bp = process.create_breakpoint_site(addr, breakpoint_type, BreakpointScope::External)?;
            process.enable_breakpoint(bp)?;
        },
        BreakpointCommand::Enable(id) => {
            process.enable_breakpoint(id)?;
        },
        BreakpointCommand::Disable(id) => {
            process.disable_breakpoint(id)?;
        },
        BreakpointCommand::Delete(id) => {
            process.remove_breakpoint_by_id(id)?;
        }
    }

    Ok(())
}

pub struct BreakpointCommandHandler {}
impl Command for BreakpointCommandHandler {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let cmd = parse_breakpoint_command(args)?;
        handle_breakpoint_command(cmd, debugger.process_mut())
    }

    fn describe(&self) {
        eprintln!("Available commands:");
        eprintln!("  list");
        eprintln!("  delete <id>");
        eprintln!("  disable <id>");
        eprintln!("  enable <id>");
        eprintln!("  set <address>");
        eprintln!("  set <address> -h")
    }

    fn summary(&self) -> &str { "Commands for operating on breakpoints" }
}
