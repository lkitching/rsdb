use std::str::FromStr;
use librsdb::parse;
use crate::debugger::{Debugger, DebuggerError};
use super::{Command, CommandParseError, CommandType, parse_address};

use librsdb::process::Process;
use librsdb::stoppoint_collection::StopPoint;
use librsdb::types::{StoppointMode, VirtualAddress};
use librsdb::watchpoint::WatchPoint;

pub struct WatchpointCommandHandler {}

enum WatchpointCommand {
    List,
    Set(VirtualAddress, StoppointMode, usize),
    Enable(<WatchPoint as StopPoint>::IdType),
    Disable(<WatchPoint as StopPoint>::IdType),
    Delete(<WatchPoint as StopPoint>::IdType)
}

fn parse_mode(mode_str: &str) -> Result<StoppointMode, CommandParseError> {
    StoppointMode::from_str(mode_str).map_err(|_e| CommandParseError::message(String::from("Invalid stoppoint mode")))
}

fn parse_size(size_str: &str) -> Result<usize, CommandParseError> {
    parse::to_integral(size_str, 16).map_err(|_e| CommandParseError::message(String::from("Invalid watch size")))
}

fn parse_id(id_str: &str) -> Result<<WatchPoint as StopPoint>::IdType, CommandParseError> {
    parse::to_integral(id_str, 16).map_err(|_e| CommandParseError::message(String::from("Invalid watchpoint id")))
}

fn parse_watchpoint_command(args: &[&str]) -> Result<WatchpointCommand, CommandParseError> {
    if args.is_empty() {
        return Err(CommandParseError::show_help(CommandType::Watchpoint));
    }

    let command = args[0];

    if "list".starts_with(command) {
        Ok(WatchpointCommand::List)
    } else if "set".starts_with(command) {
        if args.len() < 4 {
            return Err(CommandParseError::show_help(CommandType::Watchpoint));
        }

        let address = parse_address(args[1])?;
        let mode = parse_mode(args[2])?;
        let size = parse_size(args[3])?;

        Ok(WatchpointCommand::Set(address, mode, size))
    } else if args.len() >= 2 {
        let id_str = args[1];
        if "enable".starts_with(command) {
            let id = parse_id(id_str)?;
            Ok(WatchpointCommand::Enable(id))
        } else if "disable".starts_with(command) {
            let id = parse_id(id_str)?;
            Ok(WatchpointCommand::Disable(id))
        } else if "delete".starts_with(command) {
            let id = parse_id(id_str)?;
            Ok(WatchpointCommand::Delete(id))
        } else {
            Err(CommandParseError::show_help(CommandType::Watchpoint))
        }
    } else {
        Err(CommandParseError::show_help(CommandType::Watchpoint))
    }
}

fn handle_watchpoint_command(cmd: WatchpointCommand, process: &mut Process) -> Result<(), DebuggerError> {
    match cmd {
        WatchpointCommand::List => {
            if process.watchpoints().is_empty() {
                println!("No watchpoints set");
            } else {
                for watchpoint in process.watchpoints().iter() {
                    println!("{}: address = {}, mode = {}, size = {}, {}",
                        watchpoint.id(),
                        watchpoint.address(),
                        watchpoint.mode(),
                        watchpoint.size(),
                        if watchpoint.is_enabled() { "enabled" } else { "disabled" }
                    )
                }
            }
        },
        WatchpointCommand::Set(address, mode, size) => {
            let wp = process.create_watchpoint(address, mode, size)?;
            process.enable_watchpoint(wp)?;
        },
        WatchpointCommand::Enable(id) => {
            process.enable_watchpoint(id)?;
        },
        WatchpointCommand::Disable(id) => {
            process.disable_watchpoint(id)?;
        },
        WatchpointCommand::Delete(id) => {
            process.remove_watchpoint_by_id(id)?;
        }
    }

    Ok(())
}

impl Command for WatchpointCommandHandler {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let cmd = parse_watchpoint_command(args)?;
        handle_watchpoint_command(cmd, debugger.process_mut())
    }

    fn describe(&self) {
        eprintln!("Available commands:");
        eprintln!("  list");
        eprintln!("  delete <id>");
        eprintln!("  disable <id>");
        eprintln!("  enable <id>");
        eprintln!("  set <address> <write|rw|execute> <size>")
    }

    fn summary(&self) -> &str {
        "Commands for operating on watchpoints"
    }
}