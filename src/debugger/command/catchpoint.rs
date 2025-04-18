use std::str::FromStr;
use std::collections::HashSet;

use crate::debugger::{Debugger, DebuggerError};
use super::{Command, CommandParseError, CommandType};

use librsdb::process::{Process, SyscallCatchPolicy};
use librsdb::syscalls::{SyscallType};

pub struct CatchpointCommandHandler {}

enum CatchpointCommand {
    SetPolicy(SyscallCatchPolicy)
}

fn parse_syscall(name_or_id: &str) -> Result<SyscallType, CommandParseError> {
    // try to parse as an id first
    match name_or_id.parse() {
        Ok(id) => {
            SyscallType::from_id(id).map_err(|_| CommandParseError::message(format!("Invalid syscall id {}", id)))
        },
        Err(_) => {
            // try to parse by name
            SyscallType::from_str(name_or_id).map_err(|_| CommandParseError::message(format!("Invalid syscall {}", name_or_id)))
        }
    }
}

fn parse_catchpoint_command(args: &[&str]) -> Result<CatchpointCommand, CommandParseError> {
    if args.len() > 0 && "syscall".starts_with(args[0]) {
        if args.len() == 1 {
            Ok(CatchpointCommand::SetPolicy(SyscallCatchPolicy::All))
        } else if args.len() == 2 && args[1] == "none" {
            Ok(CatchpointCommand::SetPolicy(SyscallCatchPolicy::None))
        } else {
            let mut syscalls = HashSet::new();
            for name_or_id in args[1].split(",") {
                let syscall = parse_syscall(name_or_id)?;
                syscalls.insert(syscall);
            }

            Ok(CatchpointCommand::SetPolicy(SyscallCatchPolicy::Some(syscalls)))
        }
    } else {
        Err(CommandParseError::show_help(CommandType::Catchpoint))
    }
}

fn handle_catchpoint_command(command: CatchpointCommand, process: &mut Process) -> Result<(), DebuggerError> {
    match command {
        CatchpointCommand::SetPolicy(policy) => {
            process.set_syscall_catch_policy(policy);
            Ok(())
        }
    }
}

impl Command for CatchpointCommandHandler {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let command = parse_catchpoint_command(args)?;
        handle_catchpoint_command(command, debugger.process_mut())
    }

    fn describe(&self) {
        eprintln!("Available commands:");
        eprintln!("  syscall");
        eprintln!("  syscall none");
        eprintln!("  syscall <list of syscall ids or names>");
    }

    fn summary(&self) -> &str {
        "Commands for operating on catchpoints"
    }
}

