mod cont;
mod register;
mod breakpoint;
mod step;
mod memory;
mod disassemble;
mod help;
mod watchpoint;
mod catchpoint;

use std::fmt::{self, Formatter};
use std::str::FromStr;

use super::{Debugger, DebuggerError};
use librsdb::error::{Error};
use librsdb::process::{Process, StopReason};
use librsdb::disassembler::print_disassembly;

use cont::ContinueCommandHandler;
use register::RegisterCommandHandler;
use breakpoint::BreakpointCommandHandler;
use step::StepCommandHandler;
use memory::MemoryCommandHandler;
use disassemble::DisassembleCommandHandler;
pub use help::HelpCommandHandler;
use librsdb::types::VirtualAddress;
use watchpoint::WatchpointCommandHandler;
use catchpoint::CatchpointCommandHandler;

pub trait Command {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError>;

    fn describe(&self);
    fn summary(&self) -> &str;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CommandType {
    Breakpoint,
    Catchpoint,
    Continue,
    Disassemble,
    Memory,
    Register,
    Step,
    Watchpoint,
    Help
}

impl CommandType {
    pub fn get_handler(self) -> Box<dyn Command> {
        match self {
            Self::Breakpoint => Box::new(BreakpointCommandHandler {}),
            Self::Catchpoint => Box::new(CatchpointCommandHandler {}),
            Self::Continue => Box::new(ContinueCommandHandler {}),
            Self::Disassemble => Box::new(DisassembleCommandHandler {}),
            Self::Memory => Box::new(MemoryCommandHandler {}),
            Self::Register => Box::new(RegisterCommandHandler {}),
            Self::Step => Box::new(StepCommandHandler {}),
            Self::Watchpoint => Box::new(WatchpointCommandHandler {}),
            Self::Help => Box::new(HelpCommandHandler {})
        }
    }

    fn values() -> impl Iterator<Item=Self> {
        [Self::Breakpoint, Self::Continue, Self::Disassemble, Self::Memory,
            Self::Register, Self::Step, Self::Watchpoint, Self::Help].into_iter()
    }
}

impl fmt::Display for CommandType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = format!("{:?}", self);
        s.make_ascii_lowercase();
        write!(f, "{}", s)
    }
}

impl FromStr for CommandType {
    type Err = CommandParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if "breakpoint".starts_with(s) {
            Ok(Self::Breakpoint)
        } else if "continue".starts_with(s) {
            // NOTE: keep this before 'catchpoint'!
            // we want 'c' to match 'continue' and not 'catchpoint'
            Ok(Self::Continue)
        } else if "catchpoint".starts_with(s) {
            Ok(Self::Catchpoint)
        } else if "disassemble".starts_with(s) {
            Ok(Self::Disassemble)
        } else if "memory".starts_with(s) {
            Ok(Self::Memory)
        } else if "register".starts_with(s) {
            Ok(Self::Register)
        } else if "step".starts_with(s) {
            Ok(Self::Step)
        } else if "watchpoint".starts_with(s) {
            Ok(Self::Watchpoint)
        } else if "help".starts_with(s) {
            Ok(Self::Help)
        } else {
            Err(CommandParseError::message(String::from("No help available on that")))
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommandParseError {
    pub message: Option<String>,
    pub help: Option<CommandType>
}

impl CommandParseError {
    fn show_help(category: CommandType) -> Self {
        Self { message: None, help: Some(category) }
    }

    fn message(message: String) -> Self {
        Self { message: Some(message), help: None }
    }

    fn new(message: String, category: CommandType) -> Self {
        Self { message: Some(message), help: Some(category) }
    }
}

fn print_stop_reason(process: &Process, reason: &StopReason) {
    println!("Process {} {}", process.pid(), reason)
}

fn handle_stop(process: &Process, reason: &StopReason) -> Result<(), Error> {
    print_stop_reason(process, reason);
    if reason.reason.is_stopped() {
        print_disassembly(process, process.get_pc(), 5)
    } else {
        Ok(())
    }
}

pub fn parse_address(addr_str: &str) -> Result<VirtualAddress, CommandParseError> {
    VirtualAddress::from_str(addr_str)
        .map_err(|e| CommandParseError::message(format!("Address expected in hexadecimal: {}", e)))
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use crate::debugger::command::CommandType;

    #[test]
    fn command_type_from_str_test() {
        assert_eq!(CommandType::Continue, CommandType::from_str("c").unwrap(), "Expected 'c' to be continue");
    }
}
