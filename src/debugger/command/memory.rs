use crate::debugger::{Debugger, DebuggerError};
use super::{CommandType, CommandParseError, Command};

use librsdb::types::{VirtualAddress};
use librsdb::process::Process;
use librsdb::parse;

fn handle_memory_command(cmd: MemoryCommand, process: &mut Process) -> Result<(), DebuggerError> {
    match cmd {
        MemoryCommand::Read(addr, num_bytes) => {
            let data = process.read_memory(addr, num_bytes)?;

            // display data in 16-byte chunks
            let mut chunk_address = addr;
            for chunk in data.chunks(16) {
                let bytes: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                println!("{}: {}", chunk_address, bytes.join(" "));
                chunk_address += chunk.len() as isize;
            }
        },
        MemoryCommand::Write(addr, bytes) => {
            process.write_memory(addr, bytes.as_slice())?;
        }
    }

    Ok(())
}

fn parse_address(addr_str: &str) -> Result<VirtualAddress, CommandParseError> {
    parse::to_integral(addr_str, 16)
        .map_err(|e| CommandParseError::message(format!("Invalid address: {}", e)))
}

fn parse_memory_write_command(args: &[&str]) -> Result<MemoryCommand, CommandParseError> {
    if args.len() == 2 {
        let addr = parse_address(args[0])?;
        let data = parse::parse_vector(&args[1])
            .map_err(|e| CommandParseError::message(format!("Invalid data format: {}", e)))?;
        Ok(MemoryCommand::Write(addr, data))
    } else {
        Err(CommandParseError::show_help(CommandType::Memory))
    }
}

enum MemoryCommand {
    Read(VirtualAddress, usize),
    Write(VirtualAddress, Vec<u8>)
}

fn parse_memory_read_command(args: &[&str]) -> Result<MemoryCommand, CommandParseError> {
    let address = parse_address(args[0])?;
    let num_bytes = if args.len() > 1 {
        parse::to_integral(&args[1], 10)
            .map_err(|e| CommandParseError::message(format!("Invalid number of bytes: {}", e)))?
    } else {
        32usize
    };
    Ok(MemoryCommand::Read(address, num_bytes))
}

fn parse_memory_command(args: &[&str]) -> Result<MemoryCommand, CommandParseError> {
    if args.len() < 2 {
        return Err(CommandParseError::show_help(CommandType::Memory));
    }

    let memory_command = args[0];
    let command_args = &args[1..];
    if "read".starts_with(memory_command) {
        parse_memory_read_command(command_args)
    } else if "write".starts_with(memory_command) {
        parse_memory_write_command(command_args)
    } else {
        Err(CommandParseError::show_help(CommandType::Memory))
    }
}

pub struct MemoryCommandHandler {}
impl Command for MemoryCommandHandler {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let cmd = parse_memory_command(args)?;
        handle_memory_command(cmd, debugger.process_mut())
    }

    fn describe(&self) {
        eprintln!("Available commands:");
        eprintln!("  read <address>");
        eprintln!("  read <address> <num_bytes>");
        eprintln!("  write <address> <bytes>");
    }

    fn summary(&self) -> &str { "Commands for operating on memory" }
}
