use crate::debugger::{Debugger, DebuggerError};
use super::{CommandType, CommandParseError, Command};

use librsdb::types::{VirtualAddress};
use librsdb::process::Process;
use librsdb::disassembler::print_disassembly;

struct DisassembleCommand {
    address: Option<VirtualAddress>,
    instruction_count: usize
}

fn parse_disassemble_command(args: &[&str]) -> Result<DisassembleCommand, CommandParseError> {
    let mut address = None;
    let mut instruction_count = 5;

    // parse arguments
    // supported options are '-a <address>' and '-c <instruction_count>'
    let mut arg_iter = args.iter();
    while let Some(arg) = arg_iter.next() {
        match *arg {
            "-a" => {
                match arg_iter.next() {
                    Some(addr_str) => {
                        let addr = addr_str.parse().map_err(|e| CommandParseError::message(format!("Invalid address format: {}", e)))?;
                        address = Some(addr)
                    },
                    None => {
                        return Err(CommandParseError::show_help(CommandType::Disassemble));
                    }
                }
            },
            "-c" => {
                match arg_iter.next() {
                    Some(count_str) => {
                        let count = count_str.parse().map_err(|e| CommandParseError::message(format!("Invalid instruction count: {}", e)))?;
                        instruction_count = count;
                    },
                    None => {
                        return Err(CommandParseError::show_help(CommandType::Disassemble));
                    }
                }
            },
            _ => {
                return Err(CommandParseError::show_help(CommandType::Disassemble));
            }
        }
    }

    Ok(DisassembleCommand { address, instruction_count })
}

fn handle_disassemble_command(cmd: DisassembleCommand, process: &mut Process) -> Result<(), DebuggerError> {
    let address = cmd.address.unwrap_or(process.get_pc());
    print_disassembly(process, address, cmd.instruction_count)?;
    Ok(())
}

pub struct DisassembleCommandHandler {}
impl Command for DisassembleCommandHandler {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let cmd = parse_disassemble_command(args)?;
        handle_disassemble_command(cmd, debugger.process_mut())
    }

    fn describe(&self) {
        eprintln!("Available options:");
        eprintln!("  -c <number of instructions>");
        eprintln!("  -a <start address>");
    }

    fn summary(&self) -> &str { "Disassemble machine code to assembly" }
}
