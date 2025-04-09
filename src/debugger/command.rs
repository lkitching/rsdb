use std::fmt::{self, Formatter};
use std::str::FromStr;

use super::{Debugger, DebuggerError};
use librsdb::error::{Error};
use librsdb::types::{Value, VirtualAddress};
use librsdb::process::{Process, StopReason};
use librsdb::stoppoint_collection::StopPoint;
use librsdb::register::{RegisterType, RegisterInfo, REGISTER_INFOS, find_register_info_by_name};
use librsdb::disassembler::print_disassembly;
use librsdb::parse::{self, parse_register_value};

pub trait Command {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError>;

    fn describe(&self);
    fn summary(&self) -> &str;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CommandType {
    Breakpoint,
    Continue,
    Disassemble,
    Memory,
    Register,
    Step,
    Help
}

impl CommandType {
    pub fn get_handler(self) -> Box<dyn Command> {
        match self {
            Self::Breakpoint => Box::new(BreakpointCommandHandler {}),
            Self::Continue => Box::new(ContinueCommandHandler {}),
            Self::Disassemble => Box::new(DisassembleCommandHandler {}),
            Self::Memory => Box::new(MemoryCommandHandler {}),
            Self::Register => Box::new(RegisterCommandHandler {}),
            Self::Step => Box::new(StepCommandHandler {}),
            Self::Help => Box::new(HelpCommandHandler {})
        }
    }

    fn values() -> impl Iterator<Item=Self> {
        [Self::Breakpoint, Self::Continue, Self::Disassemble, Self::Memory,
            Self::Register, Self::Step, Self::Help].into_iter()
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
            Ok(Self::Continue)
        } else if "disassemble".starts_with(s) {
            Ok(Self::Disassemble)
        } else if "memory".starts_with(s) {
            Ok(Self::Memory)
        } else if "register".starts_with(s) {
            Ok(Self::Register)
        } else if "step".starts_with(s) {
            Ok(Self::Step)
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

struct ContinueCommandHandler {}
impl Command for ContinueCommandHandler {

    fn exec(&self, _args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let process = debugger.process_mut();

        process.resume()?;
        let reason = process.wait_on_signal()?;
        handle_stop(process, &reason)?;
        Ok(())
    }

    fn describe(&self) {
        eprintln!("Available commands: <none>");
    }

    fn summary(&self) -> &str { "Resume the process" }
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

struct RegisterCommandHandler { }
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

enum BreakpointCommand {
    List,
    Set(VirtualAddress),
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
        Ok(BreakpointCommand::Set(address))
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
                for bp in process.breakpoint_sites().iter() {
                    println!("{}: address = {}, {}", bp.id(), bp.address(), if bp.is_enabled() { "enabled" } else { "disabled" });
                }
            }
        },
        BreakpointCommand::Set(addr) => {
            let bp = process.create_breakpoint_site(addr)?;
            bp.enable()?;
        },
        BreakpointCommand::Enable(id) => {
            let bp = process.breakpoint_sites_mut().get_by_id_mut(id)?;
            bp.enable()?;
        },
        BreakpointCommand::Disable(id) => {
            let bp = process.breakpoint_sites_mut().get_by_id_mut(id)?;
            bp.disable()?;
        },
        BreakpointCommand::Delete(id) => {
            process.breakpoint_sites_mut().remove_by_id(id);
        }
    }

    Ok(())
}

struct BreakpointCommandHandler {}
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
    }

    fn summary(&self) -> &str { "Commands for operating on breakpoints" }
}

struct StepCommandHandler {}
impl Command for StepCommandHandler {
    fn exec(&self, _args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let process = debugger.process_mut();
        let reason = process.step_instruction()?;
        handle_stop(process, &reason)?;
        Ok(())
    }

    fn describe(&self) {
        eprintln!("Available commands: <none>");
    }

    fn summary(&self) -> &str { "Step over a single instruction" }
}


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

struct MemoryCommandHandler {}
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

struct DisassembleCommandHandler {}
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

pub struct HelpCommandHandler {}

impl Command for HelpCommandHandler {
    fn exec(&self, args: &[&str], _debugger: &mut Debugger) -> Result<(), DebuggerError> {
        let cmd = parse_help_command(args)?;
        Self::show_help(cmd.help);
        Ok(())
    }

    fn describe(&self) {
        eprintln!("Available commands:");
        eprintln!("  <command name>");
    }

    fn summary(&self) -> &str { "Get help" }
}

impl HelpCommandHandler {
    pub fn show_help(command_type_opt: Option<CommandType>) {
        match command_type_opt {
            Some(command_type) => {
                let handler = command_type.get_handler();
                handler.describe();
            },
            None => {
                let mut commands: Vec<(CommandType, String)> = CommandType::values().map(|ct| (ct, ct.to_string())).collect();
                commands.sort_by(|(_, name1), (_, name2)| name1.cmp(name2));
                let (_, longest_name) = commands.iter().max_by_key(|(_, name)| name.len()).expect("Expected command handler");
                let longest_name_len = longest_name.len();

                eprintln!("Available commands:");
                for (cmd_type, name) in commands {
                    let handler = cmd_type.get_handler();
                    let padding_len = longest_name_len - name.len();
                    let padding = String::from_iter(std::iter::repeat(' ').take(padding_len));

                    eprintln!("  {}{} - {}", name, padding, handler.summary())
                }
            }
        }
    }
}

struct HelpCommand {
    help: Option<CommandType>
}


fn parse_help_command(command_args: &[&str]) -> Result<HelpCommand, CommandParseError> {
    match command_args.first() {
        None => { Ok(HelpCommand { help: None })},
        Some(cmd) => {
            let category = CommandType::from_str(cmd)?;
            Ok(HelpCommand { help: Some(category) })
        }
    }
}