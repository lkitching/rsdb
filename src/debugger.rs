use std::fmt;
use std::fmt::{Debug, Formatter};
use std::str::{FromStr};

use rustyline;

use librsdb::error::{Error};
use librsdb::types::{Value, VirtualAddress};
use librsdb::register::{RegisterType, RegisterInfo, REGISTER_INFOS, find_register_info_by_name};
use librsdb::process::{Process, PID, PIDParseError, StdoutReplacement, StopReason};
use librsdb::parse::{self, parse_register_value};
use librsdb::stoppoint_collection::StopPoint;
use librsdb::disassembler::print_disassembly;

#[derive(Debug)]
pub enum DebuggerError {
    InputError(String),
    InteropError(Error),
    UsageError,
    InvalidCommand(CommandParseError)
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
            Self::UsageError => {
                write!(f, "Usage: rsdb -p [pid] command")
            },
            Self::InvalidCommand(parse_error) => {
                match parse_error.message.as_ref() {
                    None => Ok(()),
                    Some(msg) => write!(f, "{}", msg)
                }
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

impl From<CommandParseError> for DebuggerError {
    fn from(e: CommandParseError) -> Self {
        Self::InvalidCommand(e)
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

fn handle_stop(process: &Process, reason: &StopReason) -> Result<(), Error> {
    print_stop_reason(process, reason);
    if reason.reason.is_stopped() {
        print_disassembly(process, process.get_pc(), 5)
    } else {
        Ok(())
    }
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum CommandType {
    Breakpoint,
    Continue,
    Disassemble,
    Memory,
    Register,
    Step,
    Help
}

impl CommandType {
    fn get_handler(self) -> Box<dyn Command> {
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

struct HelpCommand {
    help: Option<CommandType>
}

#[derive(Clone, Debug)]
pub struct CommandParseError {
    message: Option<String>,
    help: Option<CommandType>
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

fn parse_help_command(command_args: &[&str]) -> Result<HelpCommand, CommandParseError> {
    match command_args.first() {
        None => { Ok(HelpCommand { help: None })},
        Some(cmd) => {
            let category = CommandType::from_str(cmd)?;
            Ok(HelpCommand { help: Some(category) })
        }
    }
}

fn parse_command_type(line: &str) -> Result<(CommandType, Vec<&str>), CommandParseError> {
    let mut args = line.split(' ');
    let command_name = args.next().expect("Expected at least one segment");
    let command_type = CommandType::from_str(command_name)?;
    let command_args: Vec<&str> = args.collect();

    Ok((command_type, command_args))
}

pub struct Debugger {
    proc: Process,
}

impl Debugger {
    pub fn launch(args: &[String]) -> Result<Self, DebuggerError> {
        if args.len() == 1 {
            Err(DebuggerError::UsageError)
        } else {
            let proc = attach(args)?;
            Ok(Self { proc })
        }
    }

    pub fn process_mut(&mut self) -> &mut Process { &mut self.proc }

    fn handle_command_parse_error(&self, e: CommandParseError) {
        if let Some(message) = e.message {
            eprintln!("{}", message);
        }

        if let Some(category) = e.help {
            HelpCommandHandler::show_help(Some(category));
        }
    }

    pub fn main_loop(&mut self) -> Result<(), DebuggerError> {
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
                match parse_command_type(cmd.as_str()) {
                    Ok((command_type, args)) => {
                        let handler = command_type.get_handler();
                        let command_result = handler.exec(args.as_slice(), self);

                        match command_result {
                            Err(DebuggerError::InvalidCommand(parse_error)) => {
                                self.handle_command_parse_error(parse_error)
                            },
                            Err(e) => {
                                eprintln!("{}", e)
                            },
                            Ok(_) => { }
                        }
                    }
                    Err(parse_err) => {
                        self.handle_command_parse_error(parse_err);
                    }
                }
            }
        }
    }
}

trait Command {
    fn exec(&self, args: &[&str], debugger: &mut Debugger) -> Result<(), DebuggerError>;

    fn describe(&self);
    fn summary(&self) -> &str;
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

struct HelpCommandHandler {}

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