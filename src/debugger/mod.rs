mod command;

use std::fmt;
use std::str::FromStr;

use rustyline;

use librsdb::error::{Error};
use librsdb::process::{Process, PID, PIDParseError, StdoutReplacement};
use command::{CommandParseError, CommandType};
use command::{HelpCommandHandler};

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

    pub fn process(&self) -> &Process { &self.proc }

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
