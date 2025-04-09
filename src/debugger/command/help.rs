use std::str::FromStr;

use crate::debugger::{Debugger, DebuggerError};
use super::{CommandType, CommandParseError, Command};

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