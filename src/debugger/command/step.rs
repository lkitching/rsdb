use super::{Command, handle_stop};
use crate::debugger::{Debugger, DebuggerError};

pub struct StepCommandHandler {}
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
