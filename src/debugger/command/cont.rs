use crate::debugger::{Debugger, DebuggerError};
use super::{Command, handle_stop};

pub struct ContinueCommandHandler {}
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
