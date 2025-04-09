use std::env;

mod debugger;

use debugger::{Debugger, DebuggerError};

fn main() -> Result<(), DebuggerError> {
    let args: Vec<String> = env::args().collect();

    let mut debugger = Debugger::launch(args.as_slice())?;
    debugger.main_loop()
}
