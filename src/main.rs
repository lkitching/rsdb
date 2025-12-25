use std::env;

use libc::{signal, SIGINT, pid_t, c_int, kill, SIGSTOP, sighandler_t};

mod debugger;

use debugger::{Debugger, DebuggerError};
use librsdb::dwarf::{DIEEntry, DIEEntryIterator, DwarfForm};
use librsdb::process::{self, StdoutReplacement};

static mut PID: Option<pid_t> = None;

fn handle_sigint(_signum: c_int) {
    unsafe {
        // send stop signal to inferior process on SIGINT
        if let Some(pid) = PID {
            kill(pid, SIGSTOP);
        }
    }
}

fn attach(args: &[String]) -> Result<Debugger, DebuggerError> {
    match args.len() {
        0 => Err(DebuggerError::UsageError),
        2 if args[0] == "-p" => {
            // passing PID
            let pid = args[1].parse::<process::PID>()?;
            let debugger = Debugger::attach(pid)?;
            Ok(debugger)
        },
        _ => {
            let program_path = args[0].as_str();
            let debugger = Debugger::launch(program_path, true, StdoutReplacement::None)?;
            println!("Launched process with PID {}", debugger.process().pid());
            Ok(debugger)
        }
    }
}

fn main() -> Result<(), DebuggerError> {
    // let args: Vec<String> = env::args().collect();
    //
    // // NOTE: first argument should be program name
    // let mut debugger = attach(&args[1..])?;
    //
    // // install signal handler for SIGINT
    // unsafe {
    //     PID = Some(debugger.process().pid());
    //     signal(SIGINT, handle_sigint as sighandler_t);
    // }
    // debugger.main_loop()

    let elf = librsdb::elf::Elf::open("target/debug/hello_rsdb")?;
    let dwarf = librsdb::dwarf::Dwarf::new(elf).expect("Failed to parse DWARF");
    for cu in dwarf.get_compile_units() {
        println!("{:?}", cu);

        let abbrev_table = dwarf.get_compile_unit_abbrev_table(&cu);
        println!("Abbrev table:");
        println!("{:?}", abbrev_table);

        //let root_entry = cu.get_root(&dwarf);
        println!("DIE entries:");
        let it = DIEEntryIterator::for_compile_unit(cu.clone(), &dwarf);
        for entry in it {
            println!("{:?}", entry);

            if let DIEEntry::Entry(die) = entry {
                // get abbrev for DIE
                let abbrev = abbrev_table.get_by_code(die.abbrev_code).expect("Failed to get DIE abbrev");

                println!("Has children? {}", abbrev.has_children);

                if let Ok(low) = die.low_pc(&cu, &dwarf) {
                    println!("Low PC: {:?}", low);

                    if let Ok(high) = die.high_pc(&cu, &dwarf) {
                        println!("High PC: {:?}", high);
                    }
                }

                println!("Attributes:");
                for attr_spec in abbrev.attribute_specs.iter() {
                    let attr = die.get_attribute(abbrev, attr_spec.attribute).expect("Failed to get attribute");
                    println!("{:?}", attr);

                    if let Ok(addr) = attr.as_address(&dwarf) {
                        println!("Address: {:?}", addr)
                    }

                    if let Ok(i) = attr.as_int(&dwarf) {
                        println!("Int: {}", i)
                    }

                    if let Ok(offset) = attr.as_section_offset(&dwarf) {
                        println!("Section offset: {}", offset)
                    }

                    if let Ok(block) = attr.as_block(&dwarf) {
                        println!("Block: {:?}", block)
                    }

                    if let Ok(ref_die) = attr.as_reference(cu, &dwarf) {
                        println!("Reference: {:?}", ref_die)
                    }
                    
                    if let Ok(s) = attr.as_string(&dwarf) {
                        println!("String: {}", s)
                    }
                }
            }

            println!()
        }
    }

    Ok(())
}
