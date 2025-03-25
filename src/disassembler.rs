use std::ffi::{c_void, CStr};
use std::mem::MaybeUninit;
use crate::types::VirtualAddress;
use crate::process::Process;
use crate::error::Error;

use zydis_sys::{ZydisDisassembleATT, ZydisMachineMode, ZyanU64, ZyanUSize, ZyanStatus};

pub struct Instruction {
    address: VirtualAddress,
    text: String
}

pub struct Disassembler<'a> {
    process: &'a Process
}

// NOTE: not defined in zydis-sys crate?
// taken from https://github.com/zyantific/zycore-c/blob/0b2432ced0884fd152b471d97ecf0258ff4d859f/include/Zycore/Status.h#L81
fn zyan_success(result: ZyanStatus) -> bool {
    (result & 0x80000000) == 0
}

impl <'a> Disassembler<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self { process }
    }

    pub fn disassemble(&self, num_instructions: usize, address: Option<VirtualAddress>) -> Result<Vec<Instruction>, Error> {
        let mut instructions: Vec<Instruction> = Vec::with_capacity(num_instructions);
        let address = address.unwrap_or(self.process.get_pc());

        // NOTE: largest x64 instruction is 15 bytes so ensure we read enough to cover the number of instructions
        let code = self.process.read_memory(address, num_instructions * 15)?;

        {
            let mut code_p = code.as_ptr();
            let mut bytes_remaining = code.len();
            let mut current_address = address;

            for _ in 0..num_instructions {
                unsafe {
                    let mut instr = MaybeUninit::uninit();
                    let result = ZydisDisassembleATT(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, current_address.addr() as ZyanU64, code_p as *const c_void, bytes_remaining as ZyanUSize, instr.as_mut_ptr());
                    if zyan_success(result) {
                        let instr = instr.assume_init();

                        // text is null-terminated c string
                        let text_p = instr.text.as_ptr();
                        let text_str = CStr::from_ptr(text_p);
                        let text = text_str.to_string_lossy().to_string();

                        instructions.push(Instruction { address: current_address, text });

                        code_p = code_p.add(instr.info.length as usize);
                        bytes_remaining -= instr.info.length as usize;
                        current_address += instr.info.length as isize;
                    } else {
                        return Err(Error::Message(String::from("Failed to decode instruction")));
                    }
                }
            }
        }

        Ok(instructions)
    }
}

pub fn print_disassembly(process: &Process, address: VirtualAddress, num_instructions: usize) -> Result<(), Error> {
    let dis = Disassembler::new(process);
    let instructions = dis.disassemble(num_instructions, Some(address))?;

    for instr in instructions.iter() {
        println!("{} {}", instr.address, instr.text);
    }

    Ok(())
}