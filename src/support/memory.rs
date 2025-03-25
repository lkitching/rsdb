use std::io::{self, Write};
use libc::{raise, SIGTRAP};

fn main() {
    let a: u64 = 0xcafecafe;
    let a_address = &a as *const u64;
    let a_address_bytes = (a_address as usize).to_le_bytes();

    let mut stdout = io::stdout();
    stdout.write_all(a_address_bytes.as_slice()).expect("Failed to write int address");
    stdout.flush().expect("Failed to flush stdout");

    unsafe { raise(SIGTRAP); }

    {
        // test writes
        // NOTE: book also allocated 12 bytes but we write a longer message and don't need the terminator
        let str = String::from("xxxxxxxxxxxx");

        let str_address = str.as_ptr();
        let str_address_bytes = (str_address as usize).to_le_bytes();

        stdout.write_all(str_address_bytes.as_slice()).expect("Failed to write string address");
        stdout.flush().expect("Failed to flush stdout");

        unsafe { raise(SIGTRAP); }

        print!("{}", str);
        stdout.flush().expect("Failed to flush stdout");
    }
}