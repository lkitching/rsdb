use std::sync::atomic::{AtomicU32, Ordering};
use libc::{pid_t};

use crate::types::VirtualAddress;
use crate::stoppoint_collection::{StopPoint};
use crate::error::Error;
use crate::interop::ptrace;

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn get_next_id() -> u32 {
    let id = ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    id
}

pub struct BreakpointSite {
    id: u32,
    pid: pid_t,
    address: VirtualAddress,
    is_enabled: bool,
    saved_data: u8
}

impl BreakpointSite {
    pub fn new(pid: pid_t, address: VirtualAddress) -> Self {
        let id = get_next_id();
        Self { id, pid, address, is_enabled: false, saved_data: 0 }
    }

    pub fn address(&self) -> VirtualAddress {
        self.address
    }

    pub fn enable(&mut self) -> Result<(), Error> {
        if self.is_enabled {
            return Ok(());
        }

        let data = ptrace::peek_data(self.pid, self.address).map_err(|e| e.with_context("Failed to enable breakpoint site"))?;

        // mask off all but low byte and save
        self.saved_data = (data & 0xFF) as u8;

        // set lower byte of data to 0xCC
        let data_with_int3 = (data & !0xFF) | 0xCC;
        ptrace::poke_data(self.pid, self.address, data_with_int3)?;

        self.is_enabled = true;
        Ok(())
    }

    pub fn disable(&mut self) -> Result<(), Error> {
        if self.is_disabled() {
            return Ok(());
        }

        // read word at breakpoint address
        let data = ptrace::peek_data(self.pid, self.address)?;

        // clear low byte and restore saved data into it
        let restored_data = (data & !0xFF) | (self.saved_data as usize);

        // write resulting word back into memory
        ptrace::poke_data(self.pid, self.address, restored_data)?;

        self.is_enabled = false;
        Ok(())
    }
}

impl StopPoint for BreakpointSite {
    type IdType = u32;
    fn id(&self) -> Self::IdType { self.id }
    fn at_address(&self, address: VirtualAddress) -> bool { self.address == address }
    fn is_enabled(&self) -> bool { self.is_enabled }
    fn disable(&mut self) { self.is_enabled = false; }
}