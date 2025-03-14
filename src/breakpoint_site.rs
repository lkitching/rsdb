use std::sync::atomic::{AtomicU32, Ordering};
use libc::{pid_t};

use crate::types::VirtualAddress;
use crate::stoppoint_collection::{StopPoint};

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
}

impl StopPoint for BreakpointSite {
    type IdType = u32;
    fn id(&self) -> Self::IdType { self.id }
    fn at_address(&self, address: VirtualAddress) -> bool { self.address == address }
    fn is_enabled(&self) -> bool { self.is_enabled }
    fn disable(&mut self) { self.is_enabled = false; }
}