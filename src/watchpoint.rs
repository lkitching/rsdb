use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};
use crate::register::DebugRegisterIndex;
use crate::stoppoint_collection::{StopPoint};
use crate::types::{StoppointMode, VirtualAddress};

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn get_next_id() -> u32 {
    let id = ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    id
}

pub struct WatchPoint {
    id: u32,
    address: VirtualAddress,
    is_enabled: bool,
    mode: StoppointMode,
    size: usize,
    hardware_register_index: Option<DebugRegisterIndex>
}

impl WatchPoint {
    pub fn new(address: VirtualAddress, mode: StoppointMode, size: usize) -> Self {
        // address must be aligned on a 'size'-byte boundary
        // e.g. 4 byte watchpoints on a 4-byte boundary
        if address.addr() & (size - 1) != 0 {
            panic!("Address {} not aligned on a {}-byte boundary", address, size);
        }

        Self {
            id: get_next_id(),
            address,
            is_enabled: false,
            mode,
            size,
            hardware_register_index: None
        }
    }

    pub fn address(&self) -> VirtualAddress { self.address }
    pub fn mode(&self) -> StoppointMode { self.mode }
    pub fn size(&self) -> usize { self.size }
    pub fn set_hardware_index(&mut self, hardware_index: DebugRegisterIndex) { self.hardware_register_index = Some(hardware_index); }
    pub fn hardware_index(&self) -> Option<DebugRegisterIndex> { self.hardware_register_index }
    pub fn clear_hardware_index(&mut self) { self.hardware_register_index = None; }
    pub fn set_enabled(&mut self) { self.is_enabled = true; }
    pub fn set_disabled(&mut self) { self.is_enabled = false; }
}

impl StopPoint for WatchPoint {
    type IdType = u32;

    fn id(&self) -> Self::IdType {
        self.id
    }

    fn at_address(&self, address: VirtualAddress) -> bool {
        self.address == address
    }

    fn in_range(&self, address_range: &Range<VirtualAddress>) -> bool {
        address_range.contains(&self.address)
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn disable(&mut self) {
        self.is_enabled = false;
    }
}