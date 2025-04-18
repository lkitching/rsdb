use std::mem;
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
    hardware_register_index: Option<DebugRegisterIndex>,
    data: u64,
    previous_data: Option<u64>
}

#[derive(Copy, Clone, Debug)]
pub enum WatchPointUpdate {
    Unchanged(u64),
    Updated { old_value: u64, new_value: u64 }
}

impl WatchPoint {
    pub fn new(address: VirtualAddress, mode: StoppointMode, size: usize, data_bytes: Vec<u8>) -> Self {
        // address must be aligned on a 'size'-byte boundary
        // e.g. 4 byte watchpoints on a 4-byte boundary
        if address.addr() & (size - 1) != 0 {
            panic!("Address {} not aligned on a {}-byte boundary", address, size);
        }

        let data = Self::encode_data(size, data_bytes);

        Self {
            id: get_next_id(),
            address,
            is_enabled: false,
            mode,
            size,
            hardware_register_index: None,
            data,
            previous_data: None
        }
    }

    fn encode_data(expected_size: usize, bytes: Vec<u8>) -> u64 {
        assert_eq!(expected_size, bytes.len(), "Expected data length {} for watchpoint value, got {}", expected_size, bytes.len());
        match expected_size {
            1 => bytes[0] as u64,
            2 => u16::from_le_bytes(bytes.try_into().unwrap()) as u64,
            4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
            8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => panic!("Unsupported data length {}", expected_size)
        }
    }

    pub fn set_data(&mut self, bytes: Vec<u8>) -> WatchPointUpdate {
        let value = Self::encode_data(self.size, bytes);
        let prev = mem::replace(&mut self.data, value);

        let update = if prev == value {
            WatchPointUpdate::Unchanged(value)
        } else {
            WatchPointUpdate::Updated { old_value: prev, new_value: value }
        };

        self.previous_data = Some(prev);
        update
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