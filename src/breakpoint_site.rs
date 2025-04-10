use std::sync::atomic::{AtomicU32, Ordering};
use std::ops::Range;

use libc::{pid_t};

use crate::types::VirtualAddress;
use crate::stoppoint_collection::{StopPoint};
use crate::register::DebugRegisterIndex;

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn get_next_id() -> u32 {
    let id = ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    id
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BreakpointType { Hardware, Software }

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BreakpointScope { Internal, External }

pub struct BreakpointSite {
    id: u32,
    pid: pid_t,
    address: VirtualAddress,
    is_enabled: bool,
    saved_data: u8,
    _type: BreakpointType,
    scope: BreakpointScope,
    hardware_register_index: Option<DebugRegisterIndex>
}

impl BreakpointSite {
    pub fn new(pid: pid_t, address: VirtualAddress, breakpoint_type: BreakpointType, scope: BreakpointScope) -> Self {
        let id = get_next_id();
        Self { id, pid, address, is_enabled: false, saved_data: 0, scope, _type: breakpoint_type, hardware_register_index: None }
    }

    pub fn address(&self) -> VirtualAddress {
        self.address
    }
    pub fn breakpoint_type(&self) -> BreakpointType { self._type }
    pub fn scope(&self) -> BreakpointScope { self.scope }

    pub fn set_enabled(&mut self) { self.is_enabled = true; }
    pub fn set_disabled(&mut self) { self.is_enabled = false; }
    pub fn save(&mut self, data: u8) { self.saved_data = data; }

    pub fn set_hardware_index(&mut self, hardware_index: DebugRegisterIndex) { self.hardware_register_index = Some(hardware_index); }
    pub fn hardware_index(&self) -> Option<DebugRegisterIndex> { self.hardware_register_index }
    pub fn clear_hardware_index(&mut self) { self.hardware_register_index = None; }

    pub fn saved_data(&self) -> u8 {
        self.saved_data
    }
    pub fn is_internal(&self) -> bool { self.scope == BreakpointScope::Internal }
    pub fn is_external(&self) -> bool { self.scope == BreakpointScope::External }

    pub fn is_hardware(&self) -> bool { self._type == BreakpointType::Hardware }
    pub fn is_software(&self) -> bool { self._type == BreakpointType::Software }
}

impl StopPoint for BreakpointSite {
    type IdType = u32;
    fn id(&self) -> Self::IdType { self.id }
    fn at_address(&self, address: VirtualAddress) -> bool { self.address == address }
    fn is_enabled(&self) -> bool { self.is_enabled }

    fn in_range(&self, address_range: &Range<VirtualAddress>) -> bool {
        address_range.contains(&self.address)
    }

    fn disable(&mut self) { self.is_enabled = false; }
}