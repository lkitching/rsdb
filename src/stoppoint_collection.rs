use crate::types::VirtualAddress;
use crate::error::{Error};
use crate::register::RegisterType;

pub trait StopPoint {
    type IdType: Copy + PartialEq;
    fn id(&self) -> Self::IdType;

    fn at_address(&self, address: VirtualAddress) -> bool;

    fn is_enabled(&self) -> bool;

    fn is_disabled(&self) -> bool {
        !self.is_enabled()
    }

    fn disable(&mut self);
}

pub struct StopPointCollection<S> {
    stop_points: Vec<S>
}

impl <S : StopPoint> StopPointCollection<S> {
    pub fn push(&mut self, point: S) -> &mut S {
        self.stop_points.push(point);
        let inserted_at = self.stop_points.len() - 1;
        &mut self.stop_points[inserted_at]
    }

    pub fn contains_id(&self, id: S::IdType) -> bool {
        self.find_by_id(id).is_some()
    }

    pub fn contains_address(&self, address: VirtualAddress) -> bool {
        self.find_by_address(address).is_some()
    }

    pub fn enabled_stoppoint_at_address(&self, address: VirtualAddress) -> bool {
        self.find_by_address(address).map(|sp| sp.is_enabled()).unwrap_or(false)
    }

    pub fn get_by_id(&self, id: S::IdType) -> Result<&S, Error> {
        self.find_by_id(id).ok_or_else(|| Error::from_message(String::from("Invalid stoppoint id")))
    }

    pub fn get_by_id_mut(&mut self, id: S::IdType) -> Result<&mut S, Error> {
        self.find_by_id_mut(id).ok_or_else(|| Error::from_message(String::from("Invalid stoppoint id")))
    }

    pub fn get_by_address(&self, address: VirtualAddress) -> Result<&S, Error> {
        self.find_by_address(address).ok_or_else(|| Error::from_message(String::from("Stoppoint with given address not found")))
    }

    pub fn get_by_address_mut(&mut self, address: VirtualAddress) -> Result<&mut S, Error> {
        self.find_by_address_mut(address).ok_or_else(|| Error::from_message(String::from("Stoppoint with given address not found")))
    }

    pub fn remove_by_id(&mut self, id: S::IdType) {
        if let Some((idx, _sp)) = self.find_indexed_by_id(id) {
            self.remove_by_index(idx);
        }
    }

    pub fn remove_by_address(&mut self, address: VirtualAddress) {
        if let Some((idx, _sp)) = self.find_indexed_by_address(address) {
            self.remove_by_index(idx);
        }
    }

    fn remove_by_index(&mut self, idx: usize) {
        // NOTE: could use swap_remove here? Could make UI confusing!
        let mut sp = self.stop_points.remove(idx);
        sp.disable();
    }

    fn find_by_id(&self, id: S::IdType) -> Option<&S> {
        self.find_indexed_by_id(id).map(|(_idx, sp)| sp)
    }

    fn find_indexed_by_id(&self, id: S::IdType) -> Option<(usize, &S)> {
        self.stop_points.iter().enumerate().find(|(_idx, sp)| sp.id() == id)
    }

    fn find_by_id_mut(&mut self, id: S::IdType) -> Option<&mut S> {
        self.stop_points.iter_mut().find(|sp| sp.id() == id)
    }

    fn find_by_address(&self, address: VirtualAddress) -> Option<&S> {
        self.find_indexed_by_address(address).map(|(_idx, sp)| sp)
    }

    fn find_by_address_mut(&mut self, address: VirtualAddress) -> Option<&mut S> {
        self.stop_points.iter_mut().find(|sp| sp.at_address(address))
    }

    fn find_indexed_by_address(&self, address: VirtualAddress) -> Option<(usize, &S)> {
        self.stop_points.iter().enumerate().find(|(_idx, sp)| sp.at_address(address))
    }
}

impl <S> StopPointCollection<S> {
    pub fn new() -> Self {
        Self { stop_points: Vec::new() }
    }
    pub fn len(&self) -> usize { self.stop_points.len() }
    pub fn is_empty(&self) -> bool { self.stop_points.is_empty() }
    pub fn iter(&self) -> impl Iterator<Item=&S> { self.stop_points.iter() }
    pub fn iter_mut(&mut self) -> impl Iterator<Item=&mut S> { self.stop_points.iter_mut() }
}