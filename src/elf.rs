use std::fs::File;
use std::path::{Path, PathBuf};
use std::{ptr, slice};
use std::cmp::Ordering;
use std::os::fd::AsRawFd;
use std::ffi::{CStr};
use std::collections::{HashMap, BTreeMap};
use std::rc::Rc;
use std::cell::OnceCell;
use std::hash::Hash;
use std::borrow::Borrow;
use std::ops::Bound;
use libc::{Elf64_Ehdr, PROT_READ, MAP_SHARED, size_t, c_void, Elf64_Shdr, Elf64_Xword, Elf64_Sym};

use crate::error::Error;
use crate::interop;
use crate::types::{VirtualAddress, FileAddress};

#[derive(Debug)]
struct FileAddressRange {
    start: FileAddress,
    end: FileAddress
}

impl PartialEq for FileAddressRange {
    fn eq(&self, other: &Self) -> bool {
        self.start.addr() == other.start.addr()
    }
}

impl Eq for FileAddressRange {}

impl PartialOrd for FileAddressRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileAddressRange {
    fn cmp(&self, other: &Self) -> Ordering {
        // NOTE: FileAddress only implements PartialOrd since comparison of addresses within
        // different ELF files is not defined
        // FileAddressRange instances *should* always contain addresses for the same instance
        assert!(Rc::ptr_eq(self.start.elf_ptr(), other.start.elf_ptr()), "address range starts in different ELF files");
        assert!(Rc::ptr_eq(self.end.elf_ptr(), other.end.elf_ptr()), "address range ends in different ELF files");

        self.start.addr().cmp(&other.start.addr())
    }
}

#[derive(Debug)]
struct UnorderedMultiMap<K, V> {
    items: HashMap<K, Vec<V>>,
}

impl <K, V> UnorderedMultiMap<K, V> {
    pub fn new() -> Self {
        Self { items: HashMap::new() }
    }
}

struct ValuesIterator<I> {
    inner: Option<I>
}

impl <I: Iterator> Iterator for ValuesIterator<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        let iter = self.inner.as_mut()?;
        iter.next()
    }
}

impl <K: Eq + Hash, V> UnorderedMultiMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) {
        match self.items.get_mut(&key) {
            None => {
                self.items.insert(key, vec![value]);
            },
            Some(values) => {
                values.push(value)
            }
        }
    }
    
    pub fn values_for<Q>(&self, key: &Q) -> impl Iterator<Item=&V>
    where
        K : Borrow<Q>,
        Q: Hash + Eq + ?Sized
    {
        let inner = self.items.get(key).map(|vs| vs.iter());
        ValuesIterator { inner }
    }
}

fn elf64_st_type(info: u8) -> u8 {
    info & 0x0F
}

const STT_TLS: u8 = 6;

pub struct Elf {
    file: File,
    file_len: u64,
    path: PathBuf,
    header: Elf64_Ehdr,
    mmap_ptr: *const c_void,
    section_headers: Vec<Elf64_Shdr>,
    section_map: HashMap<String, Elf64_Shdr>,
    load_bias: Option<VirtualAddress>,
    symbol_table: Vec<Elf64_Sym>,
    symbol_name_map: OnceCell<UnorderedMultiMap<String, Elf64_Sym>>,
    symbol_address_map: OnceCell<BTreeMap<FileAddressRange, Elf64_Sym>>
}

impl Elf {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Rc<Self>, Error> {
        let path: PathBuf = path.as_ref().to_path_buf();
        let file = File::open(path.as_path())?;

        let file_len = file.metadata()?.len();

        if (file_len as usize) < size_of::<Elf64_Ehdr>() {
            return Err(Error::from_message(String::from("Could not read ELF header")));
        }

        // mmap elf file
        let mmap_ptr = interop::mmap(ptr::null_mut(), file_len as size_t, PROT_READ, MAP_SHARED, file.as_raw_fd(), 0)?;

        // read header
        let header = unsafe { *(mmap_ptr as *const Elf64_Ehdr) };

        // read section headers
        let section_headers = Self::parse_section_headers(mmap_ptr as *const u8, &header);

        // build section header mapping
        let section_map = Self::build_section_map(mmap_ptr as *const u8, &header, section_headers.as_slice());

        // parse symbol table
        let symbol_table = Self::parse_symbol_table(mmap_ptr as *const u8, &section_map);

        let elf = Self {
            file,
            file_len,
            path,
            header,
            mmap_ptr,
            section_headers,
            section_map,
            symbol_table,
            symbol_address_map: OnceCell::new(),
            symbol_name_map: OnceCell::new(),
            load_bias: None
        };

        let mut elf = Rc::new(elf);
        elf.build_symbol_maps();

        Ok(elf)
    }

    pub fn notify_loaded(&mut self, addr: VirtualAddress) {
        self.load_bias = Some(addr)
    }

    pub fn load_bias(&self) -> Option<VirtualAddress> {
        self.load_bias
    }

    fn parse_section_headers(elf_ptr: *const u8, header: &Elf64_Ehdr) -> Vec<Elf64_Shdr> {
        // if file contains more than 0xFF00 sections, e_shnum is set to 0 and the number of
        // sections is contained within the first section header
        let num_sections = if header.e_shnum == 0 && header.e_shentsize > 0 {
            unsafe {
                let section_ptr = elf_ptr.add(header.e_shoff as usize) as *const Elf64_Shdr;
                (*section_ptr).sh_size
            }
        } else {
            header.e_shnum as Elf64_Xword
        };

        let headers = unsafe {
            let sections_ptr = elf_ptr.add(header.e_shoff as usize) as *const Elf64_Shdr;
            slice::from_raw_parts(sections_ptr, num_sections as usize)
        };

        headers.to_vec()
    }

    fn parse_symbol_table(elf_ptr: *const u8, section_map: &HashMap<String, Elf64_Shdr>) -> Vec<Elf64_Sym> {
        if let Some(symbol_table_section) = section_map.get(".symtab").or_else(|| section_map.get(".dynsym")) {
            let symbol_count = symbol_table_section.sh_size / symbol_table_section.sh_entsize;
            let symbols = unsafe {
                let sym_ptr = elf_ptr.add(symbol_table_section.sh_offset as usize) as *const Elf64_Sym;
                slice::from_raw_parts(sym_ptr, symbol_count as usize)
            };
            symbols.to_vec()
        } else {
            Vec::new()
        }
    }

    pub fn get_section_name(&self, index: usize) -> String {
        Self::find_section_header(self.mmap_ptr as *const u8, &self.header, self.section_headers.as_slice(), index)
    }

    fn find_section_header(elf_ptr: *const u8, header: &Elf64_Ehdr, section_headers: &[Elf64_Shdr], index: usize) -> String {
        let section = &section_headers[header.e_shstrndx as usize];
        Self::get_section_string(elf_ptr, section, index)
    }

    fn build_section_map<'a, 'b>(elf_ptr: *const u8, header: &Elf64_Ehdr, section_headers: &[Elf64_Shdr]) -> HashMap<String, Elf64_Shdr> {
        let mut map = HashMap::with_capacity(section_headers.len());

        for section in section_headers.iter() {
            let section_name = Self::find_section_header(elf_ptr, header, section_headers, section.sh_name as usize);
            map.insert(section_name, section.clone());
        }

        map
    }

    fn build_symbol_maps(self: &mut Rc<Self>) {
        let mut symbol_name_map = UnorderedMultiMap::new();
        let mut symbol_address_map = BTreeMap::new();

        for symbol in self.symbol_table.iter() {
            if let Some(mangled_name) = self.get_string(symbol.st_name as usize) {
                let demangle_result = interop::cxa_demangle(mangled_name.as_str());

                // insert names
                symbol_name_map.insert(mangled_name, symbol.clone());
                if let Ok(demangled_name) = demangle_result {
                    symbol_name_map.insert(demangled_name, symbol.clone());
                }
            }

            if symbol.st_value != 0 && symbol.st_name != 0 && elf64_st_type(symbol.st_info) != STT_TLS {
                let start = FileAddress::new(self.clone(), symbol.st_value as usize);
                let end = FileAddress::new(self.clone(), (symbol.st_value + symbol.st_size) as usize);
                let address_range = FileAddressRange { start, end };
                symbol_address_map.insert(address_range, symbol.clone());
            }
        }

        self.symbol_name_map.set(symbol_name_map).expect("Symbol name map already initialised");
        self.symbol_address_map.set(symbol_address_map).expect("Symbol address map already initialised");
    }

    pub fn get_symbols_by_name(&self, name: &str) -> impl Iterator<Item=&Elf64_Sym> {
        self.symbol_name_map.get().expect("Symbol name map not set").values_for(name)
    }

    pub fn get_symbol_at_file_address(self: &Rc<Self>, addr: &FileAddress) -> Option<&Elf64_Sym> {
        if Rc::ptr_eq(self, addr.elf_ptr()) {
            let map = self.symbol_address_map.get().expect("Symbol address map not set");

            // NOTE: only the first part of the range is used for the lookup
            // construct a range with an arbitrary end point
            let range = FileAddressRange { start: addr.clone(), end: FileAddress::new(self.clone(), 0) };
            map.get(&range)
        } else { None }
    }

    pub fn get_symbol_at_virtual_address(self: &Rc<Self>, addr: VirtualAddress) -> Option<&Elf64_Sym> {
        let file_addr = addr.to_file_address(self.clone())?;
        self.get_symbol_at_file_address(&file_addr)
    }

    pub fn get_symbol_containing_file_address(self: &Rc<Self>, addr: &FileAddress) -> Option<&Elf64_Sym> {
        if !Rc::ptr_eq(self, addr.elf_ptr()) {
            return None;
        }

        let map = self.symbol_address_map.get().expect("Symbol address map not set");

        // NOTE: only the first part of the range is used for the lookup
        // construct a range with an arbitrary end point
        let range = FileAddressRange { start: addr.clone(), end: FileAddress::new(self.clone(), 0) };

        // find first symbol with an address less than or equal to addr
        let cursor = map.upper_bound(Bound::Included(&range));
        let (key, value) = cursor.peek_prev()?;

        // check addr is in range
        if addr.addr() >= key.start.addr() && addr.addr() < key.end.addr() {
            Some(value)
        } else { None }
    }

    pub fn get_symbol_containing_virtual_address(self: &Rc<Self>, addr: VirtualAddress) -> Option<&Elf64_Sym> {
        let file_addr = addr.to_file_address(self.clone())?;
        self.get_symbol_containing_file_address(&file_addr)
    }

    pub fn get_section(&self, name: &str) -> Option<&Elf64_Shdr> {
        self.section_map.get(name)
    }

    pub fn get_section_contents(&self, name: &str) -> Option<&[u8]> {
        let section = self.get_section(name)?;
        let data = unsafe {
            let section_ptr = (self.mmap_ptr as *const u8).add(section.sh_offset as usize);
            slice::from_raw_parts(section_ptr, section.sh_size as usize)
        };
        Some(data)
    }

    fn get_section_string(elf_ptr: *const u8, section: &Elf64_Shdr, index: usize) -> String {
        unsafe {
            let section_ptr = elf_ptr.add(section.sh_offset as usize);

            // c-string starts at offset 'index' within the section
            let str_ptr = section_ptr.add(index);

            let c_str = CStr::from_ptr(str_ptr as *const i8);
            c_str.to_string_lossy().into_owned()
        }
    }

    pub fn get_string(&self, index: usize) -> Option<String> {
        let section = self.get_section(".strtab").or_else(|| self.get_section(".dynstr"))?;
        let str = Self::get_section_string(self.mmap_ptr as *const u8, section, index);
        Some(str)
    }

    pub fn get_section_containing_file_address(self: &Rc<Self>, addr: &FileAddress) -> Option<&Elf64_Shdr> {
        if Rc::ptr_eq(self, addr.elf_ptr()) {
            self.section_headers.iter().find(|sh| {
                let end_addr = sh.sh_addr + sh.sh_size;
                (sh.sh_addr..end_addr).contains(&(addr.addr() as u64))
            })
        } else { None }
    }

    pub fn get_section_containing_virtual_address(self: &Rc<Self>, addr: VirtualAddress) -> Option<&Elf64_Shdr> {
        let load_bias = self.load_bias?;
        self.section_headers.iter().find(|sh| {
            let start_addr = sh.sh_addr + (load_bias.addr() as u64);
            let end_addr = start_addr + sh.sh_size;
            (start_addr..end_addr).contains(&(addr.addr() as u64))
        })
    }

    pub fn get_section_start_address(self: &Rc<Self>, name: &str) -> Option<FileAddress> {
        let section = self.get_section(name)?;
        Some(FileAddress::new(self.clone(), section.sh_addr as usize))
    }
}

impl Drop for Elf {
    fn drop(&mut self) {
        let result = unsafe { libc::munmap(self.mmap_ptr as *mut c_void, self.file_len as size_t) };
        if result != 0 {
            // failed to unmap
            panic!("munmap failed!")
        }
    }
}