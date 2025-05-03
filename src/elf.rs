use std::fs::File;
use std::path::{Path, PathBuf};
use std::{ptr, slice};
use std::os::fd::AsRawFd;
use std::ffi::{CStr};
use std::collections::HashMap;
use std::rc::Rc;

use libc::{Elf64_Ehdr, PROT_READ, MAP_SHARED, size_t, c_void, Elf64_Shdr, Elf64_Xword};

use crate::error::Error;
use crate::interop;
use crate::types::{VirtualAddress, FileAddress};

pub struct Elf {
    file: File,
    file_len: u64,
    path: PathBuf,
    header: Elf64_Ehdr,
    mmap_ptr: *const c_void,
    section_headers: Vec<Elf64_Shdr>,
    section_map: HashMap<String, Elf64_Shdr>,
    load_bias: Option<VirtualAddress>
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

        let elf = Self {
            file,
            file_len,
            path,
            header,
            mmap_ptr,
            section_headers,
            section_map,
            load_bias: None
        };

        Ok(Rc::new(elf))
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