use std::rc::Rc;
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::num::NonZeroU64;
use std::ops::AddAssign;

use strum_macros::FromRepr;

use crate::elf::{Elf};
use crate::types::{FileAddress, TryFromBytes};
use crate::error::Error;

#[allow(non_camel_case_types)]
#[repr(u64)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
pub enum DwarfForm {
    DW_FORM_addr = 0x01,
    DW_FORM_block2 = 0x03,
    DW_FORM_block4 = 0x04,
    DW_FORM_data2 = 0x05,
    DW_FORM_data4 = 0x06,
    DW_FORM_data8 = 0x07,
    DW_FORM_string = 0x08,
    DW_FORM_block = 0x09,
    DW_FORM_block1 = 0x0a,
    DW_FORM_data1 = 0x0b,
    DW_FORM_flag = 0x0c,
    DW_FORM_sdata = 0x0d,
    DW_FORM_strp = 0x0e,
    DW_FORM_udata = 0x0f,
    DW_FORM_ref_addr = 0x10,
    DW_FORM_ref1 = 0x11,
    DW_FORM_ref2 = 0x12,
    DW_FORM_ref4 = 0x13,
    DW_FORM_ref8 = 0x14,
    DW_FORM_ref_udata = 0x15,
    DW_FORM_indirect = 0x16,
    DW_FORM_sec_offset = 0x17,
    DW_FORM_exprloc = 0x18,
    DW_FORM_flag_present = 0x19,
    DW_FORM_ref_sig8 = 0x20,
}

#[allow(non_camel_case_types)]
#[repr(u64)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
pub enum DwarfAttribute {
    DW_AT_sibling = 0x01,
    DW_AT_location = 0x02,
    DW_AT_name = 0x03,
    DW_AT_ordering = 0x09,
    DW_AT_byte_size = 0x0b,
    DW_AT_bit_offset = 0x0c,
    DW_AT_bit_size = 0x0d,
    DW_AT_stmt_list = 0x10,
    DW_AT_low_pc = 0x11,
    DW_AT_high_pc = 0x12,
    DW_AT_language = 0x13,
    DW_AT_discr = 0x15,
    DW_AT_discr_value = 0x16,
    DW_AT_visibility = 0x17,
    DW_AT_import = 0x18,
    DW_AT_string_length = 0x19,
    DW_AT_common_reference = 0x1a,
    DW_AT_comp_dir = 0x1b,
    DW_AT_const_value = 0x1c,
    DW_AT_containing_type = 0x1d,
    DW_AT_default_value = 0x1e,
    DW_AT_inline = 0x20,
    DW_AT_is_optional = 0x21,
    DW_AT_lower_bound = 0x22,
    DW_AT_producer = 0x25,
    DW_AT_prototyped = 0x27,
    DW_AT_return_addr = 0x2a,
    DW_AT_start_scope = 0x2c,
    DW_AT_bit_stride = 0x2e,
    DW_AT_upper_bound = 0x2f,
    DW_AT_abstract_origin = 0x31,
    DW_AT_accessibility = 0x32,
    DW_AT_address_class = 0x33,
    DW_AT_artificial = 0x34,
    DW_AT_base_types = 0x35,
    DW_AT_calling_convention = 0x36,
    DW_AT_count = 0x37,
    DW_AT_data_member_location = 0x38,
    DW_AT_decl_column = 0x39,
    DW_AT_decl_file = 0x3a,
    DW_AT_decl_line = 0x3b,
    DW_AT_declaration = 0x3c,
    DW_AT_discr_list = 0x3d,
    DW_AT_encoding = 0x3e,
    DW_AT_external = 0x3f,
    DW_AT_frame_base = 0x40,
    DW_AT_friend = 0x41,
    DW_AT_identifier_case = 0x42,
    DW_AT_macro_info = 0x43,
    DW_AT_namelist_item = 0x44,
    DW_AT_priority = 0x45,
    DW_AT_segment = 0x46,
    DW_AT_specification = 0x47,
    DW_AT_static_link = 0x48,
    DW_AT_type = 0x49,
    DW_AT_use_location = 0x4a,
    DW_AT_variable_parameter = 0x4b,
    DW_AT_virtuality = 0x4c,
    DW_AT_vtable_elem_location = 0x4d,
    DW_AT_allocated = 0x4e,
    DW_AT_associated = 0x4f,
    DW_AT_data_location = 0x50,
    DW_AT_byte_stride = 0x51,
    DW_AT_entry_pc = 0x52,
    DW_AT_use_UTF8 = 0x53,
    DW_AT_extension = 0x54,
    DW_AT_ranges = 0x55,
    DW_AT_trampoline = 0x56,
    DW_AT_call_column = 0x57,
    DW_AT_call_file = 0x58,
    DW_AT_call_line = 0x59,
    DW_AT_description = 0x5a,
    DW_AT_binary_scale = 0x5b,
    DW_AT_decimal_scale = 0x5c,
    DW_AT_small = 0x5d,
    DW_AT_decimal_sign = 0x5e,
    DW_AT_digit_count = 0x5f,
    DW_AT_picture_string = 0x60,
    DW_AT_mutable = 0x61,
    DW_AT_threads_scaled = 0x62,
    DW_AT_explicit = 0x63,
    DW_AT_object_pointer = 0x64,
    DW_AT_endianity = 0x65,
    DW_AT_elemental = 0x66,
    DW_AT_pure = 0x67,
    DW_AT_recursive = 0x68,
    DW_AT_signature = 0x69,
    DW_AT_main_subprogram = 0x6a,
    DW_AT_data_bit_offset = 0x6b,
    DW_AT_const_expr = 0x6c,
    DW_AT_enum_class = 0x6d,
    DW_AT_linkage_name = 0x6e,

    /* From DWARF5, but GCC still outputs in DWARF4 mode */
    DW_AT_defaulted = 0x8b,

    DW_AT_lo_user = 0x2000,
    DW_AT_hi_user = 0x3fff,
}

#[derive(Copy, Clone, Debug)]
pub struct AttributeSpec {
    pub attribute: u64,
    form: u64
}

#[derive(Clone, Debug)]
pub struct Abbrev {
    code: NonZeroU64,
    tag: u64,
    pub has_children: bool,
    pub attribute_specs: Vec<AttributeSpec>
}

#[derive(Debug)]
pub struct AbbrevTable {
    entries: HashMap<NonZeroU64, Abbrev>
}

impl AbbrevTable {
    pub fn get_by_code(&self, code: NonZeroU64) -> Option<&Abbrev> {
        self.entries.get(&code)
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize
}

impl <'a> Cursor<'a> {
    fn new(data: &'a[u8]) -> Self {
        Self { data, position: 0 }
    }

    fn set_position(&mut self, position: usize) {
        self.position = position;
    }

    fn is_finished(&self) -> bool {
        self.position >= self.data.len()
    }

    fn fixed_int<T: TryFromBytes, const N: usize>(&mut self) -> T {
        // TODO: check remaining bytes?
        let bytes = &self.data[self.position..self.position + N];
        let v = T::try_from_bytes(bytes).expect("Failed to convert bytes");
        self.position += N;
        v
    }

    fn u8(&mut self) -> u8 { self.fixed_int::<u8, 1>() }
    fn u16(&mut self) -> u16 { self.fixed_int::<u16, 2>() }
    fn u32(&mut self) -> u32 { self.fixed_int::<u32, 4>() }
    fn u64(&mut self) -> u64 { self.fixed_int::<u64, 8>() }
    fn i8(&mut self) -> i8 { self.fixed_int::<i8, 1>() }
    fn i16(&mut self) -> i16 { self.fixed_int::<i16, 2>() }
    fn i32(&mut self) -> i32 { self.fixed_int::<i32, 4>() }
    fn i64(&mut self) -> i64 { self.fixed_int::<i64, 8>() }

    fn string(&mut self) -> String {
        // search for terminating null byte from current position
        let mut end = self.position;
        loop {
            if end < self.data.len() {
                if self.data[end] == 0 {
                    break;
                } else {
                    end += 1;
                }
            } else {
                panic!("Reached end of buffer before locating null terminator");
            }
        }

        let cs = CStr::from_bytes_with_nul(&self.data[self.position..end+1]).expect("Failed to create CStr");
        let s = cs.to_string_lossy().to_string();

        // position cursor past end of string
        self.position = end + 2;

        s
    }

    fn uleb128(&mut self) -> u64 {
        let mut res = 0u64;
        let mut shift = 0;

        loop {
            let b = self.u8();

            // mask high bit to obtain 7-bit value and move into position within result
            let masked = b & 0x7F;
            res |= (masked as u64) << shift;

            // update shift for next byte if required
            shift += 7;

            // if hi bit is set, value continues to next byte otherwise this is the msb
            if (b & 0x80) == 0 {
                break;
            }
        }

        res
    }

    fn sleb128(&mut self) -> i64 {
        let mut res = 0u64;
        let mut shift = 0;
        let mut b = 0;

        loop {
            b = self.u8();

            // mask high bit to obtain 7-bit value and move into position within result
            let masked = b & 0x7F;
            res |= (masked as u64) << shift;
            shift += 7;

            // if hi bit is set, value continues to next byte otherwise this is msb
            if b & 0x80 == 0 {
                break;
            }
        }

        // see if result should be negative
        // negative if:
        //  * the result hasn't been filled (i.e. shift is less than 64 bits)
        //  * last byte has second most significant bit set
        if shift < size_of::<u64>() * 8 && b & 0x40 > 0 {
            // create mask of 1s and shift out bits already set in result
            let mask = !0u64 << shift;

            // set upper bits to 1 using mask
            res |= mask;
        }

        unsafe { mem::transmute(res) }
    }

    fn bytes(&mut self, len: usize) -> &'a [u8] {
        // TODO: error if len too large!
        let bytes = &self.data[self.position..self.position + len];
        self.position += len;
        bytes
    }

    fn skip_form(&mut self, form: DwarfForm) {
        use DwarfForm::*;

        match form {
            DW_FORM_flag_present => {
                // NOTE: attribute indicates presence so value uses no space
            },
            DW_FORM_data1 | DW_FORM_ref1 | DW_FORM_flag => {
                self.position += 1;
            },
            DW_FORM_data2 | DW_FORM_ref2 => {
                self.position += 2
            },
            DW_FORM_data4 | DW_FORM_ref4 | DW_FORM_ref_addr | DW_FORM_sec_offset | DW_FORM_strp => {
                self.position += 4
            },
            DW_FORM_data8 | DW_FORM_addr => {
                // WARNING: DW_FORM_addr depends on system address size!
                // we only support 64-bit so far
                self.position += 8
            },
            DW_FORM_sdata => {
                self.sleb128();
            },
            DW_FORM_udata | DW_FORM_ref_udata => {
                self.uleb128();
            },
            DW_FORM_block1 => {
                let len = self.u8();
                self.position += len as usize;
            },
            DW_FORM_block2 => {
                let len = self.u16();
                self.position += len as usize;
            },
            DW_FORM_block4 => {
                let len = self.u32();
                self.position += len as usize;
            },
            DW_FORM_block | DW_FORM_exprloc => {
                let len = self.uleb128();
                self.position += len as usize;
            },
            DW_FORM_string => {
                // search for terminating 0 byte
                while !self.is_finished() && self.data[self.position] != 0 {
                    self.position += 1;
                }

                // skip past null terminator
                self.position += 1;
            },
            DW_FORM_indirect => {
                // indirect form
                let raw_form = self.uleb128();
                let form = DwarfForm::from_repr(raw_form).expect("Invalid DWARF form value");
                self.skip_form(form);
            },
            DW_FORM_ref8 | DW_FORM_ref_sig8 => {
                // NOTE: not supported in the book!
                panic!("DW_FORM_ref8 and DW_FORM_ref_sig8 forms not supported");
                self.position += 8;
            }
        }
    }
}

impl <'a> AddAssign<usize> for Cursor<'a> {
    fn add_assign(&mut self, rhs: usize) {
        self.position += rhs
    }
}

#[derive(Clone, Debug)]
pub struct Attribute {
    attr_type: u64,
    pub attr_form: DwarfForm,
    attr_location: usize
    // TODO: add compile unit offset member?
}

impl Attribute {
    fn compile_unit_data_cursor<'a, 'b>(compile_unit: &'b CompileUnit, dwarf: &'a Dwarf) -> Cursor<'a> {
        let debug_info_data = dwarf.debug_info_data();
        let cu_bytes = &debug_info_data[compile_unit.header.offset..];
        // cu data starts after compile unit header
        Cursor::new(&cu_bytes[CompileUnitHeader::LEN_BYTES..])
    }

    pub fn as_address(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<FileAddress, Error> {
        match self.attr_form {
            DwarfForm::DW_FORM_addr => {
                //let mut cursor = Cursor::new(self.compile_unit.data);
                let mut cursor = Self::compile_unit_data_cursor(compile_unit, dwarf);
                cursor.set_position(self.attr_location);
                let addr = cursor.u64();
                let file_addr = FileAddress::new(dwarf.elf.clone(), addr as usize);
                Ok(file_addr)
            },
            _ => Err(Error::from_message(String::from("Invalid address type")))
        }
    }

    pub fn as_section_offset(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<u32, Error> {
        match self.attr_form {
            DwarfForm::DW_FORM_sec_offset => {
                let mut cursor = Self::compile_unit_data_cursor(compile_unit, dwarf);
                cursor.set_position(self.attr_location);
                let offset = cursor.u32();
                Ok(offset)
            },
            _ => Err(Error::from_message(String::from("Invalid offset type")))
        }
    }

    pub fn as_int(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<u64, Error> {
        let mut cursor = Self::compile_unit_data_cursor(compile_unit, dwarf);
        cursor.set_position(self.attr_location);

        match self.attr_form {
            DwarfForm::DW_FORM_data1 => Ok(cursor.u8() as u64),
            DwarfForm::DW_FORM_data2 => Ok(cursor.u16() as u64),
            DwarfForm::DW_FORM_data4 => Ok(cursor.u32() as u64),
            DwarfForm::DW_FORM_data8 => Ok(cursor.u64()),
            DwarfForm::DW_FORM_udata => Ok(cursor.uleb128()),
            _ => Err(Error::from_message(String::from("Invalid integer type")))
        }
    }

    pub fn as_block(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<Vec<u8>, Error> {
        let mut cursor = Self::compile_unit_data_cursor(compile_unit, dwarf);
        cursor.set_position(self.attr_location);

        let size = match self.attr_form {
            DwarfForm::DW_FORM_block1 => cursor.u8() as usize,
            DwarfForm::DW_FORM_block2 => cursor.u16() as usize,
            DwarfForm::DW_FORM_block4 => cursor.u32() as usize,
            DwarfForm::DW_FORM_block => cursor.uleb128() as usize,
            _ => return Err(Error::from_message(String::from("Invalid block type")))
        };

        // TODO: can return slice?
        Ok(cursor.bytes(size).to_vec())
    }

    pub fn as_reference(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<DIEEntry, Error> {
        let mut cursor = Self::compile_unit_data_cursor(compile_unit, dwarf);
        cursor.set_position(self.attr_location);

        let offset = match self.attr_form {
            DwarfForm::DW_FORM_ref1 => cursor.u8() as usize,
            DwarfForm::DW_FORM_ref2 => cursor.u16() as usize,
            DwarfForm::DW_FORM_ref4 => cursor.u32() as usize,
            DwarfForm::DW_FORM_ref8 => cursor.u64() as usize,
            DwarfForm::DW_FORM_udata => cursor.uleb128() as usize,
            DwarfForm::DW_FORM_ref_addr => {
                // WARNING: offset is stored in this compile unit's data but the offset itself is from
                // the start of the .debug_info section data
                let offset = cursor.u32() as usize;
                let section = dwarf.debug_info_data();
                let mut cursor = Cursor::new(section);
                cursor.set_position(offset);

                // find compile unit containing offset
                // TODO: add start/end offsets to CompileUnit!
                let compile_unit = dwarf.get_compile_units().iter().find(|cu| cu.contains_offset(offset)).expect(&format!("Failed to find compile unit at offset {}", offset));
                let die_entry = compile_unit.parse_die_entry(&mut cursor, dwarf);

                return Ok(die_entry);
            },
            other => return Err(Error::from_message(format!("Invalid reference type: {:#?}", other)))
        };

        // NOTE: if we end up here the offset is an offset into the compile unit data
        // create a new cursor starting at the start of the compile unit data
        let mut cursor = {
            let debug_info_data = dwarf.debug_info_data();
            Cursor::new(&debug_info_data[compile_unit.header.offset..])
        };
        cursor.set_position(offset);

        let die_entry = compile_unit.parse_die_entry(&mut cursor, dwarf);
        Ok(die_entry)
    }

    pub fn as_string(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<String, Error> {
        let mut cursor = Self::compile_unit_data_cursor(compile_unit, dwarf);
        cursor.set_position(self.attr_location);

        match self.attr_form {
            DwarfForm::DW_FORM_string => {
                let s = cursor.string();
                Ok(s)
            },
            DwarfForm::DW_FORM_strp => {
                let offset = cursor.u32() as usize;
                let str_table = dwarf.debug_str_data();
                let mut cursor = Cursor::new(str_table);
                cursor.set_position(offset);
                let s = cursor.string();
                Ok(s)
            },
            other => Err(Error::from_message(format!("Invalid string type {:#?}", other)))
        }
    }
}

#[derive(Clone, Debug)]
pub struct DIE {
    position: usize,
    next: usize,
    pub abbrev_code: NonZeroU64,
    attribute_locations: Vec<usize>
}

impl DIE {
    // fn contains(&self, compile_unit: &CompileUnit, attribute: u64) -> bool {
    //     let abbrev = compile_unit.get_abbrev_table().get_by_code(self.abbrev_code).expect("Failed to get abbrev");
    //     abbrev.attribute_specs.iter().find(|spec| spec.attribute == attribute).is_some()
    // }

    pub fn get_attribute(&self, abbrev: &Abbrev, attribute: u64) -> Option<Attribute> {
        for attr_index in 0..abbrev.attribute_specs.len() {
            let attr_spec = &abbrev.attribute_specs[attr_index];
            if attr_spec.attribute == attribute {
                let attr = Attribute {
                    attr_type: attr_spec.attribute,
                    attr_form: DwarfForm::from_repr(attr_spec.form).expect("Failed to convert DWARF form"),
                    attr_location: self.attribute_locations[attr_index]
                };
                return Some(attr)
            }
        }

        // attribute not found
        None
    }
}

#[derive(Clone, Debug)]
pub enum DIEEntry {
    Null(usize),
    Entry(DIE)
}

#[derive(Clone, Debug)]
pub struct CompileUnitHeader {
    // offset of the start of the compile unit within the .debug_info section
    offset: usize,
    size: u32,
    version: u16,
    abbrev_offset: usize,
    address_size: u8,
}

impl CompileUnitHeader {
    const LEN_BYTES: usize = 4 + 2 + 4 + 1;

    fn parse(cursor: &mut Cursor) -> Result<Self, Error> {
        let offset = cursor.position;
        let size = cursor.u32();
        let version = cursor.u16();
        let abbrev_offset = cursor.u32() as usize;
        let address_size = cursor.u8();

        if size == 0xFFFFFFFF {
            return Err(Error::from_message("Only DWARF32 is supported".to_string()));
        }

        if version != 4 {
            return Err(Error::from_message("Invalid address size for DWARF".to_string()));
        }

        if address_size != 8 {
            return Err(Error::from_message("Only DWARF version 4 is supported".to_string()));
        }

        let header = Self {
            offset, size, version, abbrev_offset, address_size
        };
        Ok(header)
    }

    // get the total size of this compile unit in bytes
    fn compile_unit_len(&self) -> u32 {
        // NOTE: size field contains the size of the compile unit header + data, excluding the size of the size field itself
        // add this back in to the compile unit size
        self.size + size_of::<u32>() as u32
    }

    fn data_len(&self) -> usize {
        self.compile_unit_len() as usize - Self::LEN_BYTES
    }

    // get start offset for data within the .debug_info section
    fn data_offset(&self) -> usize {
        self.offset + Self::LEN_BYTES as usize
    }
}

#[derive(Clone, Debug)]
pub struct CompileUnit {
    header: CompileUnitHeader,
    //parent: &'a Dwarf,
    //data: &'a [u8],

    // offset of the abbrev definition of this compile unit within the .debug_abbrev section
    //abbrev_offset: usize
}

impl CompileUnit {
    fn new(header: CompileUnitHeader) -> Self {
        Self { header }
    }

    fn contains_offset(&self, offset: usize) -> bool {
        // TODO: check this accounts for header size weirdness!
        let end = self.header.offset + self.header.size as usize;
        offset >= self.header.offset && offset < end
    }

    fn parse_die_entry(&self, cursor: &mut Cursor, dwarf: &Dwarf) -> DIEEntry {
        let position = cursor.position;
        let abbrev_code = cursor.uleb128();

        match NonZeroU64::new(abbrev_code) {
            None => {
                // null DIE
                // next DIE is at current cursor position
                DIEEntry::Null(cursor.position)
            },
            Some(abbrev_code) => {
                // get abbreviation table for compile unit
                // and lookup abbrev by code
                let abbrev = dwarf.get_compile_unit_abbrev_table(self).get_by_code(abbrev_code).expect("Failed to find abbreviation code");

                let mut attribute_locations = Vec::with_capacity(abbrev.attribute_specs.len());
                for attr in abbrev.attribute_specs.iter() {
                    attribute_locations.push(cursor.position);
                    // TODO: parse on construction!
                    let form = DwarfForm::from_repr(attr.form).expect("Invalid dwarf form");
                    cursor.skip_form(form)
                }

                // next DIE should be at current cursor position
                let next = cursor.position;
                let die = DIE { position, next, attribute_locations, abbrev_code };
                DIEEntry::Entry(die)
            }
        }
    }

    pub fn get_root(&self, dwarf: &Dwarf) -> DIEEntry {
        // NOTE: data contains entire compile unit data including the 11-byte header
        // create cursor for unit DIE data
        let debug_info = dwarf.debug_info_data();
        let cu_data = &debug_info[self.header.offset..];

        // skip over header and create cursor at start of DIE data
        let mut cursor = Cursor::new(&cu_data[CompileUnitHeader::LEN_BYTES..]);
        self.parse_die_entry(&mut cursor, dwarf)
    }

    fn children_of(&self, dwarf: &mut Dwarf, die: &DIE) -> DIEChildIterator {
        // let parent_abbrev = self.get_abbrev_table(dwarf).get_by_code(die.abbrev_code).expect("Failed to get parent abbrev");
        // DIEChildIterator {
        //     compile_unit: self,
        //     state: ChildIteratorState::Parent(die.next, parent_abbrev.clone()),
        //     cursor: Cursor::new(self.data)
        // }
        unimplemented!()
    }
}

enum ChildIteratorState {
    Parent(usize, Abbrev),
    Sibling(DIE, Abbrev),
    Finished
}

struct DIEChildIterator<'a> {
    compile_unit: &'a CompileUnit,
    state: ChildIteratorState,
    cursor: Cursor<'a>,
}

impl <'a> Iterator for DIEChildIterator<'a> {
    type Item = DIE;
    fn next(&mut self) -> Option<Self::Item> {
        unimplemented!()
        // match self.state {
        //     ChildIteratorState::Parent(next_pos, ref parent_abbrev) => {
        //         self.cursor.set_position(next_pos);
        //
        //         if parent_abbrev.has_children {
        //             // next item is the first child of the parent
        //             let child_die_entry = self.compile_unit.parse_die_entry(&mut self.cursor);
        //
        //             match child_die_entry {
        //                 DIEEntry::Null(sibling_pos) => {
        //                     // parent can have children but has none
        //                     // next DIE entry is therefore sibling of the parent
        //                     // set cursor position to point to next item
        //                     self.cursor.set_position(sibling_pos);
        //                     self.state = ChildIteratorState::Finished;
        //                     None
        //                 },
        //                 DIEEntry::Entry(entry) => {
        //                     // first child
        //                     let sibling_abbrev = self.compile_unit.get_abbrev_table().get_by_code(entry.abbrev_code).expect("Failed to get sibling abbrev");
        //                     self.state = ChildIteratorState::Sibling(entry.clone(), sibling_abbrev.clone());
        //                     Some(entry)
        //                 }
        //             }
        //         } else {
        //             // parent has no children
        //             self.state = ChildIteratorState::Finished;
        //             None
        //         }
        //     },
        //     ChildIteratorState::Sibling(sibling,ref sibling_abbrev) => {
        //         if sibling_abbrev.has_children {
        //             // see if the sibling has a DW_AT_sibling attribute
        //             // if it does this should be a reference to the sibling
        //             match sibling.get_attribute(self.compile_unit, DwarfAttribute::DW_AT_sibling) {
        //                 Some(sibling_at_attr) => {
        //                     let sibling_entry = sibling_at_attr.as_reference().expect("Failed to parse sibling entry");
        //                     match sibling_entry {
        //                         DIEEntry::Null(next) => {
        //                             self.cursor.set_position(next);
        //                             self.state = ChildIteratorState::Finished;
        //                             None
        //                         },
        //                         DIEEntry::Entry(sibling) => {
        //                             let sibling_abbrev = self.compile_unit.get_abbrev_table().get_by_code(sibling.abbrev_code).expect("Failed to get sibling abbrev");
        //                             self.cursor.set_position(sibling.next);
        //                             self.state = ChildIteratorState::Sibling(sibling.clone(), sibling_abbrev.clone());
        //                             Some(sibling)
        //                         }
        //                     }
        //                 },
        //                 None => {
        //                     // create iterator for sibling's children and skip over them to find next sibling
        //                     let mut nephew_iter = DIEChildIterator { compile_unit: self.compile_unit, cursor: self.cursor.clone(), state: ChildIteratorState::Parent(sibling_next_pos, sibling_abbrev.clone()) };
        //                     for _ in nephew_iter {
        //                     }
        //
        //                     // child iterator position points to next sibling
        //                     self.cursor.set_position(nephew_iter.cursor.position);
        //
        //                     // parse next sibling
        //                     let sibling_entry = CompileUnit::parse_die_entry(&mut self.cursor);
        //                     match sibling_entry {
        //                         DIEEntry::Null(next_pos) => {
        //                             // NOTE: cursor should already be at this position
        //                             self.cursor.set_position(next_pos);
        //                             self.state = ChildIteratorState::Finished;
        //                             None
        //                         },
        //                         DIEEntry::Entry(sibling) => {
        //                             let sibling_abbrev = self.compile_unit.get_abbrev_table().get_by_code(sibling.abbrev_code).expect("Failed to get sibling abbrev");
        //                             self.state = ChildIteratorState::Sibling(sibling.next, sibling_abbrev.clone());
        //                             Some(sibling)
        //                         }
        //                     }
        //                 }
        //             }
        //         } else {
        //             // NOTE: cursor should already be at this position
        //             self.cursor.set_position(sibling_next_pos);
        //             let sibling = self.compile_unit.parse_die_entry(&mut self.cursor);
        //
        //             match sibling {
        //                 DIEEntry::Null(sibling_next) => {
        //                     // no more children
        //                     // move cursor to point to next DIE entry
        //                     self.cursor.position = sibling_next;
        //                     self.state = ChildIteratorState::Finished;
        //                     None
        //                 },
        //                 DIEEntry::Entry(sibling) => {
        //                     let sibling_abbrev = self.compile_unit.get_abbrev_table().get_by_code(sibling.abbrev_code).expect("Failed to get sibling abbrev");
        //                     self.state = ChildIteratorState::Sibling(sibling.next, sibling_abbrev.clone());
        //                     Some(sibling)
        //                 }
        //             }
        //         }
        //     },
        //     ChildIteratorState::Finished => {
        //         None
        //     }
        // }
    }
}

pub struct DIEEntryIterator<'a> {
    compile_unit: CompileUnit,
    current: DIEEntry,
    dwarf: &'a Dwarf,
    done: bool,
}

impl <'a> DIEEntryIterator<'a> {
    pub fn for_compile_unit(compile_unit: CompileUnit, dwarf: &'a Dwarf) -> Self {
        let root = compile_unit.get_root(&dwarf);

        Self {
            compile_unit,
            current: root,
            dwarf,
            done: false,
        }
    }
}

impl <'a> Iterator for DIEEntryIterator<'a> {
    type Item = DIEEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done { return None; }
        let debug_info = self.dwarf.debug_info_data();

        // create cursor at start of compile unit data
        // NOTE: this is because CompileUnit::get_root creates the cursor
        // here instead of at the start of the .debug_info data so all positions
        // are relative to there instead of the start of .debug_info
        let mut cursor = Cursor::new(&debug_info[CompileUnitHeader::LEN_BYTES..]);

        let offset = match &self.current {
            DIEEntry::Null(offset) => {
                // TODO: need to track depth so we know when done?
                // move cursor to offset
                *offset
            },
            DIEEntry::Entry(die) => {
                // move cursor to next offset
                die.next
            }
        };
        cursor.set_position(offset);

        if cursor.is_finished() {
            self.done = true;
            return None;
        }

        let next = self.compile_unit.parse_die_entry(&mut cursor, &self.dwarf);
        let ret = mem::replace(&mut self.current, next);

        Some(ret)
    }
}

pub struct Dwarf {
    elf: Rc<Elf>,

    // compile units within the ELF file
    compile_units: Vec<CompileUnit>,

    // keys are offsets within the .debug_abbrev section
    abbrev_tables: HashMap<usize, AbbrevTable>,
}

impl Dwarf {
    pub fn new(elf: Rc<Elf>) -> Result<Self, Error> {
        let compile_units = Self::parse_compile_units(elf.as_ref())?;
        let abbrev_tables = Self::parse_abbrev_tables(&elf, compile_units.as_ref());
        Ok(Self { elf, compile_units, abbrev_tables })
    }

    fn parse_abbrev_tables(elf: &Elf, compile_units: &[CompileUnit]) -> HashMap<usize, AbbrevTable> {
        let mut abbrev_tables = HashMap::new();
        for compile_unit in compile_units.iter() {
            let table = Self::parse_abbrev_table(elf, compile_unit.header.offset);
            abbrev_tables.insert(compile_unit.header.offset, table);
        }
        abbrev_tables
    }

    pub fn get_compile_units(&self) -> &[CompileUnit] {
        self.compile_units.as_slice()
    }

    pub fn get_compile_unit_abbrev_table(&self, compile_unit: &CompileUnit) -> &AbbrevTable {
        self.get_abbrev_table(compile_unit.header.abbrev_offset)
    }

    fn parse_abbrev_table(elf: &Elf, offset: usize) -> AbbrevTable {
        let section = elf.get_section_contents(".debug_abbrev").expect("Failed to get .debug_abbrev section");
        let mut cursor = Cursor::new(section);
        cursor.set_position(offset);

        let mut entries = HashMap::new();
        loop {
            // NOTE: The book doesn't break immediately on reading a code of 0
            // yet apparently works somehow.
            let code_raw = cursor.uleb128();
            match NonZeroU64::new(code_raw) {
                None => break,
                Some(code) => {
                    let tag = cursor.uleb128();
                    let has_children = {
                        let flag = cursor.u8();
                        flag != 0
                    };

                    // parse attr specs
                    let mut attribute_specs = Vec::new();
                    loop {
                        let attribute = cursor.uleb128();
                        let form = cursor.uleb128();

                        if attribute == 0 {
                            break;
                        } else {
                            attribute_specs.push(AttributeSpec { attribute, form })
                        }
                    }

                    let abbrev = Abbrev { code, tag, has_children, attribute_specs };
                    entries.insert(code, abbrev);
                }
            }
        }

        AbbrevTable { entries }
    }

    fn get_abbrev_table(&self, offset: usize) -> &AbbrevTable {
        self.abbrev_tables.get(&offset).expect("No abbrev table at offset")
    }

    fn parse_compile_unit(cursor: &mut Cursor) -> Result<CompileUnit, Error> {
        let pos = cursor.position;
        let header = CompileUnitHeader::parse(cursor)?;

        // skip over compile unit data
        cursor.set_position(pos + header.compile_unit_len() as usize);

        Ok(CompileUnit { header })
    }

    fn parse_compile_units(elf: &Elf) -> Result<Vec<CompileUnit>, Error> {
        let debug_info = elf.get_section_contents(".debug_info").expect("Failed to get .debug_info section");
        let mut cursor = Cursor::new(debug_info);

        let mut units = Vec::new();

        while !cursor.is_finished() {
            let compile_unit = Self::parse_compile_unit(&mut cursor)?;

            units.push(compile_unit);
        }

        Ok(units)
    }

    fn debug_info_data(&self) -> &[u8] {
        self.expected_section_data(".debug_info")
    }

    fn debug_str_data(&self) -> &[u8] {
        self.expected_section_data(".debug_str")
    }

    fn expected_section_data(&self, section_name: &str) -> &[u8] {
        self.elf.get_section_contents(section_name).expect(&format!("Failed to get {} section", section_name))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_abbrev_table_test() {
        let elf = Elf::open("target/debug/hello_rsdb").expect("Failed to open ELF file");
        let dwarf = Dwarf::new(elf).expect("Failed to parse DWARF");
        for cu in dwarf.get_compile_units() {
            println!("{:?}", cu);

            let abbrev_table = dwarf.get_compile_unit_abbrev_table(&cu);
            println!("Abbrev table:");
            println!("{:?}", abbrev_table)
        }
    }

    #[test]
    fn parse_die_test() {
        let elf = Elf::open("target/debug/hello_rsdb").expect("Failed to open ELF file");
        let dwarf = Dwarf::new(elf).expect("Failed to parse DWARF");
        let cu = &dwarf.get_compile_units()[0];

        let mut it = DIEEntryIterator::for_compile_unit(cu.clone(), &dwarf);
        let d1 = it.next();
        let d2 = it.next();
        let d3 = it.next();
    }
}