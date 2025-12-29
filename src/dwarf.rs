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
use crate::multimap::UnorderedMultiMap;

#[allow(non_camel_case_types)]
#[repr(u64)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
pub enum DwarfTag {
    DW_TAG_array_type = 0x01,
    DW_TAG_class_type = 0x02,
    DW_TAG_entry_point = 0x03,
    DW_TAG_enumeration_type = 0x04,
    DW_TAG_formal_parameter = 0x05,
    DW_TAG_imported_declaration = 0x08,
    DW_TAG_label = 0x0a,
    DW_TAG_lexical_block = 0x0b,
    DW_TAG_member = 0x0d,
    DW_TAG_pointer_type = 0x0f,
    DW_TAG_reference_type = 0x10,
    DW_TAG_compile_unit = 0x11,
    DW_TAG_string_type = 0x12,
    DW_TAG_structure_type = 0x13,
    DW_TAG_subroutine_type = 0x15,
    DW_TAG_typedef = 0x16,
    DW_TAG_union_type = 0x17,
    DW_TAG_unspecified_parameters = 0x18,
    DW_TAG_variant = 0x19,
    DW_TAG_common_block = 0x1a,
    DW_TAG_common_inclusion = 0x1b,
    DW_TAG_inheritance = 0x1c,
    DW_TAG_inlined_subroutine = 0x1d,
    DW_TAG_module = 0x1e,
    DW_TAG_ptr_to_member_type = 0x1f,
    DW_TAG_set_type = 0x20,
    DW_TAG_subrange_type = 0x21,
    DW_TAG_with_stmt = 0x22,
    DW_TAG_access_declaration = 0x23,
    DW_TAG_base_type = 0x24,
    DW_TAG_catch_block = 0x25,
    DW_TAG_const_type = 0x26,
    DW_TAG_constant = 0x27,
    DW_TAG_enumerator = 0x28,
    DW_TAG_file_type = 0x29,
    DW_TAG_friend = 0x2a,
    DW_TAG_namelist = 0x2b,
    DW_TAG_namelist_item = 0x2c,
    DW_TAG_packed_type = 0x2d,
    DW_TAG_subprogram = 0x2e,
    DW_TAG_template_type_parameter = 0x2f,
    DW_TAG_template_value_parameter = 0x30,
    DW_TAG_thrown_type = 0x31,
    DW_TAG_try_block = 0x32,
    DW_TAG_variant_part = 0x33,
    DW_TAG_variable = 0x34,
    DW_TAG_volatile_type = 0x35,
    DW_TAG_dwarf_procedure = 0x36,
    DW_TAG_restrict_type = 0x37,
    DW_TAG_interface_type = 0x38,
    DW_TAG_namespace = 0x39,
    DW_TAG_imported_module = 0x3a,
    DW_TAG_unspecified_type = 0x3b,
    DW_TAG_partial_unit = 0x3c,
    DW_TAG_imported_unit = 0x3d,
    DW_TAG_condition = 0x3f,
    DW_TAG_shared_type = 0x40,
    DW_TAG_type_unit = 0x41,
    DW_TAG_rvalue_reference_type = 0x42,
    DW_TAG_template_alias = 0x43,
    DW_TAG_lo_user = 0x4080,
    DW_TAG_hi_user = 0xffff,
}

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

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
pub enum DwarfLang {
    DW_LANG_C89 = 0x0001,
    DW_LANG_C = 0x0002,
    DW_LANG_Ada83 = 0x0003,
    DW_LANG_C_plus_plus = 0x0004,
    DW_LANG_Cobol74 = 0x0005,
    DW_LANG_Cobol85 = 0x0006,
    DW_LANG_Fortran77 = 0x0007,
    DW_LANG_Fortran90 = 0x0008,
    DW_LANG_Pascal83 = 0x0009,
    DW_LANG_Modula2 = 0x000a,
    DW_LANG_Java = 0x000b,
    DW_LANG_C99 = 0x000c,
    DW_LANG_Ada95 = 0x000d,
    DW_LANG_Fortran95 = 0x000e,
    DW_LANG_PLI = 0x000f,
    DW_LANG_ObjC = 0x0010,
    DW_LANG_ObjC_plus_plus = 0x0011,
    DW_LANG_UPC = 0x0012,
    DW_LANG_D = 0x0013,
    DW_LANG_Python = 0x0014,
    DW_LANG_lo_user = 0x8000,
    DW_LANG_hi_user = 0xffff,
}

#[derive(Copy, Clone, Debug)]
pub struct AttributeSpec {
    pub attribute: u64,
    form: DwarfForm,
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

pub struct RangeListEntry {
    pub low: FileAddress,
    pub high: FileAddress,
}

impl RangeListEntry {
    pub fn contains(&self, addr: &FileAddress) -> bool {
        addr >= &self.low && addr < &self.high
    }
}

pub struct RangeListIterator<'a> {
    dwarf: &'a Dwarf,
    cursor: Cursor<'a>,
    base_address: Option<FileAddress>,
}

impl <'a> RangeListIterator<'a> {
    const BASE_ADDRESS_FLAG: u64 = 0xffffffffffffffff;
}

impl <'a> Iterator for RangeListIterator<'a> {
    type Item = RangeListEntry;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.cursor.is_finished() {
                return None;
            }

            let low = self.cursor.u64();
            let hi = self.cursor.u64();

            // list is terminated by a pair of 0 entries
            if low == 0 && hi == 0 {
                return None;
            } else if low == Self::BASE_ADDRESS_FLAG {
                // if low is set to the base address flag then hi is the new base address
                self.base_address = Some(FileAddress::new(Rc::clone(&self.dwarf.elf), hi as usize));
            } else {
                match self.base_address {
                    None => {
                        // no base address yet found
                        // hi and low are absolute addresses
                        let low_addr = FileAddress::new(Rc::clone(&self.dwarf.elf), low as usize);
                        let high_addr = FileAddress::new(Rc::clone(&self.dwarf.elf), hi as usize);

                        return Some(RangeListEntry { low: low_addr, high: high_addr });
                    },
                    Some(ref base_addr) => {
                        let low_addr = base_addr.clone() + low as isize;
                        let high_addr = base_addr.clone() + hi as isize;
                        return Some(RangeListEntry {
                            low: low_addr,
                            high: high_addr,
                        })
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Attribute {
    attr_type: u64,
    pub attr_form: DwarfForm,

    // offset of this attribute value within the .debug_info section
    attr_location: usize
}

impl Attribute {
    fn data_cursor<'a>(&self, dwarf: &'a Dwarf) -> Cursor<'a> {
        let mut cursor = dwarf.debug_info_cursor();
        cursor.set_position(self.attr_location);
        cursor
    }

    pub fn as_address(&self, dwarf: &Dwarf) -> Result<FileAddress, Error> {
        match self.attr_form {
            DwarfForm::DW_FORM_addr => {
                let mut cursor = self.data_cursor(dwarf);
                let addr = cursor.u64();
                let file_addr = FileAddress::new(dwarf.elf.clone(), addr as usize);
                Ok(file_addr)
            },
            _ => Err(Error::from_message(String::from("Invalid address type")))
        }
    }

    pub fn as_section_offset(&self, dwarf: &Dwarf) -> Result<u32, Error> {
        match self.attr_form {
            DwarfForm::DW_FORM_sec_offset => {
                let mut cursor = self.data_cursor(dwarf);
                let offset = cursor.u32();
                Ok(offset)
            },
            _ => Err(Error::from_message(String::from("Invalid offset type")))
        }
    }

    pub fn as_int(&self, dwarf: &Dwarf) -> Result<u64, Error> {
        let mut cursor = self.data_cursor(dwarf);

        match self.attr_form {
            DwarfForm::DW_FORM_data1 => Ok(cursor.u8() as u64),
            DwarfForm::DW_FORM_data2 => Ok(cursor.u16() as u64),
            DwarfForm::DW_FORM_data4 => Ok(cursor.u32() as u64),
            DwarfForm::DW_FORM_data8 => Ok(cursor.u64()),
            DwarfForm::DW_FORM_udata => Ok(cursor.uleb128()),
            _ => Err(Error::from_message(String::from("Invalid integer type")))
        }
    }

    pub fn as_block(&self, dwarf: &Dwarf) -> Result<Vec<u8>, Error> {
        let mut cursor = self.data_cursor(dwarf);

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
        let mut cursor = self.data_cursor(dwarf);

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
                let compile_unit = dwarf.get_compile_units().find(|cu| cu.contains_offset(offset)).expect(&format!("Failed to find compile unit at offset {}", offset));
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

    pub fn as_string(&self, dwarf: &Dwarf) -> Result<String, Error> {
        let mut cursor = self.data_cursor(dwarf);

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

    pub fn as_range_list<'a>(&self, compile_unit: &'a CompileUnit, abbrev: &'a Abbrev, dwarf: &'a Dwarf) -> Result<RangeListIterator<'a>, Error> {
        let offset = self.as_section_offset(&dwarf)?;

        // get root DIE of compile unit for this attribute
        // if it contains a low_pc attribute, use that as the initial base address
        let root_die = compile_unit.get_root(dwarf);
        let cu_low_addr = match root_die {
            DIEEntry::Entry(die) => {
                die.low_pc(compile_unit, dwarf).ok()
            },
            DIEEntry::Null(_) => None,
        };

        let debug_ranges_data = dwarf.debug_ranges_data();
        let mut cursor = Cursor::new(debug_ranges_data);
        cursor.set_position(offset as usize);

        let it = RangeListIterator {
            dwarf,
            cursor,
            base_address: cu_low_addr,
        };

        Ok(it)
    }
}

#[derive(Clone, Debug)]
pub struct DIE {
    // id of the compile unit this DIE belongs to
    compile_unit_id: CompileUnitId,

    // location of this DIE within .debug_info
    position: usize,

    // location of the next DIE within .debug_info
    next: usize,

    // code for the abbrev definition for this DIE
    pub abbrev_code: NonZeroU64,

    // offsets of the attributes of this DIE within .debug_info
    // the attributes definition are stored within the corresponding index in the abbrev
    attribute_locations: Vec<usize>
}

impl DIE {
    // TODO: add identifier for parent compile unit to DIE
    fn get_abbrev<'a>(&self, dwarf: &'a Dwarf) -> &'a Abbrev {
        dwarf.get_compile_unit_abbrev_table(self.compile_unit_id).get_by_code(self.abbrev_code).expect("Failed to find abbrev")
    }

    fn get_compile_unit<'a>(&self, dwarf: &'a Dwarf) -> &'a CompileUnit {
        // TODO: add lookup to Dwarf type by offset
        dwarf.get_compile_units().find(|cu| cu.contains_offset(self.position))
            .expect(&format!("Failed to find compile unit at offset {}", self.position))
    }

    pub fn name(&self, dwarf: &Dwarf) -> Option<String> {
        let compile_unit = self.get_compile_unit(dwarf);
        let abbrev = self.get_abbrev(dwarf);

        if let Some(name_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_name as u64) {
            // DIE contains name attribute
            name_attr.as_string(dwarf).ok()
        } else if let Some(spec_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_specification as u64) {
            // 'out-of-line' definition i.e. functions declared in one place (e.g. a header file) and implemented
            // in another
            let spec = spec_attr.as_reference(compile_unit, dwarf).expect("Failed to get spec DIE");
            match spec {
                DIEEntry::Null(_) => None,
                DIEEntry::Entry(spec_die) => {
                    spec_die.name(dwarf)
                }
            }
        } else if let Some(origin_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_abstract_origin as u64) {
            // inlined function calls which point to their definitions
            let origin = origin_attr.as_reference(compile_unit, dwarf).expect("Failed to get origin DIE");
            match origin {
                DIEEntry::Null(_) => None,
                DIEEntry::Entry(origin_die) => {
                    origin_die.name(dwarf)
                }
            }
        } else {
            // name not found
            None
        }
    }

    pub fn contains_address(&self, compile_unit: &CompileUnit, dwarf: &Dwarf, addr: &FileAddress) -> bool {
        if ! Rc::ptr_eq(addr.elf_ptr(), &dwarf.elf) { return false; }

        let abbrev = self.get_abbrev(dwarf);

        // NOTE: this should go first since the high/low pc methods iterate the range list if one exists
        if let Some(range_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_ranges as u64) {
            let mut range_list = range_attr.as_range_list(compile_unit, abbrev, dwarf).expect("Failed to get range list");
            return range_list.any(|rl| rl.contains(addr));
        }

        if let Some(low_addr_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_low_pc as u64) {
            let low_addr = low_addr_attr.as_address(dwarf).expect("Expected low address");

            // high_pc attribute should always exist?
            if let Some(high_addr_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_high_pc as u64) {
                let high_addr = high_addr_attr.as_address(dwarf).expect("Expected high address");
                return &low_addr <= addr && &high_addr < addr;
            }
        }

        false
    }

    pub fn low_pc(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<FileAddress, Error> {
        let abbrev = self.get_abbrev(dwarf);

        if let Some(range_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_ranges as u64) {
            let mut range_list = range_attr.as_range_list(compile_unit, abbrev, dwarf).expect("Failed to get range list");

            // low address is low address of first entry (which is expected to exist)
            let low_addr = range_list.next().expect("Expected non-empty range list").low;
            return Ok(low_addr)
        }

        let attr = self.get_attribute(abbrev, DwarfAttribute::DW_AT_low_pc as u64)
            .ok_or_else(|| Error::from_message("No low pc attribute found on DIE".to_owned()))?;
        attr.as_address(dwarf)
    }

    pub fn high_pc(&self, compile_unit: &CompileUnit, dwarf: &Dwarf) -> Result<FileAddress, Error> {
        let abbrev = self.get_abbrev(dwarf);

        if let Some(range_attr) = self.get_attribute(abbrev, DwarfAttribute::DW_AT_ranges as u64) {
            let range_list = range_attr.as_range_list(compile_unit, abbrev, dwarf).expect("Failed to get range list");

            // high address is high address of last entry (which should exist)
            let high_addr = range_list.last().expect("Expected non-empty range list").high;
            return Ok(high_addr)
        }

        let attr = self.get_attribute(abbrev, DwarfAttribute::DW_AT_high_pc as u64)
            .ok_or_else(|| Error::from_message("No high pc attribute found on DIE".to_owned()))?;

        if attr.attr_form == DwarfForm::DW_FORM_addr {
            // direct virtual address
            attr.as_address(dwarf)
        } else {
            // offset from low_pc attribute
            // TODO: check int form!
            let offset = attr.as_int(dwarf)? as isize;
            let low_pc = self.low_pc(compile_unit, dwarf)?;
            let high_pc = low_pc + offset;
            Ok(high_pc)
        }
    }

    pub fn get_attribute(&self, abbrev: &Abbrev, attribute: u64) -> Option<Attribute> {
        for attr_index in 0..abbrev.attribute_specs.len() {
            let attr_spec = &abbrev.attribute_specs[attr_index];
            if attr_spec.attribute == attribute {
                let attr = Attribute {
                    attr_type: attr_spec.attribute,
                    attr_form: attr_spec.form,
                    attr_location: self.attribute_locations[attr_index]
                };
                return Some(attr)
            }
        }

        // attribute not found
        None
    }

    pub fn children<'a>(&self, compile_unit: &CompileUnit, dwarf: &'a Dwarf) -> DIEChildIterator<'a> {
        DIEChildIterator {
            dwarf,
            current: self.clone(),
            next_position: self.next,
            state: ChildIteratorState::Parent,
            // TODO: add compile unit id to DIE
            compile_unit_offset: compile_unit.header.offset,
        }
    }
}

#[derive(Clone, Debug)]
pub enum DIEEntry {
    Null(usize),
    Entry(DIE)
}

impl DIEEntry {
    // returns the position of the next DIE entry
    fn next_entry_position(&self) -> usize {
        match self {
            Self::Null(next) => *next,
            Self::Entry(die) => die.next,
        }
    }
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

// identifies a compile unit within a the DWARF data of an ELF file
// contains the offset of the compile unit within the .debug_info section
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CompileUnitId(usize);

#[derive(Clone, Debug)]
pub struct CompileUnit {
    header: CompileUnitHeader,
}

impl CompileUnit {
    fn new(header: CompileUnitHeader) -> Self {
        Self { header }
    }

    pub fn id(&self) -> CompileUnitId {
        CompileUnitId(self.header.offset)
    }

    fn contains_offset(&self, offset: usize) -> bool {
        let end = self.header.offset + self.header.compile_unit_len() as usize;
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
                let abbrev = dwarf.get_compile_unit_abbrev_table(self.id()).get_by_code(abbrev_code).expect("Failed to find abbreviation code");

                let mut attribute_locations = Vec::with_capacity(abbrev.attribute_specs.len());
                for attr in abbrev.attribute_specs.iter() {
                    attribute_locations.push(cursor.position);
                    cursor.skip_form(attr.form)
                }

                // next DIE should be at current cursor position
                let next = cursor.position;
                let die = DIE { compile_unit_id: self.id(), position, next, attribute_locations, abbrev_code };
                DIEEntry::Entry(die)
            }
        }
    }

    pub fn get_root(&self, dwarf: &Dwarf) -> DIEEntry {
        // get cursor and set position to the start of the DIE data for this compile unit
        // data starts immediately after header which has a fixed length
        let mut cursor = dwarf.debug_info_cursor();
        cursor.set_position(self.header.offset + CompileUnitHeader::LEN_BYTES);

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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ChildIteratorState {
    Parent,
    Sibling,
    Finished,
}

pub struct DIEChildIterator<'a> {
    // TODO: create id? Need entire compile unit? use reference?
    compile_unit_offset: usize,

    dwarf: &'a Dwarf,

    // current DIE
    current: DIE,

    // position of next entry
    next_position: usize,

    state: ChildIteratorState,
}

impl <'a> DIEChildIterator<'a> {
    fn current_abbrev(&self) -> &Abbrev {
        self.current.get_abbrev(&self.dwarf)
    }

    fn read_next_entry(&mut self) -> DIEEntry {
        let mut cursor = self.dwarf.debug_info_cursor();
        cursor.set_position(self.current.next);
        let cu = self.dwarf.get_compile_unit(self.compile_unit_offset);
        let entry = cu.parse_die_entry(&mut cursor, &self.dwarf);

        // TODO: move this?
        self.next_position = entry.next_entry_position();

        entry
    }
}

impl <'a> Iterator for DIEChildIterator<'a> {
    type Item = DIE;
    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            ChildIteratorState::Parent => {
                // currently positioned at first child of parent if one exists
                let abbrev = self.current_abbrev();
                if abbrev.has_children {
                    // next item is first child of parent node
                    match self.read_next_entry() {
                        DIEEntry::Null(next_pos) => {
                            // no children
                            self.state = ChildIteratorState::Finished;
                            None
                        },
                        DIEEntry::Entry(child) => {
                            self.state = ChildIteratorState::Sibling;
                            self.current = child.clone();
                            Some(child)
                        }
                    }
                } else {
                    self.state = ChildIteratorState::Finished;
                    None
                }
            },
            ChildIteratorState::Sibling => {
                // current is a child of the original parent DIE
                // if it can have children we need to find the next sibling
                //   * if it contains the AT_sibling attribute, lookup the location of the next
                //     sibling
                //   * otherwise create another child iterator and iterator though all the children
                let abbrev = self.current_abbrev();
                if abbrev.has_children {
                    match self.current.get_attribute(abbrev, DwarfAttribute::DW_AT_sibling as u64) {
                        Some(sibling_attr) => {
                            let cu = self.dwarf.get_compile_unit(self.compile_unit_offset);
                            match sibling_attr.as_reference(cu, &self.dwarf).expect("Failed to read referenced sibling DIE") {
                                DIEEntry::Null(next_pos) => {
                                    // no sibling so end of children
                                    self.next_position = next_pos;
                                    self.state = ChildIteratorState::Finished;
                                    None
                                },
                                DIEEntry::Entry(sibling) => {
                                    // found next sibling
                                    self.next_position = sibling.next;
                                    //self.state = ChildIteratorState::Sibling; no-op
                                    self.current = sibling.clone();
                                    Some(sibling)
                                }
                            }
                        },
                        None => {
                            // iterate children of current node to find next sibling
                            let mut it = DIEChildIterator {
                                dwarf: self.dwarf,
                                compile_unit_offset: self.compile_unit_offset,
                                current: self.current.clone(),
                                state: ChildIteratorState::Parent,
                                next_position: self.current.next,
                            };

                            while let Some(_) = it.next() { }

                            self.next_position = it.next_position;

                            // try read next DIE
                            match self.read_next_entry() {
                                DIEEntry::Null(next_pos) => {
                                    // no more siblings so end of children for original root
                                    //self.next_position = next_pos;
                                    self.state = ChildIteratorState::Finished;
                                    None
                                },
                                DIEEntry::Entry(sibling) => {
                                    //self.position = sibling.next;
                                    // self.state = ChildIteratorState::Sibling; no-op
                                    self.current = sibling.clone();
                                    Some(sibling)
                                }
                            }
                        }
                    }
                } else {
                    // parse next entry
                    match self.read_next_entry() {
                        DIEEntry::Null(next_pos) => {
                            //self.position = next_pos;
                            self.state = ChildIteratorState::Finished;
                            None
                        },
                        DIEEntry::Entry(sibling) => {
                            //self.position = sibling.position;
                            //self.state = ChildIteratorState::Sibling; no-op
                            self.current = sibling.clone();
                            Some(sibling)
                        }
                    }
                }
            },
            ChildIteratorState::Finished => {
                None
            }
        }
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

        let mut cursor = self.dwarf.debug_info_cursor();

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

struct DIEIndexEntry {
    // used to locate DIE compile unit
    compile_unit_offset: usize,

    // offset of the DIE within .debug_info section
    die_offset: usize,
}

pub struct Dwarf {
    elf: Rc<Elf>,

    // compile units within the ELF file
    compile_units: HashMap<CompileUnitId, CompileUnit>,

    // keys are offsets within the .debug_abbrev section
    abbrev_tables: HashMap<usize, AbbrevTable>,

    function_index: UnorderedMultiMap<String, DIEIndexEntry>,
}

impl Dwarf {
    pub fn new(elf: Rc<Elf>) -> Result<Self, Error> {
        let compile_units = Self::parse_compile_units(elf.as_ref())?;
        let abbrev_tables = Self::parse_abbrev_tables(&elf, &compile_units);

        let mut dwarf = Self {
            elf,
            compile_units,
            abbrev_tables,
            function_index: UnorderedMultiMap::new(),
        };

        let function_index = dwarf.build_function_index();
        dwarf.function_index = function_index;

        Ok(dwarf)
    }

    pub fn get_compile_units(&self) -> impl Iterator<Item=&CompileUnit> {
        self.compile_units.values()
    }

    fn parse_abbrev_tables(elf: &Elf, compile_units: &HashMap<CompileUnitId, CompileUnit>) -> HashMap<usize, AbbrevTable> {
        let mut abbrev_tables = HashMap::new();
        for compile_unit in compile_units.values() {
            let table = Self::parse_abbrev_table(elf, compile_unit.header.abbrev_offset);
            abbrev_tables.insert(compile_unit.header.abbrev_offset, table);
        }
        abbrev_tables
    }

    fn build_function_index(&self) -> UnorderedMultiMap<String, DIEIndexEntry> {
        let mut index = UnorderedMultiMap::new();

        for compile_unit in self.get_compile_units() {
            if let DIEEntry::Entry(root) = compile_unit.get_root(self) {
                self.index_die(&root, &mut index);
            }
        }

        index
    }

    fn index_die(&self, die: &DIE, function_index: &mut UnorderedMultiMap<String, DIEIndexEntry>) {
        let compile_unit = die.get_compile_unit(self);
        let abbrev = die.get_abbrev(self);

        let has_range = die.get_attribute(abbrev, DwarfAttribute::DW_AT_low_pc as u64).is_some() ||
            die.get_attribute(abbrev, DwarfAttribute::DW_AT_ranges as u64).is_some();

        if has_range {
            let is_function = abbrev.tag == DwarfTag::DW_TAG_subprogram as u64 || abbrev.tag == DwarfTag::DW_TAG_inlined_subroutine as u64;
            if is_function {
                if let Some(name) = die.name(self) {
                    let entry = DIEIndexEntry {
                        compile_unit_offset: compile_unit.header.offset,
                        die_offset: die.position,
                    };
                    function_index.insert(name, entry);
                }
            }
        }

        for child in die.children(compile_unit, self) {
            self.index_die(&child, function_index);
        }
    }

    pub fn compile_unit_containing_address(&self, addr: &FileAddress) -> Option<&CompileUnit> {
        self.get_compile_units().find(|cu| {
            if let DIEEntry::Entry(root) = cu.get_root(self) {
                root.contains_address(cu, self, addr)
            } else {
                false
            }
        })
    }

    fn get_compile_unit(&self, compile_unit_offset: usize) -> &CompileUnit {
        // TODO: change argument type to compile unit id
        let id = CompileUnitId(compile_unit_offset);
        self.compile_units.get(&id).expect("Unknown compile unit")
    }

    pub fn function_containing_address(&self, addr: &FileAddress) -> Option<DIE> {
        let debug_info_data = self.debug_info_data();
        let mut cursor = Cursor::new(debug_info_data);

        self.function_index.values().find_map(|entry| {
            let compile_unit = self.get_compile_unit(entry.compile_unit_offset);

            cursor.set_position(entry.die_offset);
            if let DIEEntry::Entry(die) = compile_unit.parse_die_entry(&mut cursor, self) {
                let abbrev = die.get_abbrev(self);
                if die.contains_address(compile_unit, self, addr) && abbrev.tag == DwarfTag::DW_TAG_subprogram as u64 {
                    Some(die)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    pub fn get_compile_unit_abbrev_table(&self, compile_unit_id: CompileUnitId) -> &AbbrevTable {
        let compile_unit = self.get_compile_unit(compile_unit_id.0);
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
                            let form = DwarfForm::from_repr(form).expect("Invalid DWARF form");
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

    fn parse_compile_units(elf: &Elf) -> Result<HashMap<CompileUnitId, CompileUnit>, Error> {
        let debug_info = elf.get_section_contents(".debug_info").expect("Failed to get .debug_info section");
        let mut cursor = Cursor::new(debug_info);

        let mut units = HashMap::new();

        while !cursor.is_finished() {
            let compile_unit = Self::parse_compile_unit(&mut cursor)?;

            let id = compile_unit.id();
            units.insert(id, compile_unit);
        }

        Ok(units)
    }

    fn debug_info_data(&self) -> &[u8] {
        self.expected_section_data(".debug_info")
    }

    fn debug_ranges_data(&self) -> &[u8] {
        self.expected_section_data(".debug_ranges")
    }

    fn debug_info_cursor(&self) -> Cursor {
        let data = self.debug_info_data();
        Cursor::new(data)
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
    fn dwarf_language_test() -> Result<(), Error> {
        let elf = Elf::open("target/debug/hello_rsdb")?;
        let dwarf = Dwarf::new(elf)?;

        assert_eq!(1, dwarf.get_compile_units().count(), "Unexpected number of compile units");

        let compile_unit = dwarf.get_compile_units().next().expect("Expected compile unit");
        let root = match compile_unit.get_root(&dwarf) {
            DIEEntry::Entry(root) => root,
            DIEEntry::Null(_) => panic!("Expected DIE at root"),
        };

        let abbrev = root.get_abbrev(&dwarf);
        let attr = root.get_attribute(abbrev, DwarfAttribute::DW_AT_language as u64)
            .ok_or_else(|| Error::from_message("Expected language attribute on root DIE".to_string()))?;

        let lang = attr.as_int(&dwarf)?;

        // NOTE: differs from book
        assert_eq!(DwarfLang::DW_LANG_C99 as u64, lang, "Unexpected lang");
        Ok(())
    }

    #[test]
    fn find_main_compile_unit_test() -> Result<(), Error> {
        let elf = Elf::open("target/debug/multi_cu")?;
        let dwarf = Dwarf::new(elf)?;

        let compile_units = dwarf.get_compile_units();
        assert_eq!(2, dwarf.get_compile_units().count(), "Unexpected number of compile units");

        // find compile unit containing main function
        let main_cu = dwarf.get_compile_units().find(|cu| {
            if let DIEEntry::Entry(die) = cu.get_root(&dwarf) {
                die.children(cu, &dwarf).find(|child| {
                    let abbrev = child.get_abbrev(&dwarf);
                    if abbrev.tag == DwarfTag::DW_TAG_subprogram as u64 {
                        if let Some(name_attr) = child.get_attribute(abbrev, DwarfAttribute::DW_AT_name as u64) {
                            let name = name_attr.as_string(&dwarf).expect("Expected name string");
                            name == "main"
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }).is_some()
            } else {
                false
            }
        });

        assert!(main_cu.is_some(), "Expected compile unit with main function child");


        Ok(())
    }

    #[test]
    fn range_list_test() -> Result<(), Error> {
        let elf = Elf::open("target/debug/hello_rsdb")?;
        let dwarf = Dwarf::new(elf)?;

        let mut range_data: Vec<u64> = vec![
            0x12341234, 0x12341236,
            0xFFFFFFFFFFFFFFFF, 0x32,
            0x12341234, 0x12341236,
            0x0, 0x0
        ];

        let range_data_bytes = unsafe {
            let p = range_data.as_mut_ptr() as *mut u8;
            Vec::from_raw_parts(p, range_data.len() * 8, range_data.capacity() * 8)
        };

        mem::forget(range_data);

        let cursor = Cursor::new(range_data_bytes.as_slice());
        let mut range_list = RangeListIterator {
            dwarf: &dwarf,
            cursor,
            base_address: None
        };

        let e1 = range_list.next().expect("Expected range list entry");
        assert_eq!(0x12341234, e1.low.addr(), "Unexpected low address");
        assert_eq!(0x12341236, e1.high.addr(), "Unexpected high address");
        assert!(e1.contains(&FileAddress::new(Rc::clone(&dwarf.elf), 0x12341234)), "Expected entry to contain address");
        assert!(e1.contains(&FileAddress::new(Rc::clone(&dwarf.elf), 0x12341235)), "Expected entry to contain address");
        assert!(! e1.contains(&FileAddress::new(Rc::clone(&dwarf.elf), 0x12341236)), "Expected entry to not contain address");

        // next entry should be offset by 0x32
        let e2 = range_list.next().expect("Expected range list entry");
        assert_eq!(0x12341266, e2.low.addr(), "Unexpected low address");
        assert_eq!(0x12341268, e2.high.addr(), "Unexpected high address");
        assert!(e2.contains(&FileAddress::new(Rc::clone(&dwarf.elf), 0x12341266)), "Expected entry to contain address");
        assert!(e2.contains(&FileAddress::new(Rc::clone(&dwarf.elf), 0x12341267)), "Expected entry to contain address");
        assert!(! e2.contains(&FileAddress::new(Rc::clone(&dwarf.elf), 0x12341268)), "Expected entry to not contain address");

        assert!(range_list.next().is_none(), "Expected end of range list");

        // NOTE: tests for materialised range list 'contains' member missing

        Ok(())
    }

    #[test]
    fn get_abbrev_table_test() {
        let elf = Elf::open("target/debug/hello_rsdb").expect("Failed to open ELF file");
        let dwarf = Dwarf::new(elf).expect("Failed to parse DWARF");
        for cu in dwarf.get_compile_units() {
            println!("{:?}", cu);

            let abbrev_table = dwarf.get_compile_unit_abbrev_table(cu.id());
            println!("Abbrev table:");
            println!("{:?}", abbrev_table)
        }
    }
}