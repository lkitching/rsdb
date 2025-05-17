use std::rc::Rc;
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::ops::AddAssign;

use strum_macros::FromRepr;

use crate::elf::{Elf};
use crate::types::TryFromBytes;
use crate::error::Error;

#[allow(non_camel_case_types)]
#[repr(u64)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
enum DwarfForm {
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

struct AttributeSpec {
    attribute: u64,
    form: u64
}

struct Abbrev {
    code: u64,
    tag: u64,
    has_children: bool,
    attribute_specs: Vec<AttributeSpec>
}

struct AbbrevTable {
    entries: HashMap<u64, Abbrev>
}

impl AbbrevTable {
    fn get_by_code(&self, code: u64) -> Option<&Abbrev> {
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

        let cs = CStr::from_bytes_with_nul(&self.data[self.position..end]).expect("Failed to create CStr");
        let s = cs.to_string_lossy().to_string();

        // position cursor past end of string
        self.position = end + 1;

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

enum DIE {
    Null(usize),
    Entry { position: usize, next: usize, attribute_locations: Vec<usize> }
}

impl DIE {

}

struct CompileUnit<'a> {
    //parent: &'a Dwarf,
    data: &'a [u8],
    abbrev_offset: usize
}

impl <'a> CompileUnit<'a> {
    fn parse_die(&self, cursor: &mut Cursor) -> DIE {
        let position = cursor.position;
        let abbrev_code = cursor.uleb128();

        if abbrev_code == 0 {
            // null DIE
            // next DIE is at current cursor position
            DIE::Null(cursor.position)
        } else {
            // get abbreviation table for compile unit
            // and lookup abbrev by code
            let abbrev = self.abbreviation_table().get_by_code(abbrev_code).expect("Failed to find abbreviation code");

            let mut attribute_locations = Vec::with_capacity(abbrev.attribute_specs.len());
            for attr in abbrev.attribute_specs.iter() {
                attribute_locations.push(cursor.position);
                // TODO: parse on construction!
                let form = DwarfForm::from_repr(attr.form).expect("Invalid dwarf form");
                cursor.skip_form(form)
            }

            // next DIE should be at current cursor position
            let next = cursor.position;
            DIE::Entry { position, next, attribute_locations }
        }
    }

    fn abbreviation_table(&self) -> &AbbrevTable {
        unimplemented!()
    }

    fn root(&self) -> DIE {
        // NOTE: data contains entire compile unit data including the 11-byte header
        // create cursor for unit DIE data
        let mut cursor = Cursor::new(&self.data[11..]);
        self.parse_die(&mut cursor)
    }
}

impl <'a> CompileUnit<'a> {
    fn new(data: &'a [u8], abbrev_offset: usize) -> Self {
        Self { data, abbrev_offset }
    }

    fn get_abbrev_table<'b>(&self, parent: &'b mut Dwarf) -> &'b AbbrevTable {
        parent.get_abbrev_table(self.abbrev_offset)
    }
}

pub struct Dwarf {
    elf: Rc<Elf>,
    abbrev_tables: HashMap<usize, AbbrevTable>
}

impl Dwarf {
    fn parse_abbrev_table(elf: &Elf, offset: usize) -> AbbrevTable {
        let section = elf.get_section_contents(".debug_abbrev").expect("Failed to get .debug_abbrev section");
        let mut cursor = Cursor::new(section);
        cursor.set_position(offset);

        let mut entries = HashMap::new();
        loop {
            let code = cursor.uleb128();
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

            if code == 0 {
                break;
            } else {
                let abbrev = Abbrev { code, tag, has_children, attribute_specs };
                entries.insert(code, abbrev);
            }
        }

        AbbrevTable { entries }
    }

    fn get_abbrev_table(&mut self, offset: usize) -> &AbbrevTable {
        self.abbrev_tables.entry(offset).or_insert_with(|| Self::parse_abbrev_table(self.elf.as_ref(), offset))
    }

    fn parse_compile_unit<'a : 'b, 'b>(debug_data: &'a [u8], cursor: &'b mut Cursor) -> Result<CompileUnit<'a>, Error> {
        let start = cursor.position;
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

        // NOTE: size field contains the size of the entry excluding the size of the size field itself
        // add this back in to the compile unit size
        let size = size + size_of::<u32>() as u32;
        let data = &debug_data[start..start + size as usize];

        Ok(CompileUnit { data, abbrev_offset })
    }

    fn parse_compile_units(elf: &Elf) -> Result<Vec<CompileUnit>, Error> {
        let debug_info = elf.get_section_contents(".debug_info").expect("Failed to get .debug_info section");
        let mut cursor = Cursor::new(debug_info);

        let mut units = Vec::new();

        while !cursor.is_finished() {
            let unit_header = Self::parse_compile_unit(debug_info, &mut cursor)?;

            // skip over compile unit data
            cursor += unit_header.data.len();

            units.push(unit_header);
        }

        Ok(units)
    }
}