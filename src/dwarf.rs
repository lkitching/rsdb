use std::rc::Rc;
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::ops::AddAssign;

use crate::elf::{Elf};
use crate::types::TryFromBytes;

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
}

// impl <'a> AddAssign<isize> for Cursor<'a> {
//     fn add_assign(&mut self, rhs: isize) {
//         if rhs >= 0 {
//             self.position += rhs as usize;
//         } else {
//             self.position += rhs.abs() as usize
//         }
//     }
// }

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
}