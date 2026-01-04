use std::path::PathBuf;
use std::ops::Range;

use strum_macros::FromRepr;

use crate::types::FileAddress;
use super::{CompileUnitId, Cursor};

// NOTE: renamed from 'File' in book
#[derive(Clone, Debug)]
pub struct SourceFile {
    path: PathBuf,
    modification_time: u64,
    file_length: u64,
}

impl SourceFile {
    pub fn new(path: PathBuf, modification_time: u64, file_length: u64) -> Self {
        Self {
            path,
            modification_time,
            file_length,
        }
    }
}

#[derive(Debug)]
pub struct LineTable {
    compile_unit_id: CompileUnitId,

    // byte range occupied by the line table program within the .debug_line section
    // NOTE: book stores slice directly as data_ member
    program_span: Range<usize>,

    default_is_statement: bool,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    include_directories: Vec<PathBuf>,
    file_names: Vec<SourceFile>,
}

impl LineTable {
    pub fn new(
        compile_unit_id: CompileUnitId,
        program_span: Range<usize>,
        default_is_statement: bool,
        line_base: i8,
        line_range: u8,
        opcode_base: u8,
        include_directories: Vec<PathBuf>,
        file_names: Vec<SourceFile>,
    ) -> Self {
        Self {
            compile_unit_id,
            program_span,
            default_is_statement,
            line_base,
            line_range,
            opcode_base,
            include_directories,
            file_names,
        }
    }
}

#[derive(Debug)]
struct LineTableEntry {
    address: Option<FileAddress>,
    file_index: u64,
    line: u64,
    column: u64,
    is_statement: bool,
    basic_block_start: bool,
    end_sequence: bool,
    prologue_end: bool,
    epilogue_begin: bool,
    discriminator: u64,

    // should be index into LineTable::file_names?
    file_entry: Option<SourceFile>,
}

impl Eq for LineTableEntry {}

impl PartialEq for LineTableEntry {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address &&
            self.file_index == other.file_index &&
            self.line == other.line &&
            self.column == other.column &&
            self.discriminator == other.discriminator
    }
}

impl Default for LineTableEntry {
    fn default() -> Self {
        Self {
            address: None,
            file_index: 1,
            line: 1,
            column: 0,
            is_statement: false, // NOTE: book leaves unassigned
            basic_block_start: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            discriminator: 0,
            file_entry: None,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
enum DwarfStandardOpcode {
    DW_LNS_copy = 0x01,
    DW_LNS_advance_pc = 0x02,
    DW_LNS_advance_line = 0x03,
    DW_LNS_set_file = 0x04,
    DW_LNS_set_column = 0x05,
    DW_LNS_negate_stmt = 0x06,
    DW_LNS_set_basic_block = 0x07,
    DW_LNS_const_add_pc = 0x08,
    DW_LNS_fixed_advance_pc = 0x09,
    DW_LNS_set_prologue_end = 0x0a,
    DW_LNS_set_epilogue_begin = 0x0b,
    DW_LNS_set_isa = 0x0c,
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, FromRepr)]
pub enum DwarfExtendedOpcode {
    DW_LNE_end_sequence = 0x01,
    DW_LNE_set_address = 0x02,
    DW_LNE_define_file = 0x03,
    DW_LNE_set_discriminator = 0x04,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StandardInstruction {
    Copy,
    AdvancePC(u64),
    AdvanceLine(i64),
    SetFile(u64),
    SetColumn(u64),
    NegateStatement,
    SetBasicBlock,
    // NOTE: Result of parsing a const_add_pc opcode is an AdvancePC instruction
    //ConstAddPC,
    FixedAdvancePC(u16),
    SetPrologueEnd,
    SetEpilogueBegin,
    SetISA(u64),
}

#[derive(Clone, Debug)]
pub enum ExtendedInstruction {
    EndSequence,
    SetAddress(u64),
    DefineFile(SourceFile),
    SetDiscriminator(u64),
}

#[derive(Copy, Clone, Debug)]
struct SpecialInstruction {
    address_advance: u8,
    line_advance: i8,
}

#[derive(Clone, Debug)]
pub enum Instruction {
    Standard(StandardInstruction),
    Extended(ExtendedInstruction),
    Special(SpecialInstruction),
}

struct InstructionParser {
    // TODO: use &'a Table instead?
    opcode_base: u8,
    line_base: i8,
    line_range: u8,
}

#[derive(Clone, Debug)]
pub enum LineTableExecutionError {
    InvalidOpcode(u8),
}

impl InstructionParser {
    fn special(&self, entry: u8) -> SpecialInstruction {
        assert!(entry >= self.opcode_base);

        let adjusted_opcode = entry - self.opcode_base;
        let line_column = adjusted_opcode % self.line_range;

        SpecialInstruction {
            address_advance: adjusted_opcode / self.line_range,
            line_advance: self.line_base + (line_column as i8),
        }
    }

    fn parse(&self, cursor: &mut Cursor) -> Result<Instruction, LineTableExecutionError> {
        let opcode = cursor.u8();

        if opcode == 0 {
            // extended instruction
            let _length = cursor.uleb128();
            let extended_opcode_raw = cursor.u8();
            let extended_opcode = DwarfExtendedOpcode::from_repr(extended_opcode_raw)
            .ok_or(LineTableExecutionError::InvalidOpcode(extended_opcode_raw))?;

            let instr = match extended_opcode {
                DwarfExtendedOpcode::DW_LNE_end_sequence => ExtendedInstruction::EndSequence,
                DwarfExtendedOpcode::DW_LNE_set_address => {
                    let addr = cursor.u64();
                    ExtendedInstruction::SetAddress(addr)
                },
                DwarfExtendedOpcode::DW_LNE_define_file => {
                    unimplemented!();
                },
                DwarfExtendedOpcode::DW_LNE_set_discriminator => {
                    let discriminator = cursor.uleb128();
                    ExtendedInstruction::SetDiscriminator(discriminator)
                }
            };

            Ok(Instruction::Extended(instr))
        } else if opcode < self.opcode_base {
            // standard instruction
            // NOTE: could return result here but should always be valid if < opcode_base
            let standard_opcode = DwarfStandardOpcode::from_repr(opcode).expect("Unknown standard opcode");

            let instr = match standard_opcode {
                DwarfStandardOpcode::DW_LNS_copy => StandardInstruction::Copy,
                DwarfStandardOpcode::DW_LNS_advance_pc => {
                    let incr = cursor.uleb128();
                    StandardInstruction::AdvancePC(incr)
                },
                DwarfStandardOpcode::DW_LNS_advance_line => {
                    let incr = cursor.sleb128();
                    StandardInstruction::AdvanceLine(incr)
                },
                DwarfStandardOpcode::DW_LNS_set_file => {
                    let file_index = cursor.uleb128();
                    StandardInstruction::SetFile(file_index)
                },
                DwarfStandardOpcode::DW_LNS_set_column => {
                    let column = cursor.uleb128();
                    StandardInstruction::SetColumn(column)
                },
                DwarfStandardOpcode::DW_LNS_negate_stmt => StandardInstruction::NegateStatement,
                DwarfStandardOpcode::DW_LNS_set_basic_block => StandardInstruction::SetBasicBlock,
                DwarfStandardOpcode::DW_LNS_const_add_pc => {
                    let special = self.special(255);
                    StandardInstruction::AdvancePC(special.address_advance as u64)
                },
                DwarfStandardOpcode::DW_LNS_fixed_advance_pc => {
                    let incr = cursor.u16();
                    StandardInstruction::FixedAdvancePC(incr)
                },
                DwarfStandardOpcode::DW_LNS_set_prologue_end => StandardInstruction::SetPrologueEnd,
                DwarfStandardOpcode::DW_LNS_set_epilogue_begin => StandardInstruction::SetEpilogueBegin,
                DwarfStandardOpcode::DW_LNS_set_isa => {
                    // NOTE: book doesn't parse operand (bug?)
                    let isa = cursor.uleb128();
                    StandardInstruction::SetISA(isa)
                }
            };

            Ok(Instruction::Standard(instr))
        } else {
            // special instruction
            let instr = self.special(opcode);
            Ok(Instruction::Special(instr))
        }
    }
}

pub struct LineTableInstructionIterator<'a> {
    parser: InstructionParser,
    cursor: Cursor<'a>,
}

impl <'a> Iterator for LineTableInstructionIterator<'a> {
    type Item = Result<Instruction, LineTableExecutionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_finished() {
            None
        } else {
            let inst_result = self.parser.parse(&mut self.cursor);
            Some(inst_result)
        }
    }
}

impl <'a> LineTableInstructionIterator<'a> {
    pub fn for_table(table: &LineTable, debug_line_data: &'a [u8]) -> Self {
        let program_data = &debug_line_data[table.program_span.clone()];
        let cursor = Cursor::new(program_data);
        let parser = InstructionParser {
            opcode_base: table.opcode_base,
            line_base: table.line_base,
            line_range: table.line_range,
        };

        Self { parser, cursor }
    }
}