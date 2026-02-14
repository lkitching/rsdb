use std::path::{Path, PathBuf};
use std::ops::Range;
use std::mem;
use strum_macros::FromRepr;
use crate::types::FileAddress;
use super::{CompileUnitId, Cursor};

#[derive(Clone, Debug)]
pub struct SourceFileInfo {
    file_name: String,
    dir_index: u64,
    modification_time: u64,
    file_length: u64,
}

impl SourceFileInfo {
    pub fn read(cursor: &mut Cursor) -> Self {
        let file_name = cursor.string();
        let dir_index = cursor.uleb128();
        let modification_time = cursor.uleb128();
        let file_length = cursor.uleb128();
        Self { file_name, dir_index, modification_time, file_length }
    }

    pub fn resolve_source_file(self, compilation_dir: &Path, include_directories: &[PathBuf]) -> SourceFile {
        let path = match self.file_name.chars().next() {
            Some('/') => {
                // absolute path
                PathBuf::from(self.file_name)
            },
            _ => {
                // relative path
                if self.dir_index == 0 {
                    Path::join(compilation_dir, self.file_name)
                } else {
                    Path::join(include_directories[self.dir_index as usize - 1].as_path(), self.file_name)
                }
            }
        };

        SourceFile::new(path, self.modification_time, self.file_length)
    }
}

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

    pub fn entries<'a, 'b>(&'a self, debug_line_data: &'b [u8]) -> LineTableIterator<LineTableInstructionIterator<'b>> {
        let instr_iterator = LineTableInstructionIterator::for_table(self, debug_line_data);
        LineTableIterator {
            inner: instr_iterator,
            registers: LineTableEntry::default(),
            table_default_is_statement: self.default_is_statement
        }
    }

    pub fn get_entry_by_address<'a, 'b>(&'a self, debug_line_data: &'b [u8], address: &FileAddress) -> LineTableIterator<LineTableInstructionIterator<'b>> {
        let mut entries = self.entries(debug_line_data);
        let mut prev = entries.clone();
        let mut prev_entry: Option<LineTableEntry> = None;

        while let Some(entry_result) = entries.next() {
            match entry_result {
                Ok(entry) => {
                    if let Some(ref pe) = prev_entry {
                        if (pe.address <= address.addr()) {
                            if (entry.address > address.addr() && !entry.end_sequence) {
                                return prev;
                            }
                        }
                    }

                    // keep searching
                    prev_entry = Some(entry);
                    prev = entries.clone();
                },
                Err(_) => break
            }
        }
        prev
    }
}

#[derive(Clone, Debug)]
pub struct LineTableEntry {
    // NOTE: book uses FileAddress here which is awkward due to Elf ownership
    // we just store the raw address and resolve the file reference elsewhere
    address: usize,
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
    //file_entry: Option<SourceFile>,
}

impl LineTableEntry {
    fn update_line(&mut self, offset: i64) {
        if (offset < 0) {
            self.line -= offset.abs() as u64;
        } else {
            self.line += offset as u64;
        }
    }

    fn get_file_entry<'a, 'b>(&'a self, table: &'b LineTable) -> &'b SourceFile {
        &table.file_names[self.file_index as usize - 1]
    }
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
            address: 0,
            file_index: 1,
            line: 1,
            column: 0,
            is_statement: false, // NOTE: book leaves unassigned
            basic_block_start: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            discriminator: 0,
            //file_entry: None,
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
    DefineFile(SourceFileInfo),
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

#[derive(Clone, Debug)]
struct InstructionParser {
    // TODO: use &'a Table instead?
    opcode_base: u8,
    line_base: i8,
    line_range: u8,
}

#[derive(Clone, Debug)]
pub enum LineTableExecutionError {
    InvalidOpcode(u8),

    // indicates the stream of instructions ended before the current
    // entry could be emitted
    PartialEntry(Instruction),
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
                    let file_info = SourceFileInfo::read(cursor);
                    ExtendedInstruction::DefineFile(file_info)
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct LineTableIterator<I> {
    inner: I,
    registers: LineTableEntry,

    // value of default_is_statement from the parent table
    table_default_is_statement: bool,
}

enum EvaluationAction {
    Continue,
    Emit(LineTableEntry),
}

impl <I> LineTableIterator<I> {
    fn execute(&mut self, instruction: &Instruction) -> EvaluationAction {
        match instruction {
            Instruction::Standard(standard_instruction) => {
                match standard_instruction {
                    StandardInstruction::Copy => {
                        let entry = self.registers.clone();
                        self.registers.basic_block_start = false;
                        self.registers.prologue_end = false;
                        self.registers.epilogue_begin = false;
                        self.registers.discriminator = 0;
                        return EvaluationAction::Emit(entry);
                    },
                    StandardInstruction::AdvancePC(offset) => {
                        self.registers.address += *offset as usize;
                    },
                    StandardInstruction::AdvanceLine(offset) => {
                        self.registers.update_line(*offset);
                    },
                    StandardInstruction::SetFile(file_index) => {
                        self.registers.file_index = *file_index;
                    },
                    StandardInstruction::SetColumn(column) => {
                        self.registers.column = *column;
                    },
                    StandardInstruction::NegateStatement => {
                        self.registers.is_statement = !self.registers.is_statement;
                    },
                    StandardInstruction::SetBasicBlock => {
                        self.registers.basic_block_start = true;
                    },
                    StandardInstruction::FixedAdvancePC(incr) => {
                        self.registers.address += *incr as usize
                    },
                    StandardInstruction::SetPrologueEnd => {
                        self.registers.prologue_end = true;
                    },
                    StandardInstruction::SetEpilogueBegin => {
                        self.registers.epilogue_begin = true;
                    },
                    StandardInstruction::SetISA(_) => {
                        // NOTE: ISA register is ignored
                    }
                }
                EvaluationAction::Continue
            },
            Instruction::Extended(extended_instruction) => {
                match extended_instruction {
                    ExtendedInstruction::EndSequence => {
                        self.registers.end_sequence = true;
                        let entry = mem::take(&mut self.registers);
                        self.registers.is_statement = self.table_default_is_statement;
                        EvaluationAction::Emit(entry)
                    },
                    ExtendedInstruction::SetAddress(addr) => {
                        self.registers.address = *addr as usize;
                        EvaluationAction::Continue
                    },
                    ExtendedInstruction::DefineFile(source_file) => {
                        // need to append source file definition to parent table
                        // emit a 'define file' action?
                        // borrow the parent table/dwarf and mutate directly?
                        todo!()
                    },
                    ExtendedInstruction::SetDiscriminator(disc) => {
                        self.registers.discriminator = *disc;
                        EvaluationAction::Continue
                    }
                }
            },
            Instruction::Special(special_instruction) => {
                self.registers.address += special_instruction.address_advance as usize;
                self.registers.update_line(special_instruction.line_advance as i64);

                let entry = self.registers.clone();

                self.registers.basic_block_start = false;
                self.registers.prologue_end = false;
                self.registers.epilogue_begin = false;
                self.registers.discriminator = 0;

                EvaluationAction::Emit(entry)
            }
        }
    }
}

impl <I> Iterator for LineTableIterator<I> where I: Iterator<Item=Result<Instruction, LineTableExecutionError>> {
    type Item = Result<LineTableEntry, LineTableExecutionError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut current_instruction = self.inner.next()?;

        // at least one instruction remaining, keep evaluating until an entry is emitted
        // NOTE: an error if the instruction stream ends before an entry is emitted
        loop {
            match current_instruction {
                Ok(instruction) => {
                    // execute current instruction
                    let action = self.execute(&instruction);
                    match action {
                        EvaluationAction::Continue => {
                            // read next instruction and continue evaluating
                            match self.inner.next() {
                                None => {
                                    // no next instruction
                                    // invalid instruction stream
                                    return Some(Err(LineTableExecutionError::PartialEntry(instruction)));
                                },
                                Some(instruction_result) => {
                                    current_instruction = instruction_result;
                                }
                            }
                        },
                        EvaluationAction::Emit(entry) => {
                            // resolve file entry
                            return Some(Ok(entry));
                        }
                    }
                },
                Err(e) => {
                    return Some(Err(e));
                }
            }
        }
    }
}