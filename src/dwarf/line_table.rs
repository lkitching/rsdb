use std::path::PathBuf;
use std::ops::Range;

use super::CompileUnitId;

// NOTE: renamed from 'File' in book
#[derive(Debug)]
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



