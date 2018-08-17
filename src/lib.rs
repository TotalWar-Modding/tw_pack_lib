extern crate byteorder;

mod build;
mod parse;
mod crypto;

use std::fs::File;
use std::path::Path;

static DEBUG: bool = false;
static PFH5_PREAMBLE: u32 = 0x35484650;
static PFH4_PREAMBLE: u32 = 0x34484650;
static HAS_BIG_HEADER: u32          = 0b0000_0001_0000_0000;
static INDEX_ENCRYPTED: u32         = 0b0000_0000_1000_0000;
static HAS_INDEX_WITH_TIMESTAMPS: u32   = 0b0000_0000_0100_0000;
static CONTENT_ENCRYPTED: u32       = 0b0000_0000_0001_0000;

#[derive(Debug)]
pub struct ParsedPackFile {
    raw_data: Vec<u8>
}

#[derive(Debug)]
pub struct ParsedPackedFile {
    pub timestamp: Option<u32>,
    pub name: String,
    pub content: Vec<u8>
}

#[derive(Debug)]
pub enum ParsePackError {
    InvalidHeaderError,
    InvalidFileError
}

#[derive(Debug)]
pub enum BuildPackError {
    UnsupportedPFHVersionError,
    EmptyInputError,
    IOError
}

pub fn parse_pack<'a>(bytes: Vec<u8>) -> Result<::ParsedPackFile, ParsePackError> {
    parse::parse_pack(bytes)
}

pub fn build_pack(input_directory: &Path, output_file: &mut File, version: u32, bitmask: u32) -> Result<(), BuildPackError> {
    build::build_pack(input_directory, output_file, version, bitmask)
}
