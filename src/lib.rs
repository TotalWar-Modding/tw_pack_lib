extern crate byteorder;
#[macro_use]
extern crate bitflags;

mod build;
mod parse;
mod crypto;

use std::fs::File;
use std::path::Path;

static DEBUG: bool = false;
const PFH5_PREAMBLE: u32 = 0x35484650;
const PFH4_PREAMBLE: u32 = 0x34484650;

#[derive(Debug)]
pub enum PFHVersion {
    PFH5,
    PFH4
}

impl PFHVersion {
    pub(crate) fn get_preamble(&self) -> u32 {
        match *self {
            PFHVersion::PFH5 => PFH5_PREAMBLE,
            PFHVersion::PFH4 => PFH4_PREAMBLE
        }
    }
}

bitflags! {
    pub struct PFHFlags: u32 {
        const HAS_BIG_HEADER            = 0b0000_0001_0000_0000;
        const HAS_ENCRYPTED_INDEX       = 0b0000_0000_1000_0000;
        const HAS_INDEX_WITH_TIMESTAMPS = 0b0000_0000_0100_0000;
        const HAS_ENCRYPTED_CONTENT     = 0b0000_0000_0001_0000;
        const TYPE_MOVIE                = 0b0000_0000_0000_0100;
        const TYPE_MOD                  = 0b0000_0000_0000_0011;
        const TYPE_PATCH                = 0b0000_0000_0000_0010;
        const TYPE_RELEASE              = 0b0000_0000_0000_0001;
        // zero flags are eerie, but we don't need a boot flag anyway
    }
}

#[derive(Debug)]
pub struct PackFile {
    raw_data: Vec<u8>
}

impl PackFile {
    pub fn get_version(&self) -> ::PFHVersion {
        match parse::get_preamble(&self.raw_data) {
            PFH5_PREAMBLE => PFHVersion::PFH5,
            PFH4_PREAMBLE => PFHVersion::PFH4,
            _ => unreachable!()
        }
    }

    pub fn get_bitmask(&self) -> ::PFHFlags {
        parse::get_bitmask(&self.raw_data)
    }
}

#[derive(Debug, Clone)]
pub struct PackedFile {
    pub timestamp: Option<u32>,
    pub path: String,
    pub data: Vec<u8>
}

#[derive(Debug)]
pub enum ParsePackError {
    InvalidHeaderError,
    InvalidFileError
}

#[derive(Debug)]
pub enum BuildPackError {
    EmptyInputError,
    InputTooBigError,
    IOError
}

pub fn parse_pack<'a>(bytes: Vec<u8>) -> Result<::PackFile, ParsePackError> {
    parse::parse_pack(bytes)
}

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: PFHVersion, bitmask: PFHFlags) -> Result<(), BuildPackError> {
    build::build_pack_from_filesystem(input_directory, output_file, version, bitmask)
}

pub fn build_pack_from_memory(input: &Vec<PackedFile>, output_file: &mut File, version: PFHVersion, bitmask: PFHFlags) -> Result<(), BuildPackError> {
    build::build_pack_from_memory(input, output_file, version, bitmask)
}
