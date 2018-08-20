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
const FILE_TYPE_BOOT: u32       = 0;
const FILE_TYPE_RELEASE: u32    = 1;
const FILE_TYPE_PATCH: u32      = 2;
const FILE_TYPE_MOD: u32        = 3;
const FILE_TYPE_MOVIE: u32      = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PFHVersion {
    PFH5,
    PFH4
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PFHFileType {
    Boot,
    Release,
    Patch,
    Mod,
    Movie
}

impl PFHFileType {
    pub fn get_value(&self) -> u32 {
        match *self {
            PFHFileType::Boot => FILE_TYPE_BOOT,
            PFHFileType::Release => FILE_TYPE_RELEASE,
            PFHFileType::Patch => FILE_TYPE_PATCH,
            PFHFileType::Mod => FILE_TYPE_MOD,
            PFHFileType::Movie => FILE_TYPE_MOVIE
        }
    }
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

    pub fn get_file_type(&self) -> PFHFileType {
        match parse::get_file_type(&self.raw_data) {
            FILE_TYPE_BOOT => PFHFileType::Boot,
            FILE_TYPE_RELEASE => PFHFileType::Release,
            FILE_TYPE_PATCH => PFHFileType::Patch,
            FILE_TYPE_MOD => PFHFileType::Mod,
            FILE_TYPE_MOVIE => PFHFileType::Movie,
            _ => unreachable!()
        }
    }

    pub fn get_bitmask(&self) -> ::PFHFlags {
        parse::get_bitmask(&self.raw_data)
    }

    pub fn get_timestamp(&self) -> u32 {
        parse::get_timestamp(&self.raw_data)
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

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: &PFHVersion, bitmask: &PFHFlags, file_type: &::PFHFileType) -> Result<(), BuildPackError> {
    build::build_pack_from_filesystem(input_directory, output_file, version, bitmask, file_type)
}

pub fn build_pack_from_memory(input: &Vec<PackedFile>, output_file: &mut File, version: &PFHVersion, bitmask: &PFHFlags, file_type: &::PFHFileType) -> Result<(), BuildPackError> {
    build::build_pack_from_memory(input, output_file, version, bitmask, file_type)
}
