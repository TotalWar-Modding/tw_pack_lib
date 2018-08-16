extern crate byteorder;

mod build;
mod parse;
mod crypto;

use std::fs::File;
use std::path::Path;

use parse::PackFile;
use parse::ParsePackError;
use build::BuildPackError;

static DEBUG: bool = false;
static PFH5_PREAMBLE: u32 = 0x35484650;
static PFH4_PREAMBLE: u32 = 0x34484650;

pub fn parse_pack<'a>(bytes: Vec<u8>) -> Result<PackFile, ParsePackError> {
    parse::parse_pack(bytes)
}

pub fn build_pack(input_directory: &Path, output_file: &mut File, version: u32, bitmask: u32) -> Result<(), BuildPackError> {
    build::build_pack(input_directory, output_file, version, bitmask)
}
