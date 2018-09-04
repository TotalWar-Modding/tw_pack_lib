extern crate byteorder;
#[macro_use]
extern crate bitflags;
extern crate cached_file_view;

mod build;
mod parse;
mod crypto;

use parse::LazyLoadingPackedFile;

use std::borrow::Borrow;
use std::sync::Arc;
use std::fs::File;
use std::fmt;
use std::ops::Deref;
use std::path::Path;
use cached_file_view::FileView;
use cached_file_view::FileViewError;

static DEBUG: bool = false;
const PFH5_PREAMBLE: u32 = 0x35484650;
const PFH4_PREAMBLE: u32 = 0x34484650;
const FILE_TYPE_BOOT: u32       = 0;
const FILE_TYPE_RELEASE: u32    = 1;
const FILE_TYPE_PATCH: u32      = 2;
const FILE_TYPE_MOD: u32        = 3;
const FILE_TYPE_MOVIE: u32      = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PFHVersion {
    PFH5,
    PFH4
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct PackFile {
    view: FileView
}

impl PackFile {
    pub fn get_version(&self) -> ::PFHVersion {
        match parse::get_preamble(&self.view) {
            PFH5_PREAMBLE => PFHVersion::PFH5,
            PFH4_PREAMBLE => PFHVersion::PFH4,
            _ => unreachable!()
        }
    }

    pub fn get_file_type(&self) -> PFHFileType {
        match parse::get_file_type(&self.view) {
            FILE_TYPE_BOOT => PFHFileType::Boot,
            FILE_TYPE_RELEASE => PFHFileType::Release,
            FILE_TYPE_PATCH => PFHFileType::Patch,
            FILE_TYPE_MOD => PFHFileType::Mod,
            FILE_TYPE_MOVIE => PFHFileType::Movie,
            _ => unreachable!()
        }
    }

    pub fn get_bitmask(&self) -> ::PFHFlags {
        parse::get_bitmask(&self.view)
    }

    pub fn get_timestamp(&self) -> u32 {
        parse::get_timestamp(&self.view)
    }
}

impl PackedFile {
    pub fn get_data(&self) -> Result<Arc<Vec<u8>>, ParsePackError> {
        let packed_file_data = &mut *self.data.lock().unwrap();
        let data = match &packed_file_data.inner {
            PackedFileDataType::LazyLoading(lazy) => {
                println!("PackedFile get_data ({:x?})", &lazy.range);
                if lazy.is_encrypted {
                    let plaintext = crypto::decrypt_file(&lazy.file_view.read(&lazy.range)?.to_vec(), (lazy.range.end - lazy.range.start) as usize, false);
                    assert!(plaintext.len() as u64 == lazy.range.end - lazy.range.start, format!("{} != {}", plaintext.len(), lazy.range.end - lazy.range.start));
                    Arc::new(plaintext)
                } else {
                    Arc::new(lazy.file_view.read(&lazy.range)?.to_vec())
                }
            },
            PackedFileDataType::DataBacked(data) => {
                return Ok(data.clone());
            }
        };
        packed_file_data.inner = PackedFileDataType::DataBacked(data.clone());
        Ok(data)
    }

    pub fn set_data(&mut self, data: Arc<Vec<u8>>) {
        let packed_file_data = &mut *self.data.lock().unwrap();
        packed_file_data.inner = PackedFileDataType::DataBacked(data);
    }
}

#[derive(Clone)]
pub(crate) enum PackedFileDataType {
    DataBacked(Arc<Vec<u8>>),
    LazyLoading(LazyLoadingPackedFile)
}

pub(crate) struct PackedFileData {
    inner: PackedFileDataType
}

use std::sync::Mutex;

pub struct PackedFile {
    pub timestamp: Option<u32>,
    pub path: String,
    data: Mutex<PackedFileData>
}

impl PackedFile {
    pub fn new(timestamp: Option<u32>, path: String, data: Vec<u8>) -> Self{
        PackedFile {
            data: Mutex::new(PackedFileData {
                inner: PackedFileDataType::DataBacked(Arc::new(data))
            }),
            timestamp: timestamp,
            path: path
        }
    }
}

impl Clone for PackedFile {
    fn clone(&self) -> Self {
        PackedFile::new(self.timestamp, self.path.clone(), self.get_data().unwrap().deref().clone())
    }
}

impl fmt::Debug for PackedFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackedFile {{ timestamp: {:?}, path: {:?} }}", self.timestamp, &self.path)
    }
}

#[derive(Debug)]
pub enum ParsePackError {
    InvalidHeaderError,
    InvalidFileError,
    IOError
}

#[derive(Debug)]
pub enum BuildPackError {
    EmptyInputError,
    InputTooBigError,
    IOError
}

pub fn parse_pack<'a>(input_file: File) -> Result<::PackFile, ParsePackError> {
    parse::parse_pack(input_file)
}

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: PFHVersion, bitmask: PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32) -> Result<(), BuildPackError> {
    build::build_pack_from_filesystem(input_directory, output_file, version, bitmask, file_type, pfh_timestamp)
}

pub fn build_pack_from_memory<P: Borrow<PackedFile>>(input: &Vec<P>, output_file: &mut File, version: PFHVersion, bitmask: PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32) -> Result<(), BuildPackError> {
    build::build_pack_from_memory(input, output_file, version, bitmask, file_type, pfh_timestamp)
}
