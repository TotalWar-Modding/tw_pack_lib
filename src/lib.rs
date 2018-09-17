//! A library to create/manipulate Total War PackFiles.
//!
//! Modern Total War games (since Empire: Total War) have their data packed inside `.pack` files.
//! This library allows you to *open* those PackFiles and manipulate them however you want.
//! 
//! Not all Modern Total War games are supported yet. The supported ones are:
//! - Warhammer 2.
//! - Warhammer.
//! - Attila.
//! - Rome 2.
//! - Arena.
//!
//! Games that will be supported in the future are:
//! - Shogun 2.
//! - Napoleon.
//! - Empire.
//! - Thrones of Brittania.
//! - Three Kingdoms.
//!
//! Keep in mind that this lib only gives you the ability to *open* and *edit* PackFiles. If you want 
//! to edit the PackedFiles inside (like editing a value in a table), that's not covered by this lib.

#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate cached_file_view;

mod build;
mod crypto;
pub mod error;
mod parse;

use error::Result;
use parse::LazyLoadingPackedFile;

use std::borrow::Borrow;
use std::sync::Arc;
use std::sync::Mutex;
use std::fs::File;
use std::fmt;
use std::path::Path;
use cached_file_view::FileView;

static DEBUG: bool = false;
const PFH5_PREAMBLE: u32 = 0x35484650;
const PFH4_PREAMBLE: u32 = 0x34484650;
const PFH3_PREAMBLE: u32 = 0x33484650;
const PFH2_PREAMBLE: u32 = 0x32484650;
const PFH0_PREAMBLE: u32 = 0x30484650;
const FILE_TYPE_BOOT: u32       = 0;
const FILE_TYPE_RELEASE: u32    = 1;
const FILE_TYPE_PATCH: u32      = 2;
const FILE_TYPE_MOD: u32        = 3;
const FILE_TYPE_MOVIE: u32      = 4;

bitflags! {

    /// This represents the bitmasks a PackFile can have applied to his type.
    ///
    /// The possible bitmasks are:
    /// - `HAS_BIG_HEADER`: Used to specify that the header of the PackFile is extended by 20 bytes. Used in Arena.
    /// - `HAS_ENCRYPTED_INDEX`: Used to specify that the PackedFile Index is encrypted. Used in Arena.
    /// - `HAS_INDEX_WITH_TIMESTAMPS`: Used to specify that the PackedFile Index contains a timestamp of evey PackFile.
    /// - `HAS_ENCRYPTED_CONTENT`: Used to specify that the PackedFile's data is encrypted. Seen in `music.pack` PackFiles and in Arena.
    pub struct PFHFlags: u32 {
        const HAS_BIG_HEADER            = 0b0000_0001_0000_0000;
        const HAS_ENCRYPTED_INDEX       = 0b0000_0000_1000_0000;
        const HAS_INDEX_WITH_TIMESTAMPS = 0b0000_0000_0100_0000;
        const HAS_ENCRYPTED_CONTENT     = 0b0000_0000_0001_0000;
    }
}

/// This enum represents the **Version** of a PackFile.
///
/// The possible values are:
/// - `PFH5`: Used in Warhammer 2 and Arena.
/// - `PFH4`: Used in Warhammer 1, Attila, Rome 2, and Thrones of Brittania.
/// - `Unsupported`: Wildcard for any PackFile with a *Version* the lib doesn't support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PFHVersion {
    PFH5,
    PFH4,
    Unsupported,
}

/// This enum represents the **Type** of a PackFile. 
///
/// The possible types are, in the order they'll load when the game starts (their numeric value is the number besides them):
/// - `Boot` **(0)**: Used in CA PackFiles, not useful for modding.
/// - `Release` **(1)**: Used in CA PackFiles, not useful for modding.
/// - `Patch` **(2)**: Used in CA PackFiles, not useful for modding.
/// - `Mod` **(3)**: Used for mods. PackFiles of this type are only loaded in the game if they are enabled in the Mod Manager/Launcher.
/// - `Movie` **(4)**: Used in CA PackFiles and for some special mods. Unlike `Mod` PackFiles, these ones always get loaded.
/// - `Other(u32)`: Wildcard for any type that doesn't fit in any of the other categories. The type's value is stored in the Variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PFHFileType {
    Boot,
    Release,
    Patch,
    Mod,
    Movie,
    Other(u32),
}

#[derive(Debug, Clone)]
pub struct PackFile {
    view: FileView
}

/// This struct represents a **PackedFile**, a File contained inside a PackFile. 
///
/// A PackedFile is a File contained inside a PackFile. It contains:
/// - `timestamp`: a timestamp in `u32` format of the PackedFile, usually his `last modified` date. Optional.
/// - `path`: a path of type `a/b/c.whatever`. This is the *virtual* path of the PackedFile.
/// - `data`: a `Mutex<PackedFileData>` with the data to be contained in the PackedFile. Private. If you want to get/set it, use the dedicated methods.
///
/// Keep in mind that other than decrypting the data if it's encrypted, the PackedFiles data is stored as it's in the PackFile.
/// If you want to decode it/process it/edit it in any way, use an specialized program like RPFM, or write your own code for it.
pub struct PackedFile {
    pub timestamp: Option<u32>,
    pub path: String,
    data: Mutex<PackedFileData>
}

/// This enum represents the **Data** contained inside a PackedFile. Not intended to be used outside this lib.
///
/// Due to **Lazy Loading** the data inside a PackedFile may or may not be loaded. That means we can have:
/// - `DataBacked(Arc<Vec<u8>>)`: The data is loaded in memory, inside the Variant.
/// - `LazyLoading(LazyLoadingPackedFile)`: The data is not loaded in memory. In the Variant is store information needed to get the data ondemand.
#[derive(Clone)]
pub(crate) enum PackedFileData {
    DataBacked(Arc<Vec<u8>>),
    LazyLoading(LazyLoadingPackedFile)
}

impl PFHFileType {

    /// This function returns the PackFile's **Type** in `u32` format. To know what value corresponds with what type, check their definition's comment.
    pub fn get_value(&self) -> u32 {
        match *self {
            PFHFileType::Boot => FILE_TYPE_BOOT,
            PFHFileType::Release => FILE_TYPE_RELEASE,
            PFHFileType::Patch => FILE_TYPE_PATCH,
            PFHFileType::Mod => FILE_TYPE_MOD,
            PFHFileType::Movie => FILE_TYPE_MOVIE,
            PFHFileType::Other(value) => value
        }
    }
}

impl PFHVersion {

    /// This function returns the PackFile's **Preamble** or **Id** (his 4 first bytes) in `u32` format.
    pub(crate) fn get_preamble(&self) -> u32 {
        match *self {
            PFHVersion::PFH5 => PFH5_PREAMBLE,
            PFHVersion::PFH4 => PFH4_PREAMBLE,
            _ => unreachable!()
        }
    }
}

impl PackFile {

    /// This function returns the [`PFHVersion`](enum.PFHVersion.html) of the provided PackFile.
    pub fn get_version(&self) -> ::PFHVersion {
        match parse::get_preamble(&self.view) {
            PFH5_PREAMBLE => PFHVersion::PFH5,
            PFH4_PREAMBLE => PFHVersion::PFH4,
            PFH3_PREAMBLE | PFH2_PREAMBLE | PFH0_PREAMBLE => PFHVersion::Unsupported,
            _ => unreachable!()
        }
    }

    /// This function returns the [`PFHFileType`](enum.PFHFileType.html) of the provided PackFile.
    pub fn get_file_type(&self) -> PFHFileType {
        match parse::get_file_type(&self.view) {
            FILE_TYPE_BOOT => PFHFileType::Boot,
            FILE_TYPE_RELEASE => PFHFileType::Release,
            FILE_TYPE_PATCH => PFHFileType::Patch,
            FILE_TYPE_MOD => PFHFileType::Mod,
            FILE_TYPE_MOVIE => PFHFileType::Movie,
            value => PFHFileType::Other(value)
        }
    }

    /// This function returns the [`PFHFlags`](enum.PFHFlags.html) of the provided PackFile.
    pub fn get_bitmask(&self) -> ::PFHFlags {
        parse::get_bitmask(&self.view)
    }

    /// This function returns the `Timestamp` stored in the header of the provided PackFile, if any.
    ///
    /// Keep in mind this `Timestamp` is in `u32` format. If you want to actually check it, you have to convert it to something readable.
    // So... TODO: Return a processed timestamp instead the raw value.
    pub fn get_timestamp(&self) -> u32 {
        parse::get_timestamp(&self.view)
    }
}

impl PackedFile {

    /// This function creates a new PackedFile with the provided info.
    ///
    /// It requires:
    /// - `timestamp`: a timestamp in `u32` format of the PackedFile, usually his `last modified` date. Optional.
    /// - `path`: a path of type `a/b/c.whatever`.
    /// - `data`: the data to be contained in the PackedFile. For an empty PackedFile, just pass an empty vector.
    pub fn new(timestamp: Option<u32>, path: String, data: Vec<u8>) -> Self {
        PackedFile {
            data: Mutex::new(PackedFileData::DataBacked(Arc::new(data))),
            timestamp,
            path
        }
    }

    /// This function tries to return the raw data contained inside a PackedFile. This ***can fail*** only if you're using Lazy-Loading to open the PackFile.
    /// If not, you can safely unwrap the Result.
    pub fn get_data(&self) -> Result<Arc<Vec<u8>>> {
        let packed_file_data = &mut *self.data.lock().unwrap();
        let data = match &packed_file_data {
            PackedFileData::LazyLoading(lazy) => {
                if DEBUG {
                    println!("PackedFile get_data (0x{:x?}-0x{:x?})", lazy.range.start, lazy.range.end);
                }
                if lazy.is_encrypted {
                    let plaintext = crypto::decrypt_file(&lazy.file_view.read(&lazy.range)?.to_vec(), (lazy.range.end - lazy.range.start) as usize, false);
                    assert!(plaintext.len() as u64 == lazy.range.end - lazy.range.start, format!("{} != {}", plaintext.len(), lazy.range.end - lazy.range.start));
                    Arc::new(plaintext)
                } else {
                    Arc::new(lazy.file_view.read(&lazy.range)?.to_vec())
                }
            },
            PackedFileData::DataBacked(data) => {
                return Ok(data.clone());
            }
        };
        *packed_file_data = PackedFileData::DataBacked(data.clone());
        Ok(data)
    }

    /// This function replaces whatever data the PackedFile has with the data provided to it.
    pub fn set_data(&mut self, data: Arc<Vec<u8>>) {
        let packed_file_data = &mut *self.data.lock().unwrap();
        *packed_file_data = PackedFileData::DataBacked(data);
    }
}

impl Clone for PackedFile {
    fn clone(&self) -> Self {
        match &*self.data.lock().unwrap() {
            PackedFileData::DataBacked(ref data) => PackedFile {
                data: Mutex::new(PackedFileData::DataBacked(data.clone())),
                timestamp: self.timestamp,
                path: self.path.clone()
            },
            PackedFileData::LazyLoading(ref lazy) => PackedFile {
                data: Mutex::new(PackedFileData::LazyLoading(lazy.clone())),
                timestamp: self.timestamp,
                path: self.path.clone()
            }
        }
    }
}

impl fmt::Debug for PackedFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackedFile {{ timestamp: {:?}, path: {:?} }}", self.timestamp, &self.path)
    }
}

pub fn parse_pack(input_file: File, load_lazy: bool) -> Result<::PackFile> {
    let pack_file = parse::parse_pack(input_file)?;
    if !load_lazy {
        for packed_file in pack_file.into_iter() {
            packed_file.get_data()?;
        }
    }
    Ok(pack_file)
}

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: PFHVersion, bitmask: PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32) -> Result<()> {
    build::build_pack_from_filesystem(input_directory, output_file, version, bitmask, file_type, pfh_timestamp)
}

pub fn build_pack_from_memory<P: Borrow<PackedFile>>(input: &Vec<P>, output_file: &mut File, version: PFHVersion, bitmask: PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32) -> Result<()> {
    build::build_pack_from_memory(input, output_file, version, bitmask, file_type, pfh_timestamp)
}
