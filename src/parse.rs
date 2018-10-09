use std::fmt;
use std::fs::File;
use std::ops::Range;
use std::sync::Mutex;

use byteorder::LittleEndian;
use byteorder::ByteOrder;
use cached_file_view::FileView;

use error::{Error, Result};

pub struct PackIndexIterator<'a> {
    view: &'a FileView,
    next_item: u32,
    index_position: u32,
    content_position: u32
}

#[derive(Clone)]
pub struct LazyLoadingPackedFile {
    pub file_view: FileView,
    pub range: Range<u64>,
    pub is_encrypted: bool
}

impl fmt::Display for ::PackFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackFile (encrypted index: {}, encrypted content: {}, padding: {}, timestamped files: {})", has_encrypted_index(&self.view), has_encrypted_content(&self.view), has_padding(&self.view), has_index_with_timestamps(&self.view))
    }
}

impl fmt::Display for ::PackedFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackedFile {{ timestamp: {:?}, name: \"{}\" }}", self.timestamp, self.path)
    }
}

impl<'a> IntoIterator for &'a ::PackFile {
    type Item = ::PackedFile;
    type IntoIter = PackIndexIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        let payload_position = if has_padding(&self.view) {
            let unpadded = get_static_header_size(&self.view) + get_pack_file_index_size(&self.view) + get_packed_file_index_size(&self.view);
            let remainder = unpadded % 8;
            if remainder > 0 {
                unpadded + 8 - remainder
            } else {
                unpadded
            }
        } else {
            get_static_header_size(&self.view) + get_pack_file_index_size(&self.view) + get_packed_file_index_size(&self.view)
        };
        PackIndexIterator {
            view: &self.view,
            next_item: get_packed_file_index_length(&self.view),
            index_position: (get_static_header_size(&self.view) + get_pack_file_index_size(&self.view)),
            content_position: payload_position
        }
    }
}

pub fn get_preamble(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x00..0x04).unwrap().to_vec())
}

pub fn get_file_type(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x04..0x08).unwrap().to_vec()) & 0xf
}

pub fn get_bitmask(view: &FileView) -> ::PFHFlags {
    ::PFHFlags::from_bits_truncate(LittleEndian::read_u32(&view.read(0x04..0x08).unwrap().to_vec()) & !0xf)
}

pub fn get_timestamp(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x18..0x1C).unwrap().to_vec())
}

/// Get the amount of items in the PackFile Index.
fn get_pack_file_index_length(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x08..0x0C).unwrap().to_vec())
}

/// Get the size in bytes of the PackFile Index.
fn get_pack_file_index_size(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x0C..0x10).unwrap().to_vec())
}

/// Get the amount of items in the PackedFile Index.
fn get_packed_file_index_length(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x10..0x14).unwrap().to_vec())
}

/// Get the size in bytes of the PackedFile Index.
fn get_packed_file_index_size(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x14..0x18).unwrap().to_vec())
}

fn _get_signature_offset(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x28..0x2C).unwrap().to_vec())
}

fn get_static_header_size(raw_data: &FileView) -> u32 {
    if get_preamble(&raw_data) == ::PFH4_PREAMBLE {
        0x1C
    } else if get_preamble(&raw_data) == ::PFH5_PREAMBLE {
        if has_big_header(&raw_data) {
            0x30
        } else {
            0x1C
        }
    } else {
        panic!("Invalid preamble! ###{:?}", get_preamble(&raw_data))
    }
}

fn has_big_header(view: &FileView) -> bool {
    get_bitmask(&view).contains(::PFHFlags::HAS_BIG_HEADER)
}

fn has_encrypted_index(view: &FileView) -> bool {
    get_bitmask(&view).contains(::PFHFlags::HAS_ENCRYPTED_INDEX)
}

fn has_index_with_timestamps(view: &FileView) -> bool {
    get_bitmask(&view).contains(::PFHFlags::HAS_INDEX_WITH_TIMESTAMPS)
}

fn has_encrypted_content(view: &FileView) -> bool {
    get_bitmask(&view).contains(::PFHFlags::HAS_ENCRYPTED_CONTENT)
}

fn has_padding(raw_data: &FileView) -> bool {
    get_preamble(&raw_data) == ::PFH5_PREAMBLE && has_encrypted_content(&raw_data)
}

pub fn get_pack_file_index(view: &FileView) -> Vec<String> {

    let raw_index = view.read(get_static_header_size(view) as u64..(get_static_header_size(view) + get_pack_file_index_size(view)) as u64).unwrap().to_vec();
    
    let mut pack_file_index = vec![];
    let mut pos: usize = 0;
    for _ in 0..get_pack_file_index_length(view) {
        let mut pack_file_name = String::new();

        // For each byte...
        loop {
            let character = raw_index[pos];
            if character == 0 {
                pack_file_index.push(pack_file_name);
                pos += 1;
                break;
            } else {
                pack_file_name.push(character as char);
                pos += 1;
            }
        }
    }
    pack_file_index
}


impl<'a> PackIndexIterator<'a> {
    fn read_index_u32(&self) -> Result<u32> {
        Ok(LittleEndian::read_u32(&self.view.read(self.index_position as u64..self.index_position as u64 + 4 as u64)?.to_vec()))
    }

    fn get_next(&mut self) -> Result<::PackedFile> {
        if self.next_item >= 1 {
            self.next_item -= 1;

            // read 4 bytes item length
            let mut item_length = self.read_index_u32()?;
            item_length = if has_encrypted_index(&self.view) {
                ::crypto::decrypt_index_item_file_length(self.next_item, item_length)
            } else {
                item_length
            };
            self.index_position = self.index_position.checked_add(4).ok_or(Error::IndexIteratorError)?;

            // read 4 bytes whatever, if present
            let timestamp = if has_index_with_timestamps(&self.view) {
                let d = self.read_index_u32()?;
                self.index_position = self.index_position.checked_add(4).ok_or(Error::IndexIteratorError)?;
                Some(d)
            } else {
                None
            };

            if get_preamble(&self.view) == ::PFH5_PREAMBLE && !has_big_header(&self.view) {
                self.index_position = self.index_position.checked_add(1).ok_or(Error::IndexIteratorError)?;
            }

            let remaining_index_size = get_packed_file_index_size(&self.view) - (self.index_position - get_static_header_size(&self.view) - get_pack_file_index_size(&self.view));
            let (file_path, len) = if has_encrypted_index(&self.view) {
                ::crypto::decrypt_index_item_filename(&self.view.read(self.index_position as u64..(self.index_position + remaining_index_size) as u64)?.to_vec(), item_length as u8)
            } else {
                let mut  buf = vec!();
                let mut i = 0;
                loop {
                    let c = self.view.read((self.index_position + i) as u64..(self.index_position + i + 1) as u64)?.to_vec()[0];
                    i += 1;
                    if c == 0 {
                        break;
                    }
                    buf.push(c);
                    if i >= remaining_index_size {
                        return Err(Error::IndexIteratorError);
                    }
                }
                (buf, i)
            };
            self.index_position += len;

            let padded_item_length = if has_encrypted_content(&self.view) {
                let remainder = item_length % 8;
                if remainder > 0 {
                    item_length.checked_add(8-remainder).ok_or(Error::IndexIteratorError)?
                } else {
                    item_length
                }
            } else {
                item_length
            };

            let start = self.content_position as u64;
            let end = (self.content_position + item_length) as u64;

            if has_padding(&self.view) {
                self.content_position = self.content_position.checked_add(padded_item_length).ok_or(Error::IndexIteratorError)?;
            } else {
                self.content_position = self.content_position.checked_add(item_length).ok_or(Error::IndexIteratorError)?;
            }

            Ok(::PackedFile {
                timestamp,
                path: String::from_utf8(file_path).map_err(|_| Error::IndexIteratorError)?,
                data: Mutex::new(::PackedFileData::LazyLoading(LazyLoadingPackedFile {
                        file_view: (*self.view).clone(),
                        is_encrypted: has_encrypted_content(&self.view),
                        range: start..end
                    })
                )
            })
        } else {
            Err(Error::IndexIteratorError)
        }
    }
}

impl<'a> Iterator for PackIndexIterator<'a> {
    type Item = ::PackedFile;
    fn next(&mut self) -> Option<::PackedFile> {
        match self.get_next() {
            Ok(item) => Some(item),
            Err(_) => None
        }
    }
}

pub fn parse_pack(input_file: File) -> Result<::PackFile> {
    let file_view = FileView::new(input_file)?;

    if file_view.length < 4 || file_view.length < get_static_header_size(&file_view) as u64 {
        return Err(Error::InvalidFileError)
    }

    if file_view.length < (get_static_header_size(&file_view) + get_pack_file_index_size(&file_view)) as u64 {
        return Err(Error::InvalidFileError)
    }

    if get_preamble(&file_view) == ::PFH3_PREAMBLE || get_preamble(&file_view) == ::PFH2_PREAMBLE || get_preamble(&file_view) == ::PFH0_PREAMBLE {
        return Err(Error::UnsupportedPackFile)
    }

    if get_preamble(&file_view) != ::PFH5_PREAMBLE && get_preamble(&file_view) != ::PFH4_PREAMBLE {
        return Err(Error::InvalidHeaderError)
    }

    if get_file_type(&file_view) > 4 {
        return Err(Error::InvalidHeaderError)
    }

    if !::PFHFlags::from_bits(LittleEndian::read_u32(&file_view.read(0x04..0x08)?.to_vec()) & !0xf).is_some() {
        eprintln!("Warning: Bitmask has unknown bits set")
    }

    let begin = file_view.read(0..get_packed_file_index_size(&file_view) as u64)?;
    Ok(::PackFile {
        view: file_view,
        begin: begin
    })
}
