use std::fmt;
use std::fs::File;

use byteorder::LittleEndian;
use byteorder::ByteOrder;
use cached_file_view::FileView;
use cached_file_view::FileViewError;

pub struct PackIndexIterator<'a> {
    view: &'a FileView,
    next_item: u32,
    index_position: u32,
    content_position: u32
}

struct PackIndexIteratorError {}

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
            let unpadded = get_static_header_size(&self.view) + get_extended_header_size(&self.view) + get_index_size(&self.view);
            let remainder = unpadded % 8;
            if remainder > 0 {
                unpadded + 8 - remainder
            } else {
                unpadded
            }
        } else {
            get_static_header_size(&self.view) + get_extended_header_size(&self.view) + get_index_size(&self.view)
        };
        PackIndexIterator {
            view: &self.view,
            next_item: get_index_length(&self.view),
            index_position: (get_static_header_size(&self.view) + get_extended_header_size(&self.view)),
            content_position: payload_position
        }
    }
}

pub fn get_preamble(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x00..0x04).unwrap().get())
}

pub fn get_file_type(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x00..0x04).unwrap().get()) & 0xf
}

pub fn get_bitmask(view: &FileView) -> ::PFHFlags {
    ::PFHFlags::from_bits_truncate(LittleEndian::read_u32(&view.read(0x04..0x08).unwrap().get()) & !0xf)
}

pub fn get_timestamp(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x18..0x1C).unwrap().get())
}

fn get_index_length(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x10..0x14).unwrap().get())
}

fn get_index_size(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x14..0x18).unwrap().get())
}

fn _get_signature_offset(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x28..0x2C).unwrap().get())
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
        panic!("Invalid preamble!")
    }
}

fn get_extended_header_size(view: &FileView) -> u32 {
    LittleEndian::read_u32(&view.read(0x0C..0x10).unwrap().get())
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

impl<'a> PackIndexIterator<'a> {
    fn read_index_u32(&self) -> Result<u32, PackIndexIteratorError> {
        Ok(LittleEndian::read_u32(&self.view.read(self.index_position as u64..self.index_position as u64 + 4 as u64)?.get()))
    }

    fn get_next(&mut self) -> Result<::PackedFile, PackIndexIteratorError> {
        if self.next_item >= 1 {
            self.next_item -= 1;

            // read 4 bytes item length
            let mut item_length = self.read_index_u32()?;
            item_length = if has_encrypted_index(&self.view) {
                ::crypto::decrypt_index_item_file_length(self.next_item, item_length)
            } else {
                item_length
            };
            self.index_position = self.index_position.checked_add(4).ok_or(PackIndexIteratorError{})?;

            // read 4 bytes whatever, if present
            let timestamp = if has_index_with_timestamps(&self.view) {
                let d = self.read_index_u32()?;
                self.index_position = self.index_position.checked_add(4).ok_or(PackIndexIteratorError{})?;
                Some(d)
            } else {
                None
            };

            if get_preamble(&self.view) == ::PFH5_PREAMBLE && !has_big_header(&self.view) {
                self.index_position = self.index_position.checked_add(1).ok_or(PackIndexIteratorError{})?;
            }

            let remaining_index_size = get_index_size(&self.view) - (self.index_position - get_static_header_size(&self.view) - get_extended_header_size(&self.view));
            let (file_path, len) = if has_encrypted_index(&self.view) {
                ::crypto::decrypt_index_item_filename(self.view.read(self.index_position as u64..(self.index_position + remaining_index_size) as u64)?.get(), item_length as u8)
            } else {
                let mut  buf = vec!();
                let mut i = 0;
                loop {
                    let c = self.view.read((self.index_position + i) as u64..(self.index_position + i + 1) as u64)?.get()[0];
                    i += 1;
                    if c == 0 {
                        break;
                    }
                    buf.push(c);
                    if i >= remaining_index_size {
                        return Err(PackIndexIteratorError{});
                    }
                }
                (buf, i)
            };
            self.index_position += len;

            let padded_item_length = if has_encrypted_content(&self.view) {
                let remainder = item_length % 8;
                if remainder > 0 {
                    item_length.checked_add(8-remainder).ok_or(PackIndexIteratorError{})?
                } else {
                    item_length
                }
            } else {
                item_length
            };

            let content = if has_encrypted_content(&self.view) {
                ::crypto::decrypt_file(&self.view.read(self.content_position as u64..(self.content_position + padded_item_length) as u64)?.get(), item_length as usize, false)
            } else {
                self.view.read(self.content_position as u64..(self.content_position + item_length) as u64)?.get().to_vec()
            };

            if has_padding(&self.view) {
                self.content_position = self.content_position.checked_add(padded_item_length).ok_or(PackIndexIteratorError{})?;
            } else {
                self.content_position = self.content_position.checked_add(item_length).ok_or(PackIndexIteratorError{})?;
            }
            assert!(content.len() == item_length as usize, format!("{} != {}", content.len(), item_length));

            Ok(::PackedFile {
                timestamp: timestamp,
                path: String::from_utf8(file_path).map_err(|_| PackIndexIteratorError{})?,
                data: content
            })
        } else {
            Err(PackIndexIteratorError{})
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

pub fn parse_pack<'a>(input_file: File) -> Result<::PackFile, ::ParsePackError> {
    let file_view = FileView::new(input_file);
    if file_view.len()? < 4 || file_view.len()? < get_static_header_size(&file_view) as u64 {
        return Err(::ParsePackError::InvalidFileError)
    }

    if file_view.len()? < (get_static_header_size(&file_view) + get_extended_header_size(&file_view)) as u64 {
        return Err(::ParsePackError::InvalidFileError)
    }

    if get_preamble(&file_view) !=  ::PFH5_PREAMBLE && get_preamble(&file_view) != ::PFH4_PREAMBLE {
        return Err(::ParsePackError::InvalidHeaderError)
    }

    if get_file_type(&file_view) > 4 {
        return Err(::ParsePackError::InvalidHeaderError)
    }

    if !::PFHFlags::from_bits(LittleEndian::read_u32(&file_view.read(0x04..0x08)?.get()) & !0xf).is_some() {
        eprintln!("Warning: Bitmask has unknown bits set")
    }

    Ok(::PackFile {
        view: file_view
    })
}

impl From<FileViewError> for PackIndexIteratorError {
    fn from(_: FileViewError) -> Self {
        PackIndexIteratorError {}
    }
}

impl From<FileViewError> for ::ParsePackError {
    fn from(_: FileViewError) -> Self {
        ::ParsePackError::IOError
    }
}
