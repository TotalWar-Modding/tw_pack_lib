use std::fmt;

use byteorder::LittleEndian;
use byteorder::ByteOrder;

#[derive(Debug)]
pub struct PackIndexIterator<'a> {
    raw_data: &'a [u8],
    next_item: u32,
    index_position: u32,
    content_position: u32
}

struct PackIndexIteratorError {}

impl fmt::Display for ::PackFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackFile (encrypted index: {}, encrypted content: {}, padding: {}, timestamped files: {})", has_encrypted_index(&self.raw_data), has_encrypted_content(&self.raw_data), has_padding(&self.raw_data), has_index_with_timestamps(&self.raw_data))
    }
}

impl fmt::Display for ::PackedFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackedFile {{ timestamp: {:?}, name: \"{}\" }}", self.timestamp, self.name)
    }
}

impl<'a> IntoIterator for &'a ::PackFile {
    type Item = ::PackedFile;
    type IntoIter = PackIndexIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        let payload_position = if has_padding(&self.raw_data) {
            let unpadded = get_static_header_size(&self.raw_data) + get_extended_header_size(&self.raw_data) + get_index_size(&self.raw_data);
            let remainder = unpadded % 8;
            if remainder > 0 {
                unpadded + 8 - remainder
            } else {
                unpadded
            }
        } else {
            get_static_header_size(&self.raw_data) + get_extended_header_size(&self.raw_data) + get_index_size(&self.raw_data)
        };
        PackIndexIterator {
            raw_data: &self.raw_data,
            next_item: get_index_length(&self.raw_data),
            index_position: get_static_header_size(&self.raw_data) + get_extended_header_size(&self.raw_data),
            content_position: payload_position
        }
    }
}

fn get_preamble(raw_data: &[u8]) -> u32 {
    LittleEndian::read_u32(&raw_data[0x00..0x04])
}

fn get_bitmask(raw_data: &[u8]) -> u32 {
    LittleEndian::read_u32(&raw_data[0x04..0x08])
}

fn get_index_length(raw_data: &[u8]) -> u32 {
    LittleEndian::read_u32(&raw_data[0x10..0x14])
}

fn get_index_size(raw_data: &[u8]) -> u32 {
    LittleEndian::read_u32(&raw_data[0x14..0x18])
}

fn _get_signature_offset(raw_data: &[u8]) -> u32 {
    LittleEndian::read_u32(&raw_data[0x28..0x2C])
}

fn get_static_header_size(raw_data: &[u8]) -> u32 {
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

fn get_extended_header_size(raw_data: &[u8]) -> u32 {
    LittleEndian::read_u32(&raw_data[0x0C..0x10])
}

fn has_big_header(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & ::HAS_BIG_HEADER != 0
}

fn has_encrypted_index(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & ::INDEX_ENCRYPTED != 0
}

fn has_index_with_timestamps(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & ::HAS_INDEX_WITH_TIMESTAMPS != 0
}

fn has_encrypted_content(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & ::CONTENT_ENCRYPTED != 0
}

fn has_padding(raw_data: &[u8]) -> bool {
    if get_preamble(&raw_data) == ::PFH5_PREAMBLE && has_encrypted_content(&raw_data) {
        true
    } else {
        false
    }
}

impl<'a> PackIndexIterator<'a> {
    fn read_index_u32(&self) -> Result<u32, PackIndexIteratorError> {
        if self.raw_data.len() as u32 >= self.index_position + 4 {
            Ok(LittleEndian::read_u32(&self.raw_data[self.index_position as usize..(self.index_position + 4) as usize]))
        } else {
            Err(PackIndexIteratorError{})
        }
    }

    fn read_data_slice(&self, from: u32, size: u32) -> Result<&[u8], PackIndexIteratorError> {
        let to = from.checked_add(size).ok_or(PackIndexIteratorError{})?;
        if to <= self.raw_data.len() as u32 {
            Ok(&self.raw_data[from as usize..to as usize])
        } else {
            Err(PackIndexIteratorError{})
        }
    }

    fn read_content_slice(&self, size: u32) -> Result<&[u8], PackIndexIteratorError> {
        self.read_data_slice(self.content_position, size)
    }

    fn read_index_slice(&self, size: u32) -> Result<&[u8], PackIndexIteratorError> {
        self.read_data_slice(self.index_position, size)
    }

    fn get_next(&mut self) -> Result<::PackedFile, PackIndexIteratorError> {
        if self.next_item >= 1 {
            self.next_item -= 1;

            // read 4 bytes item length
            let mut item_length = self.read_index_u32()?;
            item_length = if has_encrypted_index(&self.raw_data) {
                ::crypto::decrypt_index_item_file_length(self.next_item, item_length)
            } else {
                item_length
            };
            self.index_position = self.index_position.checked_add(4).ok_or(PackIndexIteratorError{})?;

            // read 4 bytes whatever, if present
            let timestamp = if has_index_with_timestamps(&self.raw_data) {
                let d = self.read_index_u32()?;
                self.index_position = self.index_position.checked_add(4).ok_or(PackIndexIteratorError{})?;
                Some(d)
            } else {
                None
            };

            if get_preamble(&self.raw_data) == ::PFH5_PREAMBLE && !has_big_header(&self.raw_data) {
                self.index_position = self.index_position.checked_add(1).ok_or(PackIndexIteratorError{})?;
            }

            let remaining_index_size = get_index_size(&self.raw_data) - (self.index_position - get_static_header_size(&self.raw_data) - get_extended_header_size(&self.raw_data));
            let (file_path, len) = if has_encrypted_index(&self.raw_data) {
                ::crypto::decrypt_index_item_filename(self.read_index_slice(remaining_index_size)?,item_length as u8)
            } else {
                let mut  buf = vec!();
                let mut i = 0;
                loop {
                    let c = self.raw_data[(self.index_position + i) as usize];
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

            let padded_item_length = if has_encrypted_content(&self.raw_data) {
                let remainder = item_length % 8;
                if remainder > 0 {
                    item_length.checked_add(8-remainder).ok_or(PackIndexIteratorError{})?
                } else {
                    item_length
                }
            } else {
                item_length
            };

            let content = if has_encrypted_content(&self.raw_data) {
                ::crypto::decrypt_file(&self.read_content_slice(padded_item_length)?, item_length as usize, false)
            } else {
                self.read_content_slice(item_length)?.to_vec()
            };

            if has_padding(&self.raw_data) {
                self.content_position = self.content_position.checked_add(padded_item_length).ok_or(PackIndexIteratorError{})?;
            } else {
                self.content_position = self.content_position.checked_add(item_length).ok_or(PackIndexIteratorError{})?;
            }
            assert!(content.len() == item_length as usize, format!("{} != {}", content.len(), item_length));

            Ok(::PackedFile {
                timestamp: timestamp,
                name: String::from_utf8(file_path).map_err(|_| PackIndexIteratorError{})?,
                content: content
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

pub fn parse_pack<'a>(bytes: Vec<u8>) -> Result<::PackFile, ::ParsePackError> {
    if bytes.len() < 4 || bytes.len() < get_static_header_size(&bytes) as usize {
        return Err(::ParsePackError::InvalidFileError)
    }

    if bytes.len() < (get_static_header_size(&bytes) + get_extended_header_size(&bytes)) as usize {
        return Err(::ParsePackError::InvalidFileError)
    }

    if get_preamble(&bytes) !=  ::PFH5_PREAMBLE && get_preamble(&bytes) != ::PFH4_PREAMBLE {
        return Err(::ParsePackError::InvalidHeaderError)
    }

    Ok(::PackFile {
        raw_data: bytes
    })
}
