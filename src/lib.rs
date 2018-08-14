extern crate byteorder;

use std::fmt;

use byteorder::LittleEndian;
use byteorder::ByteOrder;

mod crypto;

static DEBUG: bool = false;
static INDEX_ENCRYPTED: u32 = 1 << 7;
static HAS_INDEX_EXTRA_DWORD: u32 = 1 << 6;
static CONTENT_ENCRYPTED: u32 = 1 << 4;

#[derive(Debug)]
pub struct PackFile {
    raw_data: Vec<u8>
}

#[derive(Debug)]
pub struct PackIndexIterator<'a> {
    raw_data: &'a [u8],
    next_item: u32,
    index_position: u32,
    payload_position: u32
}

#[derive(Debug)]
pub struct PackedFile {
    pub extra_dword: Option<u32>,
    pub name: String,
    pub content: Vec<u8>
}

#[derive(Debug)]
pub enum PackLibError {
    InvalidHeaderError,
    FileTooSmallError
}

impl fmt::Display for PackFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackFile (encrypted index: {}, padded payload: {})", has_encrypted_index(&self.raw_data), has_encrypted_content(&self.raw_data))
    }
}

impl fmt::Display for PackedFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackedFile {{ extra_dword: {:?}, name: \"{}\" }}", self.extra_dword, self.name)
    }
}

impl<'a> IntoIterator for &'a PackFile {
    type Item = Result<PackedFile, PackLibError>;
    type IntoIter = PackIndexIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        let payload_position = if has_encrypted_content(&self.raw_data) {
            let unpadded = get_minimum_header_size() + get_index_size(&self.raw_data);
            let remainder = unpadded % 8;
            if remainder > 0 {
                unpadded + 8 - remainder
            } else {
                unpadded
            }
        } else {
            get_minimum_header_size() + get_index_size(&self.raw_data)
        };
        PackIndexIterator {
            raw_data: &self.raw_data,
            next_item: get_index_length(&self.raw_data),
            index_position: get_minimum_header_size(),
            payload_position: payload_position
        }
    }
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

fn get_minimum_header_size() -> u32 {
    0x30
}

fn has_encrypted_index(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & INDEX_ENCRYPTED != 0
}

fn has_index_extra_dword(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & HAS_INDEX_EXTRA_DWORD != 0
}

fn has_encrypted_content(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & CONTENT_ENCRYPTED != 0
}


impl<'a> Iterator for PackIndexIterator<'a> {
    type Item = Result<PackedFile, PackLibError>;
    fn next(&mut self) -> Option<Result<PackedFile, PackLibError>> {
        if self.next_item >= 1 {
            self.next_item -= 1;

            // read 4 bytes item length
            let mut item_length = LittleEndian::read_u32(&self.raw_data[self.index_position as usize..(self.index_position + 4) as usize]);
            item_length = if has_encrypted_index(&self.raw_data) {
                crypto::decrypt_index_item_file_length(self.next_item, item_length)
            } else {
                item_length
            };
            self.index_position += 4;

            // read 4 bytes whatever, if present
            let dword2 = if has_index_extra_dword(&self.raw_data) {
                let d = LittleEndian::read_u32(&self.raw_data[self.index_position as usize..(self.index_position + 4) as usize]);
                self.index_position += 4;
                Some(d)
            } else {
                None
            };

            let from = self.index_position;
            let to = self.raw_data.len();

            let (plaintext, len) = if has_encrypted_index(&self.raw_data) {
                crypto::decrypt_index_item_filename(&self.raw_data[from as usize..to],item_length as u8)
            } else {
                let mut  buf = vec!();
                let mut i = 0;
                loop {
                    let c = self.raw_data[(from + i) as usize];
                    buf.push(c);
                    i += 1;
                    if c == 0 {
                        break;
                    }
                }
                (buf, i)
            };

            self.index_position += len;
            let current_payload_position = self.payload_position;
            self.payload_position += item_length;
            if has_encrypted_content(&self.raw_data) {
                let remainder = self.payload_position % 8;
                if remainder > 0 {
                    self.payload_position += 8 - remainder
                }
            }

            let content = if has_encrypted_content(&self.raw_data) {
                crypto::decrypt_file(&self.raw_data[current_payload_position as usize..(current_payload_position + item_length) as usize], item_length as usize, false)
            } else {
                self.raw_data[current_payload_position as usize..(current_payload_position + item_length) as usize].to_vec()
            };

            Some(Ok(PackedFile {
                extra_dword: dword2,
                name: String::from_utf8(plaintext[..(len-1) as usize].to_vec()).unwrap(),
                content: content
            }))
        } else {
            None
        }
    }
}

pub fn parse_pack<'a>(bytes: Vec<u8>) -> Result<PackFile, PackLibError> {
    if bytes.len() < get_minimum_header_size() as usize {
        return Err(PackLibError::FileTooSmallError)
    }

    if LittleEndian::read_u32(&bytes[0..4]) != 0x35484650 {
        return Err(PackLibError::InvalidHeaderError)
    }

    Ok(PackFile {
        raw_data: bytes
    })
}
