extern crate byteorder;

use std::fmt;

use byteorder::LittleEndian;
use byteorder::ByteOrder;

mod crypto;

static DEBUG: bool = false;
static IS_ENCRYPTED: u32 = 1 << 7;
static HAS_INDEX_EXTRA_DWORD: u32 = 1 << 6;
static IS_PADDED: u32 = 1 << 4;

#[derive(Debug)]
pub struct PackFile {
    raw_data: Vec<u8>
}

#[derive(Debug)]
pub struct PackIndexIterator<'a> {
    raw_data: &'a [u8],
    next_item: u32,
    index_position: u32,
    payload_position: u32,
}

#[derive(Debug)]
pub struct PackedFile<'a> {
    pub extra_dword: Option<u32>,
    pub name: String,
    pub content: &'a [u8]
}

impl<'a> fmt::Display for PackedFile<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PackedFile {{ extra_dword: {:?}, name: \"{}\" }}", self.extra_dword, self.name)
    }
}

impl<'a> IntoIterator for &'a PackFile {
    type Item = PackedFile<'a>;
    type IntoIter = PackIndexIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        let payload_position = if is_padded(&self.raw_data) {
            let unpadded = get_header_size(&self.raw_data) + get_index_size(&self.raw_data);
            let remainder = unpadded % 8;
            if remainder > 0 {
                unpadded + 8 - remainder
            } else {
                unpadded
            }
        } else {
            get_header_size(&self.raw_data) + get_index_size(&self.raw_data)
        };
        println!("{}", is_padded(&self.raw_data));
        PackIndexIterator {
            raw_data: &self.raw_data,
            next_item: get_index_length(&self.raw_data),
            index_position: get_header_size(&self.raw_data),
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

fn get_header_size(_raw_data: &[u8]) -> u32 {
    0x30 //TODO
}

fn is_encrypted(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & IS_ENCRYPTED != 0
}

fn has_index_extra_dword(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & HAS_INDEX_EXTRA_DWORD != 0
}

fn is_padded(raw_data: &[u8]) -> bool {
    get_bitmask(&raw_data) & IS_PADDED != 0
}


impl<'a> Iterator for PackIndexIterator<'a> {
    type Item = PackedFile<'a>;
    fn next(&mut self) -> Option<PackedFile<'a>> {
        if self.next_item >= 1 {
            self.next_item -= 1;

            // read 4 bytes item length
            let mut item_length = LittleEndian::read_u32(&self.raw_data[self.index_position as usize..(self.index_position + 4) as usize]);
            item_length = if is_encrypted(&self.raw_data) {
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

            let (plaintext, len) = if is_encrypted(&self.raw_data) {
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
            if is_padded(&self.raw_data) {
                let remainder = self.payload_position % 8;
                if remainder > 0 {
                    self.payload_position += 8 - remainder
                }
            }

            Some(PackedFile {
                extra_dword: dword2,
                name: String::from_utf8(plaintext[..(len-1) as usize].to_vec()).unwrap(),
                content: &self.raw_data[current_payload_position as usize..(current_payload_position + item_length) as usize]
            })
        } else {
            None
        }
    }
}

pub fn parse_pack<'a>(bytes: Vec<u8>) -> PackFile {
    PackFile {
        raw_data: bytes
    }
}
