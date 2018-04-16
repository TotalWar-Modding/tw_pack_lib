extern crate byteorder;

use std::str;
use std::cmp::min;

use byteorder::LittleEndian;
use byteorder::ByteOrder;

mod crypto;

static DEBUG: bool = false;
static IS_ENCRYPTED: u32 = 1 << 7;
static HAS_EXTRA_DWORD: u32 = 1 << 6;

pub struct Pack {
    pub raw_data: Vec<u8>
}

#[derive(Debug)]
pub struct PackHeader<'a> {
    raw_data: &'a Vec<u8>
}

#[derive(Debug)]
pub struct PackIndex<'a> {
    pub raw_data: &'a [u8],
    pub length: u32,
    pub is_encrypted: bool,
    pub has_extra_word: bool
}

#[derive(Debug)]
pub struct PackIndexItem {
    pub item_length: u32,
    pub dword2: Option<u32>,
    pub name: String
}

pub struct PackIndexIterator<'a> {
    raw_data: &'a [u8],
    iterator_item_index: u32,
    iterator_position: usize,
    is_encrypted: bool,
    has_extra_word: bool
}


impl Pack {
    pub fn get_header(&self) -> PackHeader {
        PackHeader::new(&self.raw_data)
    }
    pub fn get_index(&self) -> PackIndex {
        PackIndex::new(&self.raw_data[self.get_index_start()..self.get_index_start()+self.get_header().get_index_size() as usize],
                       self.get_header().get_index_length(),
                       (self.get_header().get_bitmask() & IS_ENCRYPTED) != 0,
                       (self.get_header().get_bitmask() & HAS_EXTRA_DWORD) != 0)
    }

    fn get_index_start(&self) -> usize {
        0x30 //TODO
    }
}

impl<'a> PackHeader<'a> {
    pub fn new(raw_data: &'a Vec<u8>) -> PackHeader {
        PackHeader {
            raw_data: raw_data
        }
    }

    pub fn get_pack_id(&self) -> &str {
        str::from_utf8(&self.raw_data[0x0..0x4]).unwrap()
    }

    pub fn get_bitmask(&self) -> u32 {
        LittleEndian::read_u32(&self.raw_data[0x04..0x08])
    }

    pub fn get_has_header_extension(&self) -> u32 {
        LittleEndian::read_u32(&self.raw_data[0x08..0x0C])
    }

    pub fn get_header_extension_size(&self) -> u32 {
        LittleEndian::read_u32(&self.raw_data[0x0C..0x10])
    }

    pub fn get_index_length(&self) -> u32 {
        LittleEndian::read_u32(&self.raw_data[0x10..0x14])
    }

    pub fn get_payload_offset(&self) -> u32 {
        LittleEndian::read_u32(&self.raw_data[0x14..0x18])
    }

    pub fn get_index_size(&self) -> u32 {
        LittleEndian::read_u32(&self.raw_data[0x28..0x2C])
    }

    pub fn get_header_size(&self) -> u32 {
        0x30 //TODO
    }
}

impl<'a> PackIndex<'a> {
    fn new(raw_data: &'a [u8], length: u32, is_encrypted: bool, has_extra_dword: bool) -> PackIndex {
        PackIndex {
            raw_data: raw_data,
            length: length,
            is_encrypted: is_encrypted,
            has_extra_word: has_extra_dword
        }
    }
}

impl<'a> IntoIterator for &'a PackIndex<'a> {
    type Item = PackIndexItem;
    type IntoIter = PackIndexIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        PackIndexIterator {
            raw_data: self.raw_data,
            iterator_position: 0,
            iterator_item_index: self.length,
            is_encrypted: self.is_encrypted,
            has_extra_word: self.has_extra_word
        }
    }
}

impl<'a> Iterator for PackIndexIterator<'a> {
    type Item = PackIndexItem;
    fn next(&mut self) -> Option<PackIndexItem> {
        if self.iterator_item_index >= 1 {
            self.iterator_item_index -= 1;
            let number_of_bytes_to_be_read: usize = 0x1C4;

            // read 4 bytes item length
            let mut item_length = LittleEndian::read_u32(&self.raw_data[self.iterator_position..self.iterator_position + 4]);
            item_length = if self.is_encrypted {
                crypto::decrypt_index_item_file_length(self.iterator_item_index, item_length)
            } else {
                item_length
            };
            self.iterator_position += 4;

            // read 4 bytes whatever, if present
            let dword2 = if self.has_extra_word {
                let d = LittleEndian::read_u32(&self.raw_data[self.iterator_position..self.iterator_position + 4]);
                self.iterator_position += 4;
                Some(d)
            } else {
                None
            };

            let source_size = number_of_bytes_to_be_read + self.iterator_position;
            //println!("source_size 0x{:X}", source_size);

            let from = self.iterator_position;
            let to = min(self.iterator_position + source_size, self.raw_data.len());
            //println!("decrypting from {:X} to {:X}", from, to);
            let (plaintext, len) = crypto::decrypt_index_item_filename(&self.raw_data[from..to],item_length as u8);
            self.iterator_position += len;

            Some(PackIndexItem {
                item_length: item_length,
                dword2: dword2,
                name: String::from_utf8(plaintext[..len-1].to_vec()).unwrap()
            })
        } else {
            None
        }
    }
}

pub fn parse_pack(bytes: Vec<u8>) -> Pack {
    Pack {
        raw_data: bytes
    }
}

