use std::num::Wrapping;
use std::ops::Range;
use std::vec::Vec;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;

static INDEX_KEY: &str = "L2{B3dPL7L*v&+Q3ZsusUhy[BGQn(Uq$f>JQdnvdlf{-K:>OssVDr#TlYU|13B}r";
fn get_key_at(pos: usize) -> u8 {
    INDEX_KEY.as_bytes()[pos % (INDEX_KEY.len())]
}

pub fn decrypt_index_item_file_length(item_index: u32, ciphertext: u32) -> u32 {
    let decrypted = item_index ^ ciphertext ^ 0x15091984;
    if ::DEBUG {
        println!("# {:X} = {:X} ^ {:X} ^ {:X}", decrypted, item_index, ciphertext, 0x15091984);
    }
    decrypted
}

pub fn decrypt_index_item_filename(ciphertext: &[u8], key: u8) -> (Vec<u8>, u32) {
    let mut buffer: Vec<u8> = Vec::with_capacity(100);
    let mut idx = 0;
    loop {
        let c = ciphertext[idx as usize] ^ key ^ get_key_at(idx);
        if ::DEBUG {
            println!("{:X} ({}) = {:X} ^ {:X} ^ {:X}", c, c as char, ciphertext[idx as usize], key, get_key_at(idx));
        }
        idx += 1;
        if c == 0 {
            break;
        }
        buffer.push(c);
    }
    (buffer, idx as u32)
}

static FILE_KEY: Wrapping<u64> = Wrapping(0x8FEB2A6740A6920E);

pub fn decrypt_file(ciphertext: &[u8], length: usize, verbose: bool) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let padded_length = ciphertext.len() + 7 & !7;
    assert!(padded_length % 8 == 0);
    assert!(padded_length < ciphertext.len() + 8);
    let mut edi: u32 = 0;
    let mut esi = 0;
    let mut eax;
    let mut edx;
    for _ in 0..padded_length/8 {
        // push 0x8FEB2A67
        // push 0x40A6920E
        // mov eax, edi
        // not eax
        // push 0
        // push eax
        // call multiply
        let prod = (FILE_KEY * Wrapping((!edi) as u64)).0;
        if verbose {
            println!("prod: {:X}", prod);
        }
        eax = prod as u32;
        edx = (prod >> 32) as u32;
        if verbose {
            println!("eax: {:X}", eax);
            println!("edx: {:X}", edx);
        }

        // xor eax, [ebx+esi]
        eax ^= read_padded_u32(&ciphertext, esi..esi + 4);
        if verbose {
            println!("eax: {:X}", eax);
        }

        // add edi, 8
        edi += 8;

        // xor edx, [ebx+esi+4]
        let _edx = read_padded_u32(&ciphertext, esi + 4..esi + 8);
        if verbose {
            println!("_edx {:X}", _edx);
        }
        edx ^= _edx;
        if verbose {
            println!("edx {:X}", edx);
        }

        // mov [esi], eax
        plaintext.write_u32::<LittleEndian>(eax).unwrap();

        // mov [esi+4], edx
        if verbose {
            println!("{:X}", edx);
        }
        plaintext.write_u32::<LittleEndian>(edx).unwrap();
        esi += 8;
    }
    plaintext.truncate(length);
    plaintext
}

fn read_padded_u32(source: &[u8], range: Range<usize>) -> u32 {
    if range.end <= source.len() {
        LittleEndian::read_u32(&source[range])
    } else {
        let mut v = Vec::with_capacity(4);
        if range.start < source.len() {
            v.extend_from_slice(&source[range.start..source.len()]);
        }
        v.resize(4, 0);
        debug_assert!(v.len() == 4);
        LittleEndian::read_u32(&v)
    }
}
