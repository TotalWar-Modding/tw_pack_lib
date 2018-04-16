static KEY: &str = "L2{B3dPL7L*v&+Q3ZsusUhy[BGQn(Uq$f>JQdnvdlf{-K:>OssVDr#TlYU|13B}r";
pub fn get_key_at(pos: usize) -> u8 {
    KEY.as_bytes()[pos % KEY.len()]
}

pub fn decrypt_index_item_file_length(item_index: u32, ciphertext: u32) -> u32 {
    let decrypted = item_index ^ ciphertext ^ 0x15091984;
    if ::DEBUG {
        println!("# {:X} = {:X} ^ {:X} ^ {:X}", decrypted, item_index, ciphertext, 0x15091984);
    }
    decrypted
}

pub fn decrypt_index_item_filename(ciphertext: &[u8], key: u8) -> (Vec<u8>, usize){
    let mut buffer: Vec<u8> = Vec::with_capacity(100);
    let mut idx = 0;
    loop {
        let c = ciphertext[idx] ^ key ^ get_key_at(idx);
        if ::DEBUG {
            println!("{:X} ({}) = {:X} ^ {:X} ^ {:X}", c, c as char, buffer[idx], key, get_key_at(idx));
        }
        buffer.push(c);
        idx += 1;
        if c == 0 {
            break;
        }
    }
    (buffer, idx)
}

