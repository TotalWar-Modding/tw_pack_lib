static KEY: &str = "L2{B3dPL7L*v&+Q3ZsusUhy[BGQn(Uq$f>JQdnvdlf{-K:>OssVDr#TlYU|13B}r";
pub fn get_key_at(pos: u32) -> u8 {
    KEY.as_bytes()[(pos % (KEY.len() as u32)) as usize]
}

pub fn decrypt_index_item_file_length(item_index: u32, ciphertext: u32) -> u32 {
    let decrypted = item_index ^ ciphertext ^ 0x15091984;
    if ::DEBUG {
        println!("# {:X} = {:X} ^ {:X} ^ {:X}", decrypted, item_index, ciphertext, 0x15091984);
    }
    decrypted
}

pub fn decrypt_index_item_filename(ciphertext: &[u8], key: u8) -> (Vec<u8>, u32){
    let mut buffer: Vec<u8> = Vec::with_capacity(100);
    let mut idx: u32 = 0;
    loop {
        let c = ciphertext[idx as usize] ^ key ^ get_key_at(idx);
        buffer.push(c);
        if ::DEBUG {
            println!("{:X} ({}) = {:X} ^ {:X} ^ {:X}", c, c as char, buffer[idx as usize], key, get_key_at(idx));
        }
        idx += 1;
        if c == 0 {
            break;
        }
    }
    (buffer, idx)
}

