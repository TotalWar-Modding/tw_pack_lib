// This module is for helpers that doesn't fit in any of the other modules. 
extern crate chrono;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use self::chrono::Utc;

/// Get the current date and return it, as a decoded u32.
#[allow(dead_code)]
pub fn get_current_time() -> u32 {

    // Get the current time as an encoded i64 and turn it into u32.
    let mut date = vec![0;8];
    date.write_i64::<LittleEndian>(Utc::now().naive_utc().timestamp()).unwrap();
    date.truncate(4);
    LittleEndian::read_u32(&date)
}
