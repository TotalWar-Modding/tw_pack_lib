extern crate twa_pack_lib;

mod build;

use std::fs::File;
use std::io::Read;
use std::path::Path;

#[test]
fn test_read_header() {
    let mut f = File::open(Path::new("tests/parse/boot.pack")).expect("file not found");
    let mut buf = vec!();
    f.read_to_end(&mut buf).unwrap();

    let pack = twa_pack_lib::parse_pack(buf).unwrap();

    for item in pack.into_iter() {
        println!("{}", item);
    }
}
