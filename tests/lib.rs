extern crate twa_pack_lib;

use std::fs::File;
use std::io::Read;
use std::path::Path;

#[test]
fn test_read_header() {
    let mut f = File::open(Path::new("tests").join("boot.pack")).expect("file not found");
    let mut buf = vec!();
    f.read_to_end(&mut buf).unwrap();

    let pack = twa_pack_lib::parse_pack(buf);
    let index = pack.get_index();

    for item in index.into_iter() {
        println!("{:?}", item);
    }
}

