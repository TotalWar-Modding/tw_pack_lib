extern crate twa_pack_lib;

use std::fs::File;
use std::path::Path;

#[test]
fn test_build_pfh5_pack() {
    twa_pack_lib::build_pack_from_filesystem(&Path::new(&"tests/build/loadingscreen"),
                                             &mut File::create(Path::new("tests/build/loadingscreen_test.pack")).unwrap(),
                                             twa_pack_lib::PFHVersion::PFH5,
                                             0x0103).unwrap()
}
