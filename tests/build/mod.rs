extern crate twa_pack_lib;

use std::fs::File;
use std::path::Path;

use twa_pack_lib::PFHVersion;
use twa_pack_lib::PFHFlags;
use twa_pack_lib::PFHFileType;

#[test]
fn test_build_pfh5_pack() {
    twa_pack_lib::build_pack_from_filesystem(&Path::new(&"tests/build/loadingscreen"),
                                             &mut File::create(Path::new("tests/build/loadingscreen_test.pack")).unwrap(),
                                             &PFHVersion::PFH5,
                                             &(PFHFlags::HAS_BIG_HEADER),
                                             &PFHFileType::Mod).unwrap()
}
