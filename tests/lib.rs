extern crate twa_pack_lib;

mod build;
mod parse;

use std::fs;
use std::fs::File;
use std::path::Path;

use twa_pack_lib::PackedFile;
use twa_pack_lib::PFHVersion;
use twa_pack_lib::PFHFileType;
use twa_pack_lib::PFHFlags;

#[test]
fn test_repack() {
    fs::copy("tests/twa_boot.pack.bk", "tests/repack_twa_boot.pack").unwrap();
    let f = File::open(Path::new("tests/repack_twa_boot.pack")).expect("file not found");
    let pack = twa_pack_lib::parse_pack(f).unwrap();
    let packed_files: Vec<PackedFile> = pack.into_iter().collect();

    for packed_file in &packed_files {
        println!("{:?}", packed_file.get_data().unwrap())
    }

    let mut f = File::create(Path::new("tests/repack_twa_boot.pack")).expect("cannot open file");
    twa_pack_lib::build_pack_from_memory(&packed_files,
        &mut f,
        PFHVersion::PFH5,
        PFHFlags::HAS_BIG_HEADER | PFHFlags::HAS_INDEX_WITH_TIMESTAMPS,
        PFHFileType::Boot,
        42).unwrap()

}
