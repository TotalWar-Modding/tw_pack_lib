extern crate tw_pack_lib;

mod build;
mod parse;

use std::fs;
use std::fs::File;
use std::path::Path;

use tw_pack_lib::PackedFile;
use tw_pack_lib::PFHVersion;
use tw_pack_lib::PFHFileType;
use tw_pack_lib::PFHFlags;

#[test]
fn test_repack() {
    fs::copy("tests/twa_boot.pack.bk", "tests/repack_twa_boot.pack").unwrap();
    let f = File::open(Path::new("tests/repack_twa_boot.pack")).expect("file not found");
    let pack = tw_pack_lib::parse_pack(f, true).unwrap();
    let mut packed_files: Vec<PackedFile> = pack.into_iter().collect();

    for packed_file in &packed_files {
        println!("{:?}", packed_file.get_data().unwrap())
    }

    let mut f = File::create(Path::new("tests/repack_twa_boot.pack")).expect("cannot open file");
    tw_pack_lib::build_pack_from_memory(&mut packed_files,
        &mut f,
        PFHVersion::PFH5,
        PFHFlags::HAS_BIG_HEADER | PFHFlags::HAS_INDEX_WITH_TIMESTAMPS,
        PFHFileType::Boot,
        42,
        &[]).unwrap()

}

#[test]
fn test_pack_file_index() {
    fs::copy("tests/test_pack_file_index.pack.bk", "tests/test_pack_file_index.pack").unwrap();
    let f = File::open(Path::new("tests/test_pack_file_index.pack")).expect("file not found");
    let pack = tw_pack_lib::parse_pack(f, true).unwrap();
    let pack_files = pack.get_pack_file_index();
    println!("{:?}", pack_files);
    let mut packed_files: Vec<PackedFile> = pack.into_iter().collect();

    for packed_file in &packed_files {
        println!("{:?}", packed_file.get_data().unwrap())
    }

    let mut f = File::create(Path::new("tests/test_pack_file_index_copy.pack")).expect("cannot open file");
    tw_pack_lib::build_pack_from_memory(&mut packed_files,
        &mut f,
        PFHVersion::PFH5,
        PFHFlags::empty(),
        PFHFileType::Boot,
        42,
        &pack_files).unwrap();

    let f = File::open(Path::new("tests/test_pack_file_index_copy.pack")).expect("file not found");
    let pack = tw_pack_lib::parse_pack(f, true).unwrap();
    let pack_files_copy = pack.get_pack_file_index();
    assert_eq!(pack_files, pack_files_copy);
}
