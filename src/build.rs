use std::borrow::Borrow;
use std::fs::File;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;

use byteorder::LittleEndian;
use byteorder::WriteBytesExt;

use error::Result;

fn traverse_directory(directory: &Path, prefix: &str) -> Result<Vec<::PackedFile>> {
    let mut files = vec!();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::metadata(&path)?;
        let relative_path = if !prefix.is_empty() {
            prefix.to_owned() + &"\\".to_owned() + &entry.file_name().into_string().unwrap()
        } else {
            entry.file_name().into_string().unwrap()
        };
        if metadata.is_dir() {
            let child_files = traverse_directory(&path, &relative_path)?;
            files.extend(child_files)
        } else if metadata.is_file() {
            let mut file = File::open(path)?;
            let mut buf = vec!();
            file.read_to_end(&mut buf)?;
            files.push(::PackedFile::new(None, relative_path, buf))
        }
    }
    Ok(files)
}

fn write_header<P: Borrow<::PackedFile>>(
    output_file: &mut File, 
    version: ::PFHVersion, 
    bitmask: ::PFHFlags, 
    file_type: ::PFHFileType, 
    pfh_timestamp: u32, 
    pack_files_index_size: u32, 
    packed_files_index_size: u32, 
    pack_files: &[String],
    packed_files: &Vec<P>
) -> Result<()> {

    output_file.write_u32::<LittleEndian>(version.get_preamble())?;
    output_file.write_u32::<LittleEndian>(bitmask.bits | file_type.get_value())?;
    output_file.write_u32::<LittleEndian>(pack_files.len() as u32)?; // PF Index Count
    output_file.write_u32::<LittleEndian>(pack_files_index_size)?; // PF Index Size
    output_file.write_u32::<LittleEndian>(packed_files.len() as u32)?;
    output_file.write_u32::<LittleEndian>(packed_files_index_size)?;
    match version {
        ::PFHVersion::PFH4  => {
            output_file.write_u32::<LittleEndian>(pfh_timestamp)?;
        },
        ::PFHVersion::PFH5 => {
            if bitmask.contains(::PFHFlags::HAS_BIG_HEADER) {
                output_file.write_u32::<LittleEndian>(0)?;
                output_file.write_u32::<LittleEndian>(0)?;
                output_file.write_u32::<LittleEndian>(0)?;
                output_file.write_u32::<LittleEndian>(0)?;
                output_file.write_u32::<LittleEndian>(0)?;
                output_file.write_u32::<LittleEndian>(0)?;
            } else {
                output_file.write_u32::<LittleEndian>(pfh_timestamp)?;
            }
        }
    }
    Ok(())
}
fn write_pack_file_index(output_file: &mut File, pack_files: &[String]) -> Result<()> {
    for pack_file in pack_files {
        output_file.write_all(pack_file.as_ref())?;
        output_file.write_u8(0)?;
    }
    Ok(())
}

fn write_packed_file_index<P: Borrow<::PackedFile>>(output_file: &mut File, files: &Vec<P>, version: ::PFHVersion, bitmask: ::PFHFlags) -> Result<()> {
    for file in files {
        let file = file.borrow();
        output_file.write_u32::<LittleEndian>(file.get_data()?.len() as u32)?;
        if bitmask.contains(::PFHFlags::HAS_INDEX_WITH_TIMESTAMPS) {
            output_file.write_u32::<LittleEndian>(file.timestamp.unwrap_or(0))?
        }

        if version == ::PFHVersion::PFH5 && !bitmask.contains(::PFHFlags::HAS_BIG_HEADER) {
            output_file.write_u8(0)?;
        }
        output_file.write_all(file.path.as_ref())?;
        output_file.write_u8(0)?;
    }
    Ok(())
}

fn write_content<P: Borrow<::PackedFile>>(output_file: &mut File, files: &Vec<P>) -> Result<()> {
    for file in files {
        output_file.write_all(&file.borrow().get_data()?)?;
    }
    Ok(())
}

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32, pack_files: &[String]) -> Result<()> {
    let mut input_files = traverse_directory(input_directory, "")?;
    build_pack_from_memory(pack_files, &mut input_files, output_file, version, bitmask, file_type, pfh_timestamp)
}

pub fn build_pack_from_memory<P: Borrow<::PackedFile>>(
    pack_files: &[String],
    packed_files: &mut Vec<P>,
    output_file: &mut File,
    version: ::PFHVersion,
    bitmask: ::PFHFlags,
    file_type: ::PFHFileType,
    pfh_timestamp: u32
) -> Result<()> {

    let mut pack_file_index_size = 0;
    for pack_file in pack_files {
        pack_file_index_size += pack_file.len() + 1;
    }

    let mut packed_file_index_size = 0;
    packed_files.sort_unstable_by(|a, b| a.borrow().path.cmp(&b.borrow().path));
    let packed_files = &*packed_files;
    for packed_file in packed_files {
        let packed_file: &::PackedFile = packed_file.borrow();
        packed_file_index_size += packed_file.path.len() as u32 + 1;
        packed_file_index_size += 4;
        if bitmask.contains(::PFHFlags::HAS_INDEX_WITH_TIMESTAMPS) {
            packed_file_index_size += 4;
        }
        if version == ::PFHVersion::PFH5 && !bitmask.contains(::PFHFlags::HAS_BIG_HEADER) {
            packed_file_index_size += 1;
        }
    }
    write_header(output_file, version, bitmask, file_type, pfh_timestamp, pack_file_index_size as u32, packed_file_index_size, pack_files, &packed_files)?;
    write_pack_file_index(output_file, pack_files)?;
    write_packed_file_index(output_file, packed_files, version, bitmask)?;
    write_content(output_file, packed_files)?;
    Ok(())
}
