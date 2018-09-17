use std::borrow::Borrow;
use std::fs::File;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;

use byteorder::LittleEndian;
use byteorder::WriteBytesExt;

use error::Result;

fn traverse_directory(directory: &Path, prefix: String) -> Result<Vec<::PackedFile>> {
    let mut files = vec!();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::metadata(&path)?;
        let relative_path = if prefix.len() > 0 {
            prefix.clone() + &"\\".to_string() + &entry.file_name().into_string().unwrap()
        } else {
            entry.file_name().into_string().unwrap()
        };
        if metadata.is_dir() {
            let child_files = traverse_directory(&path, relative_path)?;
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

fn write_header<P: Borrow<::PackedFile>>(output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32, index_size: u32, files: &Vec<P>) -> Result<()> {
    output_file.write_u32::<LittleEndian>(version.get_preamble())?;
    output_file.write_u32::<LittleEndian>(bitmask.bits | file_type.get_value())?;
    output_file.write_u32::<LittleEndian>(0)?; // PF Index Count
    output_file.write_u32::<LittleEndian>(0)?; // PF Index Size
    output_file.write_u32::<LittleEndian>(files.len() as u32)?;
    output_file.write_u32::<LittleEndian>(index_size)?;
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
        _ => unreachable!()
    }
    Ok(())
}

fn write_index<P: Borrow<::PackedFile>>(output_file: &mut File, files: &Vec<P>, version: ::PFHVersion, bitmask: ::PFHFlags) -> Result<()> {
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

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags, file_type: ::PFHFileType, pfh_timestamp: u32) -> Result<()> {
    let input_files = traverse_directory(input_directory, "".to_string())?;
    build_pack_from_memory(&input_files, output_file, version, bitmask, file_type, pfh_timestamp)
}

pub fn build_pack_from_memory<P: Borrow<::PackedFile>>(input_files: &Vec<P>, output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags,  file_type: ::PFHFileType, pfh_timestamp: u32) -> Result<()> {
    let mut index_size = 0;
    for input_file in input_files {
        let input_file = input_file.borrow();
        index_size += input_file.path.len() as u32 + 1;
        index_size += 4;
        if bitmask.contains(::PFHFlags::HAS_INDEX_WITH_TIMESTAMPS) {
            index_size += 4;
        }
        if version == ::PFHVersion::PFH5 && !bitmask.contains(::PFHFlags::HAS_BIG_HEADER) {
            index_size += 1;
        }
    }
    write_header(output_file, version, bitmask, file_type, pfh_timestamp, index_size, &input_files)?;
    write_index(output_file, input_files, version, bitmask)?;
    write_content(output_file, input_files)?;
    Ok(())
}
