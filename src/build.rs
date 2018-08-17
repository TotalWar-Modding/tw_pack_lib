use std::io::Read;
use std::fs::File;
use std::fs;

use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use std::io;
use std::io::Write;
use std::path::Path;

impl From<io::Error> for ::BuildPackError {
    fn from(_: io::Error) -> Self {
        ::BuildPackError::IOError
    }
}

fn traverse_directory(directory: &Path, prefix: String) -> Result<Vec<::PackedFile>, ::BuildPackError> {
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
            files.push(::PackedFile {
                name: relative_path,
                timestamp: None,
                content: buf
            })
        }
    }
    Ok(files)
}

fn write_header(output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags, index_size: u32, files: &Vec<::PackedFile>) -> Result<(), ::BuildPackError> {
    output_file.write_u32::<LittleEndian>(version.get_preamble())?;
    output_file.write_u32::<LittleEndian>(bitmask.bits)?;
    output_file.write_u32::<LittleEndian>(0)?; // PF Index Count
    output_file.write_u32::<LittleEndian>(0)?; // PF Index Size
    output_file.write_u32::<LittleEndian>(files.len() as u32)?;
    output_file.write_u32::<LittleEndian>(index_size as u32)?;
    match version {
        ::PFHVersion::PFH4  => {
            output_file.write_u32::<LittleEndian>(0)?; // timestamp
        },
        ::PFHVersion::PFH5 => {
            output_file.write_u32::<LittleEndian>(0)?;
            output_file.write_u32::<LittleEndian>(0)?;
            output_file.write_u32::<LittleEndian>(0)?;
            output_file.write_u32::<LittleEndian>(0)?;
            output_file.write_u32::<LittleEndian>(0)?;
            output_file.write_u32::<LittleEndian>(0)?;
        }
    }
    Ok(())
}

fn write_index(output_file: &mut File, files: &Vec<::PackedFile>) -> Result<(), ::BuildPackError> {
    for file in files {
        output_file.write_u32::<LittleEndian>(file.content.len() as u32)?;
        output_file.write_all(file.name.as_ref())?;
        output_file.write_u8(0)?;
    }
    Ok(())
}

fn write_content(output_file: &mut File, files: &Vec<::PackedFile>) -> Result<(), ::BuildPackError> {
    for file in files {
        output_file.write_all(&file.content)?;
    }
    Ok(())
}

pub fn build_pack_from_filesystem(input_directory: &Path, output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags) -> Result<(), ::BuildPackError> {
    let input_files = traverse_directory(input_directory, "".to_string())?;
    if input_files.len() < 1 {
        return Err(::BuildPackError::EmptyInputError)
    }
    build_pack_from_memory(&input_files, output_file, version, bitmask)
}

pub fn build_pack_from_memory(input_files: &Vec<::PackedFile>, output_file: &mut File, version: ::PFHVersion, bitmask: ::PFHFlags) -> Result<(), ::BuildPackError> {
    if input_files.len() < 1 {
        return Err(::BuildPackError::EmptyInputError)
    }

    let mut index_size = 0;
    for input_file in input_files {
        index_size += input_file.name.len() as u32 + 1;
        index_size += 4;
        index_size += input_file.timestamp.unwrap_or(0);
    }
    write_header(output_file, version, bitmask, index_size, &input_files)?;
    write_index(output_file, input_files)?;
    write_content(output_file, input_files)?;
    Ok(())
}
