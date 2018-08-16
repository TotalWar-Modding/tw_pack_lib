use std::io::Read;
use std::fs::File;
use std::fs;

use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use std::io;
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub enum BuildPackError {
    UnsupportedPFHVersionError,
    EmptyInputError,
    InputNotAFolderError,
    IOError
}

struct PackedFile {
    relative_path: String,
    data: Vec<u8>
}

impl From<io::Error> for BuildPackError {
    fn from(_: io::Error) -> Self {
        BuildPackError::IOError
    }
}

pub fn build_pack(input_directory: &Path, output_file: &mut File, version: u32, bitmask: u32) -> Result<(), BuildPackError> {
    if version != 4 && version != 5 {
        return Err(BuildPackError::UnsupportedPFHVersionError)
    }
    let (_content_size, index_size, files) = traverse_directory(input_directory, "".to_string())?;
    if files.len() < 1 {
        return Err(BuildPackError::EmptyInputError)
    }
    write_header(output_file, version, bitmask, index_size+4, &files)?;
    write_index(output_file, &files)?;
    write_content(output_file, &files)?;
    Ok(())
}

fn traverse_directory(directory: &Path, prefix: String) -> Result<(u32, u32, Vec<PackedFile>), BuildPackError> {
    let mut files = vec!();
    let mut content_size = 0;
    let mut index_size = 0;
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
            let (child_content_size, child_index_size, child_files) = traverse_directory(&path, relative_path)?;
            content_size += child_content_size;
            index_size += child_index_size;
            files.extend(child_files)
        } else if metadata.is_file() {
            let mut file = File::open(path)?;
            let mut buf = vec!();
            file.read_to_end(&mut buf)?;
            content_size += buf.len() as u32;
            index_size += relative_path.len() as u32 + 1;
            files.push(PackedFile {
                relative_path: relative_path,
                data: buf
            })
        }
    }
    Ok((content_size, index_size, files))
}

fn write_header(output_file: &mut File, version: u32, bitmask: u32, index_size: u32, files: &Vec<PackedFile>) -> Result<(), BuildPackError> {
    if version == 4 {
        output_file.write_u32::<LittleEndian>(::PFH4_PREAMBLE)?
        // TODO
    } else if version == 5 {
        output_file.write_u32::<LittleEndian>(::PFH5_PREAMBLE)?;
        output_file.write_u32::<LittleEndian>(bitmask)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(files.len() as u32)?;
        output_file.write_u32::<LittleEndian>(index_size as u32)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(0)?;
        output_file.write_u32::<LittleEndian>(0)?;
    } else {
        panic!();
    }
    Ok(())
}

fn write_index(output_file: &mut File, files: &Vec<PackedFile>) -> Result<(), BuildPackError> {
    for file in files {
        output_file.write_u32::<LittleEndian>(file.data.len() as u32)?;
        output_file.write_all(file.relative_path.as_ref())?;
        output_file.write_u8(0)?;
    }
    Ok(())
}

fn write_content(output_file: &mut File, files: &Vec<PackedFile>) -> Result<(), BuildPackError> {
    for file in files {
        output_file.write_all(&file.data)?;
    }
    Ok(())
}
