//! This module contains all error-related code of the library.

use std::io;
use std::result;
use cached_file_view::FileViewError;

/// Alias for handling errors more easely.
pub type Result<T> = result::Result<T, Error>;

/// This enum contains all the possible errors this library can return.
/// 
/// The possible variants, or error types are:
/// - `InvalidHeaderError`: Used for when the Header of the PackFile is not valid.
/// - `InvalidFileError`: Used for when the File we are trying to open is not a valid PackFile. 
/// - `IndexIteratorError`: Used when iterating through PackedFiles fails for any reason.
/// - `IOError`: Used for generic IO errors.
#[derive(Debug)]
pub enum Error {
    InvalidHeaderError,
    InvalidFileError,
    IndexIteratorError,
    IOError
}

//--------------------------------------------------------------------------------//
//                       From<T> Implementations for Error
//--------------------------------------------------------------------------------//
impl From<FileViewError> for Error {
    fn from(_: FileViewError) -> Self {
        Error::IOError
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::IOError
    }
}
