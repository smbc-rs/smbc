// smbc is library wrapping libsmbclient from Samba project
// Copyright (c) 2016 Konstantin Gribov
//
// This file is part of smbc.
//
// smbc is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// smbc is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with smbc. If not, see <http://www.gnu.org/licenses/>.

use std::error;
use std::ffi;
use std::fmt;
use std::io;
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    NewContext(io::Error),
    InitContext(io::Error),
    NulInPath(ffi::NulError),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NewContext(ref err) => write!(f, "New context error: {}", err),
            Error::InitContext(ref err) => write!(f, "Init context error: {}", err),
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::NulInPath(ref err) => write!(f, "NUL in path: {}", err),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::NewContext(ref err) => Some(err),
            Error::InitContext(ref err) => Some(err),
            Error::Io(ref err) => Some(err),
            Error::NulInPath(ref err) => Some(err),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<ffi::NulError> for Error {
    fn from(err: ffi::NulError) -> Self {
        Error::NulInPath(err)
    }
}
