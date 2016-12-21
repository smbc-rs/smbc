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

//! smbc is wrapper around `libsmbclient` from Samba project
//!
//! It provides basic `std::fs`-like API to access SMB/CIFS file shares
//!
//! Primary entrypoint is [`SmbClient`](struct.SmbClient.html) struct.
//!
//! Files are represented by [`SmbFile`](struct.SmbFile.html).
//!
//! Basic example:
//! ```rust
//! fn load
//! # fn main() {}
//! ```

//#![warn(missing_docs)]

#[macro_use]
extern crate log;
extern crate libc;

#[macro_use]
mod util;

/// Module with smbc's Result and Error coercions
pub mod result;

/// Main API module (reexported later)
pub mod smbc;

pub use result::*;
pub use smbc::*;
