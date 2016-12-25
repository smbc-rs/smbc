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

//! `smbc` is wrapper library around `libsmbclient` from Samba project.

// imports {{{1
use std::default::Default;
use std::io;
use std::mem;
use std::panic;
use std::ptr;

use std::borrow::Cow;
use std::io::{Read, Write, Seek, SeekFrom};

use libc::{self, c_char, c_int, c_void, mode_t, off_t};

use smbclient_sys::*;
use util::*;
use result::Result;
// 1}}}

const SMBC_FALSE: smbc_bool = 0;
const SMBC_TRUE: smbc_bool = 1;

// types {{{1
// {{{2
/// ## Basic info
///
/// `SmbClient` is primary struct in *smbc*.
///
/// It wraps and manages `libsmbclient`s `SMBCCTX *`
/// and provides an entry point for all interaction with `SMB` shares.
///
/// When `SmbClient` is obtained it can be used to:
///
/// * open files in different modes (see
///   [`open_with(..)` method family](struct.SmbClient.html#method.open_with)
///   and [`SmbFile` examples](struct.SmbFile.html#examples))
/// * create and delete directories (see
///   [`create_dir(..)`](struct.SmbClient.html#method.create_dir)/
///   [`remove_dir(..)`](struct.SmbClient.html#method.remove_dor))
///
/// ## Examples
///
/// ```rust
/// # use std::borrow::Cow;
/// #
/// # fn main() {}
/// #
/// # fn example() -> smbc::Result<()> {
///     let password = "Pa$$w0rd1!".to_owned();
///
///     let password_ref: &str = &password;
///     let auth = move |host: &str, share: &str| {
///         (Cow::Borrowed("WORKGROUP"), Cow::Borrowed("test"), Cow::Borrowed(password_ref))
///     };
///     let client = try!(smbc::SmbClient::new(&auth));
///
/// #   Ok(())
/// # }
/// ```
///
// 2}}}
pub struct SmbClient<'a> {
    ctx: *mut SMBCCTX,
    #[allow(dead_code)]
    auth_fn: &'a for<'b> Fn(&'b str, &'b str) -> (Cow<'a, str>, Cow<'a, str>, Cow<'a, str>),
}

// {{{2
/// ## Basic info
///
/// `SmbFile` is representation of currently open file.
///
/// It corresponds to `libsmbclient`'s `SMBCFILE *`.
///
/// ## Examples
///
/// See also [`SmbClient`'s examples](struct.SmbClient.html#)
/// to find out how to initialize `SmbClient`.
///
/// ```rust
/// # use std::borrow::Cow;
/// # use std::io::{Read, Write, Seek};
/// #
/// # fn main() {}
/// #
/// fn get_content(file: &mut smbc::SmbFile) -> smbc::Result<String> {
///     let mut buffer = String::new();
///     try!(file.read_to_string(&mut buffer));
///     Ok(buffer)
/// }
///
/// fn example() -> smbc::Result<()> {
///     // ...snip...
/// # let password = "Pa$$w0rd1";
/// # let auth = move |host: &str, share: &str| {
/// #    (Cow::Borrowed("WORKGROUP"), Cow::Borrowed("test"), Cow::Borrowed(password))
/// # };
///     let client = try!(smbc::SmbClient::new(&auth));
///     let mut file = try!(client.open("smb://127.0.0.1/share/path/to/file"));
///     println!("dumped file:\n\n{}", try!(get_content(&mut file)));
///     Ok(())
/// }
/// ```
// 2}}}
pub struct SmbFile<'a: 'b, 'b> {
    smbc: &'b SmbClient<'a>,
    fd: *mut SMBCFILE,
}
// 1}}}

/// Default (dummy) credential `WORKGROUP\guest` with empty password
const DEF_CRED: (Cow<'static, str>, Cow<'static, str>, Cow<'static, str>) = (Cow::Borrowed("WORKGROUP"), Cow::Borrowed("guest"), Cow::Borrowed(""));

// SmbClient {{{1
impl<'a> SmbClient<'a> {
    // {{{2
    /// Creates new `SmbClient` given auth function.
    ///
    /// `auth_fn` receives two callback parameters:
    ///
    /// * `server` -- server for which auth is requested
    /// * `share` -- share for which auth is requested
    ///
    /// Should *return* tuple `(workgroup, username, password)` as a result.
    pub fn new<F>(auth_fn: &'a F) -> Result<SmbClient<'a>>
        where F: for<'b> Fn(&'b str, &'b str) -> (Cow<'a, str>, Cow<'a, str>, Cow<'a, str>) {
        let mut smbc = SmbClient {
            ctx: ptr::null_mut(),
            auth_fn: auth_fn,
        };

        unsafe {
            let ctx = try!(result_from_ptr_mut(smbc_new_context()));

            smbc_setOptionUserData(ctx, auth_fn as *const _ as *mut c_void);
            smbc_setFunctionAuthDataWithContext(ctx, Some(Self::auth_wrapper::<F>));

            smbc_setOptionOneSharePerServer(ctx, SMBC_TRUE);

            smbc_setOptionDebugToStderr(ctx, SMBC_TRUE);
            //smbc_setDebug(ctx, 10);

            smbc.ctx = try!(result_from_ptr_mut(smbc_init_context(ctx)));
        }

        trace!(target: "smbc", "new smbclient");
        Ok(smbc)
    }

    /// Auth wrapper passed to `SMBCCTX` to authenticate requests to SMB servers.
    extern "C" fn auth_wrapper<F: 'a>(ctx: *mut SMBCCTX,
                                             srv: *const c_char,
                                             shr: *const c_char,
                                             wg: *mut c_char,
                                             wglen: c_int,
                                             un: *mut c_char,
                                             unlen: c_int,
                                             pw: *mut c_char,
                                             pwlen: c_int)
                                             -> ()
        where F: for<'b> Fn(&'b str, &'b str) -> (Cow<'a, str>, Cow<'a, str>, Cow<'a, str>) {
        unsafe {
            let srv = cstr(srv);
            let shr = cstr(shr);
            trace!(target: "smbc", "authenticating on {}\\{}", &srv, &shr);

            let auth: &'a F = mem::transmute(smbc_getOptionUserData(ctx) as *const c_void);
            let auth = panic::AssertUnwindSafe(auth);
            let r = panic::catch_unwind(|| {
                trace!(target: "smbc", "auth with {:?}\\{:?}", srv, shr);
                auth(&srv, &shr)
            });
            let (workgroup, username, password) = r.unwrap_or(DEF_CRED);
            trace!(target: "smbc", "cred: {}\\{} {}", &workgroup, &username, &password);
            write_to_cstr(wg as *mut u8, wglen as usize, &workgroup);
            write_to_cstr(un as *mut u8, unlen as usize, &username);
            write_to_cstr(pw as *mut u8, pwlen as usize, &password);
        }
        ()
    }

    /// Opens [`SmbFile`](struct.SmbFile.html) defined by SMB `path` with `options`.
    ///
    /// See [OpenOptions](struct.OpenOptions.html).
    pub fn open_with<'b, P: AsRef<str>>(&'b self,
                                        path: P,
                                        options: OpenOptions)
                                        -> Result<SmbFile<'a, 'b>> {
        trace!(target: "smbc", "open_with {:?}", options);

        let open_fn = try_ufn!(smbc_getFunctionOpen <- self);

        let path = try!(cstring(path));
        trace!(target: "smbc", "opening {:?} with {:?}", path, open_fn);

        unsafe {
            let fd = try!(result_from_ptr_mut(open_fn(self.ctx,
                                                      path.as_ptr(),
                                                      try!(options.to_flags()),
                                                      options.mode)));
            if (fd as i64) < 0 {
                trace!(target: "smbc", "neg fd");
            }
            Ok(SmbFile {
                smbc: &self,
                fd: fd,
            })
        }
    }

    /// Open read-only [`SmbFile`](struct.SmbFile.html) defined by SMB `path`.
    ///
    /// Alias for [`open_ro(..)`](struct.SmbClient.html#method.open_ro).
    pub fn open<'b, P: AsRef<str>>(&'b self, path: P) -> Result<SmbFile<'a, 'b>> {
        self.open_ro(path)
    }

    /// Open write-only [`SmbFile`](struct.SmbFile.html) defined by SMB `path`.
    ///
    /// If file doesn't exists it will be created.
    /// If file exists it will be truncated.
    ///
    /// Alias for [`open_wo(..)`](struct.SmbClient.html#method.open_wo).
    pub fn create<'b, P: AsRef<str>>(&'b self, path: P) -> Result<SmbFile<'a, 'b>> {
        self.open_wo(path)
    }

    /// Open read-only [`SmbFile`](struct.SmbFile.html) defined by SMB `path`.
    ///
    /// See [`open_with(..)`](struct.SmbClient.html#method.open_with).
    pub fn open_ro<'b, P: AsRef<str>>(&'b self, path: P) -> Result<SmbFile<'a, 'b>> {
        self.open_with(path, OpenOptions::default())
    }

    /// Open write-only [`SmbFile`](struct.SmbFile.html) defined by SMB `path`.
    ///
    /// If file doesn't exists it will be created.
    /// If file exists it will be truncated.
    ///
    /// See [`open_with(..)`](struct.SmbClient.html#method.open_with).
    pub fn open_wo<'b, P: AsRef<str>>(&'b self, path: P) -> Result<SmbFile<'a, 'b>> {
        self.open_with(path, OpenOptions::default().read(false).write(true).create(true).truncate(true))
    }

    /// Open read-write [`SmbFile`](struct.SmbFile.html) defined by SMB `path`.
    ///
    /// If file doesn't exists it will be created.
    ///
    /// See [`open_with(..)`](struct.SmbClient.html#method.open_with).
    pub fn open_rw<'b, P: AsRef<str>>(&'b self, path: P) -> Result<SmbFile<'a, 'b>> {
        self.open_with(path, OpenOptions::default().read(true).write(true).create(true))
    }

    #[doc(hidden)]
    /// Get metadata for file at `path`
    pub fn metadata<P: AsRef<str>>(&self, path: P) -> Result<()> {
        let stat_fn = try_ufn!(smbc_getFunctionStat <- self);
        let path = try!(cstring(path));

        unimplemented!();
    }

    /// Create new directory at SMB `path`
    pub fn create_dir<P: AsRef<str>>(&self, path: P) -> Result<()> {
        let mkdir_fn = try_ufn!(smbc_getFunctionMkdir <- self);
        let path = try!(cstring(path));
        try!(to_result_with_le(unsafe { mkdir_fn(self.ctx, path.as_ptr(), 0o755) }));
        Ok(())
    }

    //    pub fn create_dir_all<P: AsRef<str>>(&self, path: P) -> Result<()> {
    //        unimplemented!();
    //    }

    /// Delete directory at SMB `path`.
    ///
    /// Directory should be empty to delete it.
    pub fn remove_dir<P: AsRef<str>>(&self, path: P) -> Result<()> {
        let rmdir_fn = try_ufn!(smbc_getFunctionRmdir <- self);
        let path = try!(cstring(path));
        try!(to_result_with_le(unsafe { rmdir_fn(self.ctx, path.as_ptr()) }));
        Ok(())
    }
} // 2}}}

impl<'a> Drop for SmbClient<'a> {
    // {{{2
    /// Destroy `SmbClient` and close all connections.
    fn drop(&mut self) {
        trace!(target: "smbc", "closing smbclient");
        unsafe {
            smbc_free_context(self.ctx, 1 as c_int);
        }
    }
} // 2}}}
// 1}}}

// OpenOptions {{{1
/// Describes options for opening file:
///
/// * `read` if readable;
/// * `write` if writable;
/// * `flags` is *bitwise OR* of `O_CREAT`, `O_EXCL` and `O_TRUNC`;
/// * `mode` for *POSIX* file mode.
#[derive(Clone, Copy, Debug)]
pub struct OpenOptions {
    flags: c_int,
    read: bool,
    write: bool,
    mode: mode_t,
}

impl OpenOptions {
    // {{{2
    /// Allows reading file (set by default).
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Allows writing to file.
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Allows appending to file.
    pub fn append(mut self, append: bool) -> Self {
        self.flag(libc::O_APPEND, append);
        self
    }

    /// Allows creating file if it doesn't exists.
    ///
    /// Opening file will fail in case file exists if
    /// [`exclusive`](struct.OpenOptions.html#method.exclusive)
    /// also set.
    pub fn create(mut self, create: bool) -> Self {
        self.flag(libc::O_CREAT, create);
        self
    }

    /// File will be truncated (size set to `0`)
    /// if it's already exists.
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.flag(libc::O_TRUNC, truncate);
        self
    }

    /// `open_*` will fail if file already exists
    /// (when used with `create` also set).
    ///
    /// See [`create`](struct.OpenOptions.html#method.create)
    pub fn exclusive(mut self, exclusive: bool) -> Self {
        self.flag(libc::O_EXCL, exclusive);
        self
    }

    /// Set POSIX file mode
    pub fn mode(mut self, mode: mode_t) -> Self {
        self.mode = mode;
        self
    }

    fn flag(&mut self, flag: c_int, on: bool) {
        if on {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    /// Naive impl, rewrite to check for incompatible flags
    fn to_flags(&self) -> Result<c_int> {
        let base_mode = match (self.read, self.write) {
            // defaults to read only
            (false, false) |
            (true, false) => libc::O_RDONLY,
            (false, true) => libc::O_WRONLY,
            (true, true) => libc::O_RDWR,
        };
        Ok(base_mode | self.flags)
    }
} // }}}
// 1}}}

impl Default for OpenOptions {
    /// Default [`OpenOptions`](struct.OpenOptions.html) is
    /// read-only with POSIX perms `0644`
    /// (`rw` for owner, `r` for group and others).
    fn default() -> OpenOptions {
        OpenOptions {
            flags: 0,
            read: true,
            write: false,
            mode: 0o644,
        }
    }
}

// SmbFile {{{1
impl<'a, 'b> SmbFile<'a, 'b> {
    // {{{2
} // }}}

impl<'a, 'b> Read for SmbFile<'a, 'b> {
    // {{{2
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        trace!(target: "smbc", "reading file to buf [{:?};{}]", buf.as_ptr(), buf.len());
        let read_fn = try_ufn!(smbc_getFunctionRead <- self.smbc);
        let bytes_read = try!(to_result_with_le(unsafe {
            read_fn(self.smbc.ctx,
                    self.fd,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as _)
        }));
        Ok(bytes_read as usize)
    }
} // }}}

impl<'a, 'b> Write for SmbFile<'a, 'b> {
    // {{{2
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        trace!(target: "smbc", "writing buf [{:?};{}] to file", buf.as_ptr(), buf.len());
        let write_fn = try_ufn!(smbc_getFunctionWrite <- self.smbc);
        let bytes_wrote = try!(to_result_with_le(unsafe {
            write_fn(self.smbc.ctx,
                     self.fd,
                     buf.as_ptr() as *const c_void,
                     buf.len() as _)
        }));
        Ok(bytes_wrote as usize)
    }

    /// Do nothing for SmbFile
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
} // }}}

impl<'a, 'b> Seek for SmbFile<'a, 'b> {
    // {{{2
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        trace!(target: "smbc", "seeking file {:?}", pos);
        let lseek_fn = try_ufn!(smbc_getFunctionLseek <- self.smbc);
        let (whence, off) = match pos {
            SeekFrom::Start(p) => (libc::SEEK_SET, p as off_t),
            SeekFrom::End(p) => (libc::SEEK_END, p as off_t),
            SeekFrom::Current(p) => (libc::SEEK_CUR, p as off_t),
        };
        let res = try!(to_result_with_errno(unsafe { lseek_fn(self.smbc.ctx, self.fd, off, whence) }, libc::EINVAL));
        Ok(res as u64)
    }
} // }}}

impl<'a, 'b> Drop for SmbFile<'a, 'b> {
    // {{{2
    fn drop(&mut self) {
        trace!(target: "smbc", "closing file");
        unsafe {
            smbc_getFunctionClose(self.smbc.ctx).map(|f| f(self.smbc.ctx, self.fd));
        }
    }
} // }}}
// 1}}}

// vim: fen:fdm=marker:fdl=1:
