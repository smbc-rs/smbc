# smbc -- `libsmbclient` wrapper

[![Crates.io](https://img.shields.io/crates/v/smbc.svg)](https://crates.io/crates/smbc)
[![Build Status](https://travis-ci.org/smbc-rs/smbc.svg?branch=master)](https://travis-ci.org/smbc-rs/smbc)
[![Crates.io](https://img.shields.io/crates/l/smbc.svg)](https://crates.io/crates/smbc)
[![Docs](https://docs.rs/smbc/badge.svg)](https://docs.rs/smbc)
[![Gitter](https://img.shields.io/gitter/room/smbc-rs/general.svg)](https://gitter.im/smbc-rs/general)

## About

`smbc` is a type-safe wrapper library for `libsmbclient` from [Samba][samba] project.

It use [`smbclient-sys`][smbclient-sys] crate for bindings to `libsmbclient`.


## License

Licensed under [GNU General Public License][gpl] version 3 or any later version.
It can be found at [COPYING](COPYING) or at [GNU][gpl] site.


[gpl]: https://www.gnu.org/licenses/gpl.txt
[samba]: https://www.samba.org
[smbclient-sys]: https://crates.io/crates/smbclient-sys
