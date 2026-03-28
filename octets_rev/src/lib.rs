// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Zero-copy abstraction for parsing and constructing network packets.
//!
//! This crate provides a set of types for safely and efficiently reading from
//! and writing to byte buffers. It is designed to be used in performance-critical
//! applications like network protocol implementations, where minimizing copies
//! is essential.
//!
//! It supports both classical left-to-right (forward) processing and right-to-left
//! (backward) processing.
//!
//! # Examples
//!
//! Reading from a buffer:
//! ```
//! use octets_rev::Octets;
//!
//! let data = [0x01, 0x00, 0x42, 0x05, b'h', b'e', b'l', b'l', b'o'];
//! let mut b = Octets::with_slice(&data);
//!
//! assert_eq!(b.get_u8(), Ok(1));
//! assert_eq!(b.get_u16(), Ok(0x0042));
//!
//! let mut sub = b.get_bytes_with_u8_length().unwrap();
//! assert_eq!(sub.as_ref(), b"hello");
//! ```
//!
//! # Forward and Backward Processing
//!
//! This crate supports both forward and backward processing of buffers.
//! `Octets` and `OctetsMut` operate from the beginning of the buffer towards the end.
//! `OctetsRev` and `OctetsMutRev` operate from the end of the buffer towards the beginning.
//!
//! This is particularly useful for protocols that define fields relative to the end of a packet
//! or when building a packet from both ends to avoid moving data.
//!
//! ```
//! use octets_rev::{OctetsMut, OctetsMutRev, Octets, OctetsRev};
//!
//! let mut data = [0; 10];
//!
//! // Write 0x01 at the beginning
//! {
//!     let mut b = OctetsMut::with_slice(&mut data);
//!     b.put_u8(0x01).unwrap();
//! }
//!
//! // Write 0xFE at the end
//! {
//!     let mut b = OctetsMutRev::with_slice(&mut data);
//!     b.put_u8(0xFE).unwrap();
//! }
//!
//! assert_eq!(data[0], 0x01);
//! assert_eq!(data[9], 0xFE);
//!
//! // Read them back
//! let mut forward = Octets::with_slice(&data);
//! assert_eq!(forward.get_u8(), Ok(0x01));
//!
//! let mut backward = OctetsRev::with_slice(&data);
//! assert_eq!(backward.get_u8(), Ok(0xFE));
//! ```
//!
//! # Generic Processing with Traits
//!
//! By using the [`OctetsRead`] and [`OctetsWrite`] traits, you can write
//! generic code that works identically for both forward and backward buffers.
//! This is possible because `OctetsRev` and `OctetsMutRev` ensure that "reading
//! the next integer" always moves the cursor in the "natural" direction for
//! that buffer.
//!
//! If a protocol defines a sequence of fields (e.g., [Type, ID]), the same
//! generic function can parse these fields whether they are stored at the
//! beginning of the packet (processed forward) or at the end of the packet
//! (processed backward).
//!
//! ```
//! use octets_rev::{OctetsRead, Octets, OctetsRev, Result};
//!
//! struct Frame {
//!     ty: u8,
//!     id: u16,
//! }
//!
//! impl Frame {
//!     /// This code is oblivious to whether R is forward or backward.
//!     /// It just reads the "next" fields in the defined logical order.
//!     fn parse<R: OctetsRead>(r: &mut R) -> Result<Self> {
//!         let ty = r.get_u8()?;
//!         let id = r.get_u16()?;
//!         Ok(Frame { ty, id })
//!     }
//! }
//!
//! // Forward processing: Type=1, ID=0x0042.
//! // Data is physically [0x01, 0x00, 0x42].
//! {
//!     let data = [0x01, 0x00, 0x42];
//!     let mut forward = Octets::with_slice(&data);
//!     let f_frame = Frame::parse(&mut forward).unwrap();
//!     assert_eq!(f_frame.ty, 0x01);
//!     assert_eq!(f_frame.id, 0x0042);
//! }
//!
//! // Backward processing: Type=1, ID=0x0042.
//! // Data is physically [0x00, 0x42, 0x01] because OctetsRev reads from the end.
//! {
//!     let data = [0x00, 0x42, 0x01];
//!     let mut backward = OctetsRev::with_slice(&data);
//!     let b_frame = Frame::parse(&mut backward).unwrap();
//!     assert_eq!(b_frame.ty, 0x01);
//!     assert_eq!(b_frame.id, 0x0042);
//! }
//! ```

use branches::unlikely;
/// Zero-copy abstraction for parsing and constructing network packets.
use std::mem;
use std::ops::Deref;
use std::ptr;

/// A specialized [`Result`] type for buffer operations.
pub type Result<T> = std::result::Result<T, BufferError>;

/// An error indicating that a buffer operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferError {
    /// The provided buffer is not big enough to complete the operation.
    BufferTooShortError,

    /// The buffer contains invalid data according to the protocol rules.
    BufferProtocolError,
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BufferError::BufferTooShortError => write!(f, "BufferTooShortError"),
            BufferError::BufferProtocolError => write!(f, "BufferProtocolError"),
        }
    }
}

impl std::error::Error for BufferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

macro_rules! peek_u {
    ($b:expr, $ty:ty, $len:expr) => {{
        let len = $len;
        let src = &$b.buf[$b.off..];
        if src.len() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let mut out: $ty = 0;
        unsafe {
            let dst = &mut out as *mut $ty as *mut u8;
            let off = (mem::size_of::<$ty>() - len) as isize;
            ptr::copy_nonoverlapping(src.as_ptr(), dst.offset(off), len);
        };
        Ok(<$ty>::from_be(out))
    }};
}

macro_rules! peek_u_buflen_guaranteed {
    ($b:expr, $ty:ty , $len:expr) => {{
        let len = $len;
        let src = &$b.buf[$b.off..];
        let mut out: $ty = 0;
        unsafe {
            let dst = &mut out as *mut $ty as *mut u8;
            let off = (mem::size_of::<$ty>() - len) as isize;
            ptr::copy_nonoverlapping(src.as_ptr(), dst.offset(off), len);
        };
        Ok(<$ty>::from_be(out))
    }};
}

macro_rules! get_u {
    ($b:expr, $ty:ty, $len:expr) => {{
        let out = peek_u!($b, $ty, $len);
        $b.off += $len;
        out
    }};
}

macro_rules! peek_u_reverse {
    ($b:expr, $ty:ty , $len:expr) => {{
        if unlikely($b.off < $len) {
            return Err(BufferError::BufferProtocolError);
        } else {
            $b.off -= $len;
            let out = peek_u_buflen_guaranteed!($b, $ty, $len);
            $b.off += $len;
            return out;
        }
    }};
}

/// The set of [..]() functions uses this macro to read the buffer
/// in the reverse direction, from the end to the beginning, like reading
/// a Manga.
///
/// For example, we start at offset = buf.len(); then rewind 1 byte to read 1
/// byte. The buffer offset keeps moving backward while reading information with
/// the set of [..]() functions.
macro_rules! get_u_reverse {
    ($b:expr, $ty:ty, $len:expr) => {{
        if unlikely($b.off < $len) {
            return Err(BufferError::BufferProtocolError);
        } else {
            $b.off -= $len;
            let out = peek_u_buflen_guaranteed!($b, $ty, $len);
            return out;
        }
    }};
}

macro_rules! put_u_reverse {
    ($b:expr, $ty:ty, $v:expr, $len:expr) => {{
        let len = $len;
        if $b.off < len {
            return Err(BufferError::BufferTooShortError);
        }
        $b.off -= len;
        let v = $v;
        let dst = &mut $b.buf[$b.off..($b.off + len)];
        unsafe {
            let src = &<$ty>::to_be(v) as *const $ty as *const u8;
            let off = (std::mem::size_of::<$ty>() - len) as isize;
            std::ptr::copy_nonoverlapping(src.offset(off), dst.as_mut_ptr(), len);
        }
        Ok(dst)
    }};
}

macro_rules! put_u {
    ($b:expr, $ty:ty, $v:expr, $len:expr) => {{
        let len = $len;
        if $b.buf.len() < $b.off + len {
            return Err(BufferError::BufferTooShortError);
        }
        let v = $v;
        let dst = &mut $b.buf[$b.off..($b.off + len)];
        unsafe {
            let src = &<$ty>::to_be(v) as *const $ty as *const u8;
            let off = (mem::size_of::<$ty>() - len) as isize;
            ptr::copy_nonoverlapping(src.offset(off), dst.as_mut_ptr(), len);
        }
        $b.off += $len;
        Ok(dst)
    }};
}

/// A zero-copy immutable byte buffer.
///
/// `Octets` wraps an in-memory buffer of bytes and provides utility functions
/// for manipulating it. The underlying buffer is provided by the user and is
/// not copied when creating an `Octets`. Operations are panic-free and will
/// avoid indexing the buffer past its end.
///
/// Additionally, an offset (initially set to the start of the buffer) is
/// incremented as bytes are read from / written to the buffer, to allow for
/// sequential operations.
#[derive(Debug, PartialEq, Eq)]
pub struct Octets<'a> {
    buf: &'a [u8],
    off: usize,
}
impl<'a> Octets<'a> {
    /// Creates an `Octets` from the given slice, without copying.
    ///
    /// Since the `Octets` is immutable, the input slice needs to be
    /// immutable.
    pub fn with_slice(buf: &'a [u8]) -> Self {
        Octets { buf, off: 0 }
    }

    /// Reads an unsigned 8-bit integer from the current offset and advances
    /// the buffer.
    pub fn get_u8(&mut self) -> Result<u8> {
        get_u!(self, u8, 1)
    }

    /// Reads an unsigned 8-bit integer from the current offset without
    /// advancing the buffer.
    pub fn peek_u8(&mut self) -> Result<u8> {
        peek_u!(self, u8, 1)
    }

    /// Reads an unsigned 16-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u16(&mut self) -> Result<u16> {
        get_u!(self, u16, 2)
    }

    /// Reads an unsigned 24-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u24(&mut self) -> Result<u32> {
        get_u!(self, u32, 3)
    }

    /// Reads an unsigned 32-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u32(&mut self) -> Result<u32> {
        get_u!(self, u32, 4)
    }

    /// Reads an unsigned 64-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u64(&mut self) -> Result<u64> {
        get_u!(self, u64, 8)
    }

    /// Reads an unsigned variable-length integer in network byte-order from
    /// the current offset and advances the buffer.
    pub fn get_varint(&mut self) -> Result<u64> {
        let first = self.peek_u8()?;
        let len = varint_parse_len(first);
        if len > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        let out = match len {
            1 => u64::from(self.get_u8()? & 0x3f),
            2 => u64::from(self.get_u16()? & 0x3fff),
            4 => u64::from(self.get_u32()? & 0x3fffffff),
            8 => self.get_u64()? & 0x3fffffffffffffff,
            _ => unreachable!(),
        };
        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer.
    pub fn get_bytes(&mut self, len: usize) -> Result<Octets<'a>> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };
        self.off += len;
        Ok(out)
    }

    /// Reads `len` + 1 bytes from the current offset without copying and
    /// advances the buffer, where `len` is an unsigned 8-bit integer
    /// prefix.
    pub fn get_bytes_with_u8_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 16-bit integer prefix in network
    /// byte-order.
    pub fn get_bytes_with_u16_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned variable-length integer prefix
    /// in network byte-order.
    pub fn get_bytes_with_varint_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes(&self, len: usize) -> Result<Octets<'a>> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };
        Ok(out)
    }

    /// Returns a slice of `len` elements from the current offset.
    pub fn slice(&self, len: usize) -> Result<&'a [u8]> {
        if len > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        Ok(&self.buf[self.off..self.off + len])
    }

    /// Returns a slice of `len` elements from the end of the buffer.
    pub fn slice_last(&self, len: usize) -> Result<&'a [u8]> {
        if len > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        let cap = self.cap();
        Ok(&self.buf[cap - len..])
    }

    /// Advances the buffer's offset.
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        if skip > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        self.off += skip;
        Ok(())
    }

    pub fn rewind(&mut self, rewind: usize) -> Result<()> {
        if rewind > self.off {
            return Err(BufferError::BufferTooShortError);
        }
        self.off -= rewind;
        Ok(())
    }

    /// Returns the remaining capacity in the buffer.
    pub fn cap(&self) -> usize {
        self.buf.len() - self.off
    }

    /// Returns the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns a reference to the internal buffer.
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl<'a> AsRef<[u8]> for Octets<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

impl<'a> Deref for Octets<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

/// A zero-copy mutable byte buffer.
///
/// Like `Octets` but mutable.
#[derive(Debug, PartialEq, Eq)]
pub struct OctetsMut<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> OctetsMut<'a> {
    /// Creates an `OctetsMut` from the given slice, without copying.
    ///
    /// Since there's no copy, the input slice needs to be mutable to allow
    /// modifications.
    pub fn with_slice(buf: &'a mut [u8]) -> Self {
        OctetsMut { buf, off: 0 }
    }

    /// Reads an unsigned 8-bit integer from the current offset and advances
    /// the buffer.
    pub fn get_u8(&mut self) -> Result<u8> {
        get_u!(self, u8, 1)
    }

    /// Reads an unsigned 8-bit integer from the current offset without
    /// advancing the buffer.
    pub fn peek_u8(&mut self) -> Result<u8> {
        peek_u!(self, u8, 1)
    }

    /// Writes an unsigned 8-bit integer at the current offset and advances
    /// the buffer.
    pub fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        put_u!(self, u8, v, 1)
    }

    /// Reads an unsigned 16-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u16(&mut self) -> Result<u16> {
        get_u!(self, u16, 2)
    }

    /// Writes an unsigned 16-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        put_u!(self, u16, v, 2)
    }

    /// Reads an unsigned 24-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u24(&mut self) -> Result<u32> {
        get_u!(self, u32, 3)
    }

    /// Writes an unsigned 24-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u24(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u!(self, u32, v, 3)
    }

    /// Reads an unsigned 32-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u32(&mut self) -> Result<u32> {
        get_u!(self, u32, 4)
    }

    /// Writes an unsigned 32-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u!(self, u32, v, 4)
    }

    /// Reads an unsigned 64-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u64(&mut self) -> Result<u64> {
        get_u!(self, u64, 8)
    }

    /// Writes an unsigned 64-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        put_u!(self, u64, v, 8)
    }

    /// Reads an unsigned variable-length integer in network byte-order from
    /// the current offset and advances the buffer.
    pub fn get_varint(&mut self) -> Result<u64> {
        let first = self.peek_u8()?;
        let len = varint_parse_len(first);
        if len > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        let out = match len {
            1 => u64::from(self.get_u8()?),
            2 => u64::from(self.get_u16()? & 0x3fff),
            4 => u64::from(self.get_u32()? & 0x3fffffff),
            8 => self.get_u64()? & 0x3fffffffffffffff,
            _ => unreachable!(),
        };
        Ok(out)
    }

    /// Writes an unsigned variable-length integer in network byte-order at the
    /// current offset and advances the buffer.
    pub fn put_varint(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_varint_with_len(v, varint_len(v))
    }

    /// Writes an unsigned variable-length integer of the specified length, in
    /// network byte-order at the current offset and advances the buffer.
    pub fn put_varint_with_len(
        &mut self, v: u64, len: usize,
    ) -> Result<&mut [u8]> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let buf = match len {
            1 => self.put_u8(v as u8)?,
            2 => {
                let buf = self.put_u16(v as u16)?;
                buf[0] |= 0x40;
                buf
            },
            4 => {
                let buf = self.put_u32(v as u32)?;
                buf[0] |= 0x80;
                buf
            },
            8 => {
                let buf = self.put_u64(v)?;
                buf[0] |= 0xc0;
                buf
            },
            _ => panic!("BUG: value is too large for varint"),
        };
        Ok(buf)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer.
    pub fn get_bytes(&mut self, len: usize) -> Result<Octets<'_>> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };
        self.off += len;
        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer.
    pub fn get_bytes_mut(&mut self, len: usize) -> Result<OctetsMut<'_>> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let out = OctetsMut {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };
        self.off += len;
        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 8-bit integer prefix.
    pub fn get_bytes_with_u8_length(&mut self) -> Result<Octets<'_>> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 16-bit integer prefix in network
    /// byte-order.
    pub fn get_bytes_with_u16_length(&mut self) -> Result<Octets<'_>> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }
    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned variable-length integer prefix
    /// in network byte-order.
    pub fn get_bytes_with_varint_length(&mut self) -> Result<Octets<'_>> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes(&mut self, len: usize) -> Result<Octets<'_>> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };
        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes_mut(&mut self, len: usize) -> Result<OctetsMut<'_>> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let out = OctetsMut {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };
        Ok(out)
    }

    /// Writes `len` bytes to the current offset by copy offset and advances the buffer.
    pub fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        let len = v.len();
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        if len == 0 {
            return Ok(());
        }
        self.as_mut()[..len].copy_from_slice(v);
        self.off += len;
        Ok(())
    }

    /// Splits the buffer in two at the given absolute offset.
    pub fn split_at(
        &mut self, off: usize,
    ) -> Result<(OctetsMut<'_>, OctetsMut<'_>)> {
        if self.len() < off {
            return Err(BufferError::BufferTooShortError);
        }
        let (left, right) = self.buf.split_at_mut(off);
        let first = OctetsMut { buf: left, off: 0 };
        let last = OctetsMut { buf: right, off: 0 };
        Ok((first, last))
    }

    /// Returns a slice of `len` elements from the current offset.
    pub fn slice(&'a mut self, len: usize) -> Result<&'a mut [u8]> {
        if len > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        Ok(&mut self.buf[self.off..self.off + len])
    }

    /// Returns a slice of `len` elements from the end of the buffer.
    pub fn slice_last(&'a mut self, len: usize) -> Result<&'a mut [u8]> {
        if len > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        let cap = self.cap();
        Ok(&mut self.buf[cap - len..])
    }

    /// Advances the buffer's offset.
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        if skip > self.cap() {
            return Err(BufferError::BufferTooShortError);
        }
        self.off += skip;
        Ok(())
    }

    /// Rewinds the buffer's offset.
    pub fn rewind(&mut self, rewind: usize) -> Result<()> {
        if rewind > self.off {
            return Err(BufferError::BufferTooShortError);
        }
        self.off -= rewind;
        Ok(())
    }

    /// Returns the remaining capacity in the buffer.
    pub fn cap(&self) -> usize {
        self.buf.len() - self.off
    }

    /// Returns the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns a reference to the internal buffer.
    pub fn buf(&self) -> &[u8] {
        self.buf
    }

    pub fn buf_mut(&mut self) -> &mut [u8] {
        self.buf
    }

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl<'a> AsRef<[u8]> for OctetsMut<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

impl<'a> AsMut<[u8]> for OctetsMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..]
    }
}

/// Returns how many bytes it would take to encode `v` as a variable-length
/// integer in network byte-order.
pub const fn varint_len(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16383 {
        2
    } else if v <= 1_073_741_823 {
        4
    } else if v <= 4_611_686_018_427_387_903 {
        8
    } else {
        unreachable!()
    }
}

/// Returns how long the variable-length integer is, given its first byte.
pub const fn varint_parse_len(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    }
}

/// Returns how long the variable-length integer is, given its last byte,
/// when reading in reverse.
pub const fn varint_parse_len_reverse(last: u8) -> usize {
    match last & !0xfc {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    }
}

/// A trait for reading from a byte buffer.
pub trait OctetsRead {
    /// The type of bytes returned by `get_bytes` and related functions.
    type Bytes: AsRef<[u8]>;

    /// Reads an unsigned 8-bit integer and advances the buffer.
    fn get_u8(&mut self) -> Result<u8>;

    /// Reads an unsigned 16-bit integer in network byte-order and advances the buffer.
    fn get_u16(&mut self) -> Result<u16>;

    /// Reads an unsigned 24-bit integer in network byte-order and advances the buffer.
    fn get_u24(&mut self) -> Result<u32>;

    /// Reads an unsigned 32-bit integer in network byte-order and advances the buffer.
    fn get_u32(&mut self) -> Result<u32>;

    /// Reads an unsigned 64-bit integer in network byte-order and advances the buffer.
    fn get_u64(&mut self) -> Result<u64>;

    /// Reads an unsigned variable-length integer in network byte-order and advances the buffer.
    fn get_varint(&mut self) -> Result<u64>;

    /// Reads `len` bytes without copying and advances the buffer.
    fn get_bytes(&mut self, len: usize) -> Result<Self::Bytes>;

    /// Reads `len` + 1 bytes without copying and advances the buffer, where `len` is an
    /// unsigned 8-bit integer prefix.
    fn get_bytes_with_u8_length(&mut self) -> Result<Self::Bytes>;

    /// Reads `len` + 2 bytes without copying and advances the buffer, where `len` is an
    /// unsigned 16-bit integer prefix in network byte-order.
    fn get_bytes_with_u16_length(&mut self) -> Result<Self::Bytes>;

    /// Reads `len` + varint bytes without copying and advances the buffer, where `len` is an
    /// unsigned variable-length integer prefix in network byte-order.
    fn get_bytes_with_varint_length(&mut self) -> Result<Self::Bytes>;

    /// Reads an unsigned 8-bit integer without advancing the buffer.
    fn peek_u8(&mut self) -> Result<u8>;

    /// Reads `len` bytes without copying and without advancing the buffer.
    fn peek_bytes(&mut self, len: usize) -> Result<Self::Bytes>;

    /// Advances the buffer's offset.
    fn skip(&mut self, skip: usize) -> Result<()>;

    /// Rewinds the buffer's offset.
    fn rewind(&mut self, rewind: usize) -> Result<()>;

    /// Returns the remaining capacity in the buffer.
    fn cap(&self) -> usize;

    /// Returns the total length of the buffer.
    fn len(&self) -> usize;

    /// Returns `true` if the buffer is empty.
    fn is_empty(&self) -> bool;

    /// Returns the current offset of the buffer.
    fn off(&self) -> usize;

    /// Returns a reference to the internal buffer.
    fn buf(&self) -> &[u8];

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    fn to_vec(&self) -> Vec<u8>;
}

/// A trait for writing to a byte buffer.
pub trait OctetsWrite {
    /// Writes an unsigned variable-length integer in network byte-order and advances the buffer.
    fn put_varint(&mut self, v: u64) -> Result<&mut [u8]>;

    /// Writes an unsigned variable-length integer of the specified length in network byte-order
    /// and advances the buffer.
    fn put_varint_with_len(&mut self, v: u64, len: usize) -> Result<&mut [u8]>;

    /// Writes an unsigned 8-bit integer and advances the buffer.
    fn put_u8(&mut self, v: u8) -> Result<&mut [u8]>;

    /// Writes an unsigned 16-bit integer in network byte-order and advances the buffer.
    fn put_u16(&mut self, v: u16) -> Result<&mut [u8]>;

    /// Writes an unsigned 24-bit integer in network byte-order and advances the buffer.
    fn put_u24(&mut self, v: u32) -> Result<&mut [u8]>;

    /// Writes an unsigned 32-bit integer in network byte-order and advances the buffer.
    fn put_u32(&mut self, v: u32) -> Result<&mut [u8]>;

    /// Writes an unsigned 64-bit integer in network byte-order and advances the buffer.
    fn put_u64(&mut self, v: u64) -> Result<&mut [u8]>;

    /// Writes `v.len()` bytes by copying and advances the buffer.
    fn put_bytes(&mut self, v: &[u8]) -> Result<()>;

    /// Advances the buffer's offset.
    fn skip(&mut self, skip: usize) -> Result<()>;

    /// Rewinds the buffer's offset.
    fn rewind(&mut self, rewind: usize) -> Result<()>;

    /// Returns the remaining capacity in the buffer.
    fn cap(&self) -> usize;

    /// Returns the total length of the buffer.
    fn len(&self) -> usize;

    /// Returns `true` if the buffer is empty.
    fn is_empty(&self) -> bool;

    /// Returns the current offset of the buffer.
    fn off(&self) -> usize;

    /// Returns a reference to the internal buffer.
    fn buf(&self) -> &[u8];

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    fn to_vec(&self) -> Vec<u8>;
}

/// A zero-copy immutable byte buffer for backward processing.
///
/// `OctetsRev` is similar to `Octets`, but it operates from the end of the buffer
/// towards the beginning. The cursor (offset) initially points to the end of the
/// buffer and moves backwards as data is read.
///
/// For each `get_u*` or `get_varint` operation, the offset is first decreased
/// by the size of the integer, and then the value is read from that new offset.
#[derive(Debug, PartialEq, Eq)]
pub struct OctetsRev<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> OctetsRev<'a> {
    /// Creates an `OctetsRev` from the given slice, pointing the cursor at the
    /// end of the slice.
    pub fn with_slice(buf: &'a [u8]) -> Self {
        OctetsRev {
            buf,
            off: buf.len(),
        }
    }

    /// Reads an unsigned 8-bit integer by first decreasing the offset by 1
    /// and then reading at that offset.
    pub fn get_u8(&mut self) -> Result<u8> {
        get_u_reverse!(self, u8, 1);
    }

    /// Reads an unsigned 8-bit integer from the current offset without
    /// rewinding the buffer.
    pub fn peek_u8(&mut self) -> Result<u8> {
        peek_u_reverse!(self, u8, 1)
    }

    /// Reads an unsigned 16-bit integer in network byte-order by first
    /// decreasing the offset by 2 and then reading at that offset.
    pub fn get_u16(&mut self) -> Result<u16> {
        get_u_reverse!(self, u16, 2)
    }

    /// Reads an unsigned 24-bit integer in network byte-order by first
    /// decreasing the offset by 3 and then reading at that offset.
    pub fn get_u24(&mut self) -> Result<u32> {
        get_u_reverse!(self, u32, 3)
    }

    /// Reads an unsigned 32-bit integer in network byte-order by first
    /// decreasing the offset by 4 and then reading at that offset.
    pub fn get_u32(&mut self) -> Result<u32> {
        get_u_reverse!(self, u32, 4)
    }

    /// Reads an unsigned 64-bit integer in network byte-order by first
    /// decreasing the offset by 8 and then reading at that offset.
    pub fn get_u64(&mut self) -> Result<u64> {
        get_u_reverse!(self, u64, 8)
    }

    /// Reads an unsigned variable-length integer in network byte-order by
    /// first decreasing the offset by the integer's length and then reading
    /// at that offset.
    ///
    /// In reversed buffers, variable-length integers have their length indicator
    /// bits (the 2 most significant bits) in the "first" byte in the backward
    /// direction (which is the last byte in forward direction).
    pub fn get_varint(&mut self) -> Result<u64> {
        if unlikely(self.off == 0) {
            Err(BufferError::BufferProtocolError)
        } else {
            let last = self.peek_u8()?;
            let len = varint_parse_len_reverse(last);
            let out = match len {
                1 => u64::from(self.get_u8()? >> 2),
                2 => u64::from(self.get_u16()? >> 2),
                4 => u64::from(self.get_u32()? >> 2),
                8 => self.get_u64()? >> 2,
                _ => unreachable!(),
            };
            Ok(out)
        }
    }

    /// Reads `len` bytes from the current offset (moving backwards) without
    /// copying. The offset is decreased by `len`. The returned `Octets`
    /// is forward-oriented.
    pub fn get_bytes(&mut self, len: usize) -> Result<Octets<'a>> {
        if unlikely(self.off < len) {
            Err(BufferError::BufferProtocolError)
        } else {
            self.off -= len;
            let out = Octets {
                buf: &self.buf[self.off..self.off + len],
                off: 0,
            };
            Ok(out)
        }
    }

    /// Reads `len` + 1 bytes from the current offset (moving backwards) without
    /// copying, where `len` is an unsigned 8-bit integer prefix.
    pub fn get_bytes_with_u8_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` + 2 bytes from the current offset (moving backwards) without
    /// copying, where `len` is an unsigned 16-bit integer prefix.
    pub fn get_bytes_with_u16_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` + varint bytes from the current offset (moving backwards)
    /// without copying, where `len` is an unsigned variable-length integer prefix.
    pub fn get_bytes_with_varint_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    /// Advances the buffer's offset, moving it towards the beginning (lower values).
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        if self.off < skip {
            return Err(BufferError::BufferTooShortError);
        }
        self.off -= skip;
        Ok(())
    }

    /// Rewinds the buffer's offset, moving it towards the end (higher values).
    pub fn rewind(&mut self, rewind: usize) -> Result<()> {
        if rewind > self.buf.len() - self.off {
            return Err(BufferError::BufferTooShortError);
        }
        self.off += rewind;
        Ok(())
    }

    /// Returns the remaining capacity in the buffer (bytes before the cursor).
    pub fn cap(&self) -> usize {
        self.off
    }

    /// Returns the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns a reference to the internal buffer.
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl<'a> AsRef<[u8]> for OctetsRev<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.off]
    }
}

impl<'a> std::ops::Deref for OctetsRev<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[..self.off]
    }
}

impl<'a> From<Octets<'a>> for OctetsRev<'a> {
    /// Convert from forward to backward direction
    fn from(value: Octets<'a>) -> Self {
        OctetsRev {
            buf: value.buf,
            off: value.off,
        }
    }
}

impl<'a> From<OctetsRev<'a>> for Octets<'a> {
    /// Convert from backward to forward direction
    fn from(value: OctetsRev<'a>) -> Self {
        Octets {
            buf: value.buf,
            off: value.off,
        }
    }
}

/// A zero-copy mutable byte buffer for backward processing.
///
/// `OctetsMutRev` is the mutable version of `OctetsRev`. It operates from the
/// end of the buffer towards the beginning.
///
/// For each `put_u*` or `put_varint` operation, the offset is first decreased
/// by the size of the integer, and then the value is written at that new offset.
#[derive(Debug, PartialEq, Eq)]
pub struct OctetsMutRev<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> OctetsMutRev<'a> {
    /// Creates an `OctetsMutRev` from the given slice, pointing the cursor at
    /// the end of the slice.
    pub fn with_slice(buf: &'a mut [u8]) -> Self {
        let len = buf.len();
        OctetsMutRev { buf, off: len }
    }

    /// Writes an unsigned 8-bit integer by first decreasing the offset by 1
    /// and then writing at that offset.
    pub fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        put_u_reverse!(self, u8, v, 1)
    }

    /// Writes an unsigned 16-bit integer in network byte-order by first
    /// decreasing the offset by 2 and then writing at that offset.
    pub fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        put_u_reverse!(self, u16, v, 2)
    }

    /// Writes an unsigned 24-bit integer in network byte-order by first
    /// decreasing the offset by 3 and then writing at that offset.
    pub fn put_u24(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u_reverse!(self, u32, v, 3)
    }

    /// Writes an unsigned 32-bit integer in network byte-order by first
    /// decreasing the offset by 4 and then writing at that offset.
    pub fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u_reverse!(self, u32, v, 4)
    }

    /// Writes an unsigned 64-bit integer in network byte-order by first
    /// decreasing the offset by 8 and then writing at that offset.
    pub fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        put_u_reverse!(self, u64, v, 8)
    }

    /// Writes an unsigned variable-length integer in network byte-order by
    /// first decreasing the offset by the integer's length and then writing
    /// at that offset.
    #[inline]
    pub fn put_varint(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_varint_with_len(v, varint_len(v))
    }

    /// Writes an unsigned variable-length integer of the specified length in
    /// network byte-order by first decreasing the offset by `len` and then
    /// writing at that offset.
    #[inline]
    pub fn put_varint_with_len(
        &mut self, v: u64, len: usize,
    ) -> Result<&mut [u8]> {
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        let buf = match len {
            1 => self.put_u8((v << 2) as u8)?,
            2 => {
                let buf = self.put_u16((v << 2) as u16)?;
                buf[1] |= 0x1;
                buf
            },
            4 => {
                let buf = self.put_u32((v << 2) as u32)?;
                buf[3] |= 0x2;
                buf
            },
            8 => {
                let buf = self.put_u64(v << 2)?;
                buf[7] |= 0x3;
                buf
            },
            _ => unimplemented!(),
        };
        Ok(buf)
    }

    /// Writes `v.len()` bytes by copying them at the current offset (moving
    /// backwards). The offset is decreased by `v.len()`.
    pub fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        let len = v.len();
        if self.cap() < len {
            return Err(BufferError::BufferTooShortError);
        }
        if len == 0 {
            return Ok(());
        }
        self.off -= len;
        self.buf[self.off..self.off + len].copy_from_slice(v);
        Ok(())
    }

    /// Advances the buffer's offset, moving it towards the beginning (lower values).
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        if self.off < skip {
            return Err(BufferError::BufferTooShortError);
        }
        self.off -= skip;
        Ok(())
    }

    /// Rewinds the buffer's offset, moving it towards the end (higher values).
    pub fn rewind(&mut self, rewind: usize) -> Result<()> {
        if rewind > self.buf.len() - self.off {
            return Err(BufferError::BufferTooShortError);
        }
        self.off += rewind;
        Ok(())
    }

    /// Returns the remaining capacity in the buffer (bytes before the cursor).
    pub fn cap(&self) -> usize {
        self.off
    }

    /// Returns the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns a reference to the internal buffer.
    pub fn buf(&self) -> &[u8] {
        self.buf
    }

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl<'a> AsRef<[u8]> for OctetsMutRev<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.off]
    }
}

impl<'a> AsMut<[u8]> for OctetsMutRev<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.off]
    }
}

impl<'a> From<OctetsMut<'a>> for OctetsMutRev<'a> {
    fn from(value: OctetsMut<'a>) -> Self {
        OctetsMutRev {
            buf: value.buf,
            off: value.off,
        }
    }
}

impl<'a> From<OctetsMutRev<'a>> for OctetsMut<'a> {
    fn from(value: OctetsMutRev<'a>) -> Self {
        OctetsMut {
            buf: value.buf,
            off: value.off,
        }
    }
}

impl<'a> OctetsRead for Octets<'a> {
    type Bytes = Octets<'a>;

    #[inline]
    fn get_u8(&mut self) -> Result<u8> {
        Octets::get_u8(self)
    }

    #[inline]
    fn get_u16(&mut self) -> Result<u16> {
        Octets::get_u16(self)
    }

    #[inline]
    fn get_u24(&mut self) -> Result<u32> {
        Octets::get_u24(self)
    }

    #[inline]
    fn get_u32(&mut self) -> Result<u32> {
        Octets::get_u32(self)
    }

    #[inline]
    fn get_u64(&mut self) -> Result<u64> {
        Octets::get_u64(self)
    }

    #[inline]
    fn get_varint(&mut self) -> Result<u64> {
        Octets::get_varint(self)
    }

    #[inline]
    fn get_bytes(&mut self, len: usize) -> Result<Self::Bytes> {
        Octets::get_bytes(self, len)
    }

    #[inline]
    fn get_bytes_with_u8_length(&mut self) -> Result<Self::Bytes> {
        Octets::get_bytes_with_u8_length(self)
    }

    #[inline]
    fn get_bytes_with_u16_length(&mut self) -> Result<Self::Bytes> {
        Octets::get_bytes_with_u16_length(self)
    }

    #[inline]
    fn get_bytes_with_varint_length(&mut self) -> Result<Self::Bytes> {
        Octets::get_bytes_with_varint_length(self)
    }

    #[inline]
    fn peek_u8(&mut self) -> Result<u8> {
        Octets::peek_u8(self)
    }

    #[inline]
    fn peek_bytes(&mut self, len: usize) -> Result<Self::Bytes> {
        Octets::peek_bytes(self, len)
    }

    #[inline]
    fn skip(&mut self, skip: usize) -> Result<()> {
        Octets::skip(self, skip)
    }

    #[inline]
    fn rewind(&mut self, rewind: usize) -> Result<()> {
        Octets::rewind(self, rewind)
    }

    #[inline]
    fn cap(&self) -> usize {
        Octets::cap(self)
    }

    #[inline]
    fn len(&self) -> usize {
        Octets::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        Octets::is_empty(self)
    }

    #[inline]
    fn off(&self) -> usize {
        Octets::off(self)
    }

    #[inline]
    fn buf(&self) -> &'a [u8] {
        Octets::buf(self)
    }

    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        Octets::to_vec(self)
    }
}

impl<'a> OctetsRead for OctetsRev<'a> {
    type Bytes = Octets<'a>;

    #[inline]
    fn get_u8(&mut self) -> Result<u8> {
        OctetsRev::get_u8(self)
    }

    #[inline]
    fn get_u16(&mut self) -> Result<u16> {
        OctetsRev::get_u16(self)
    }

    #[inline]
    fn get_u24(&mut self) -> Result<u32> {
        OctetsRev::get_u24(self)
    }

    #[inline]
    fn get_u32(&mut self) -> Result<u32> {
        OctetsRev::get_u32(self)
    }

    #[inline]
    fn get_u64(&mut self) -> Result<u64> {
        OctetsRev::get_u64(self)
    }

    #[inline]
    fn get_varint(&mut self) -> Result<u64> {
        OctetsRev::get_varint(self)
    }

    #[inline]
    fn get_bytes(&mut self, len: usize) -> Result<Self::Bytes> {
        OctetsRev::get_bytes(self, len)
    }

    #[inline]
    fn get_bytes_with_u8_length(&mut self) -> Result<Self::Bytes> {
        OctetsRev::get_bytes_with_u8_length(self)
    }

    #[inline]
    fn get_bytes_with_u16_length(&mut self) -> Result<Self::Bytes> {
        OctetsRev::get_bytes_with_u16_length(self)
    }

    #[inline]
    fn get_bytes_with_varint_length(&mut self) -> Result<Self::Bytes> {
        OctetsRev::get_bytes_with_varint_length(self)
    }

    #[inline]
    fn peek_u8(&mut self) -> Result<u8> {
        OctetsRev::peek_u8(self)
    }

    #[inline]
    fn peek_bytes(&mut self, len: usize) -> Result<Self::Bytes> {
        // Let's implement it by rewinding and then advancing back.
        if self.off < len {
            return Err(BufferError::BufferTooShortError);
        }
        self.off -= len;
        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };
        self.off += len;
        Ok(out)
    }

    #[inline]
    fn skip(&mut self, skip: usize) -> Result<()> {
        OctetsRev::skip(self, skip)
    }

    #[inline]
    fn rewind(&mut self, rewind: usize) -> Result<()> {
        OctetsRev::rewind(self, rewind)
    }

    #[inline]
    fn cap(&self) -> usize {
        OctetsRev::cap(self)
    }

    #[inline]
    fn len(&self) -> usize {
        OctetsRev::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        OctetsRev::is_empty(self)
    }

    #[inline]
    fn off(&self) -> usize {
        OctetsRev::off(self)
    }

    #[inline]
    fn buf(&self) -> &'a [u8] {
        OctetsRev::buf(self)
    }

    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        OctetsRev::to_vec(self)
    }
}

impl OctetsWrite for OctetsMut<'_> {
    #[inline]
    fn put_varint(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_varint(v)
    }

    #[inline]
    fn put_varint_with_len(&mut self, v: u64, len: usize) -> Result<&mut [u8]> {
        self.put_varint_with_len(v, len)
    }

    #[inline]
    fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        self.put_u8(v)
    }

    #[inline]
    fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        self.put_u16(v)
    }

    #[inline]
    fn put_u24(&mut self, v: u32) -> Result<&mut [u8]> {
        self.put_u24(v)
    }

    #[inline]
    fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        self.put_u32(v)
    }

    #[inline]
    fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_u64(v)
    }

    #[inline]
    fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        self.put_bytes(v)
    }

    #[inline]
    fn skip(&mut self, skip: usize) -> Result<()> {
        OctetsMut::skip(self, skip)
    }

    #[inline]
    fn rewind(&mut self, rewind: usize) -> Result<()> {
        OctetsMut::rewind(self, rewind)
    }

    #[inline]
    fn cap(&self) -> usize {
        OctetsMut::cap(self)
    }

    #[inline]
    fn len(&self) -> usize {
        OctetsMut::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        OctetsMut::is_empty(self)
    }

    #[inline]
    fn off(&self) -> usize {
        OctetsMut::off(self)
    }

    #[inline]
    fn buf(&self) -> &[u8] {
        OctetsMut::buf(self)
    }

    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        OctetsMut::to_vec(self)
    }
}

impl OctetsWrite for Box<dyn OctetsWrite + '_> {
    fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        (**self).put_u8(v)
    }

    fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        (**self).put_u16(v)
    }

    fn put_u24(&mut self, v: u32) -> Result<&mut [u8]> {
        (**self).put_u24(v)
    }

    fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        (**self).put_u32(v)
    }

    fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        (**self).put_u64(v)
    }

    fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        (**self).put_bytes(v)
    }

    fn put_varint(&mut self, v: u64) -> Result<&mut [u8]> {
        (**self).put_varint(v)
    }

    fn put_varint_with_len(&mut self, v: u64, len: usize) -> Result<&mut [u8]> {
        (**self).put_varint_with_len(v, len)
    }

    fn cap(&self) -> usize {
        (**self).cap()
    }

    fn len(&self) -> usize {
        (**self).len()
    }

    fn off(&self) -> usize {
        (**self).off()
    }

    fn buf(&self) -> &[u8] {
        (**self).buf()
    }

    fn skip(&mut self, skip: usize) -> Result<()> {
        (**self).skip(skip)
    }

    fn rewind(&mut self, rewind: usize) -> Result<()> {
        (**self).rewind(rewind)
    }

    fn to_vec(&self) -> Vec<u8> {
        (**self).to_vec()
    }

    fn is_empty(&self) -> bool {
        (**self).is_empty()
    }
}

impl<'a> OctetsRead for Box<dyn OctetsRead<Bytes = Octets<'a>> + '_> {
    type Bytes = Octets<'a>;

    fn get_u8(&mut self) -> Result<u8> {
        (**self).get_u8()
    }

    fn get_u16(&mut self) -> Result<u16> {
        (**self).get_u16()
    }

    fn get_u24(&mut self) -> Result<u32> {
        (**self).get_u24()
    }

    fn get_u32(&mut self) -> Result<u32> {
        (**self).get_u32()
    }

    fn get_u64(&mut self) -> Result<u64> {
        (**self).get_u64()
    }

    fn peek_u8(&mut self) -> Result<u8> {
        (**self).peek_u8()
    }

    fn get_bytes(&mut self, len: usize) -> Result<Self::Bytes> {
        (**self).get_bytes(len)
    }

    fn get_varint(&mut self) -> Result<u64> {
        (**self).get_varint()
    }

    fn get_bytes_with_u8_length(&mut self) -> Result<Self::Bytes> {
        (**self).get_bytes_with_u8_length()
    }

    fn get_bytes_with_u16_length(&mut self) -> Result<Self::Bytes> {
        (**self).get_bytes_with_u16_length()
    }

    fn get_bytes_with_varint_length(&mut self) -> Result<Self::Bytes> {
        (**self).get_bytes_with_varint_length()
    }

    fn is_empty(&self) -> bool {
        (**self).is_empty()
    }

    fn to_vec(&self) -> Vec<u8> {
        (**self).to_vec()
    }

    fn rewind(&mut self, rewind: usize) -> Result<()> {
        (**self).rewind(rewind)
    }

    fn skip(&mut self, skip: usize) -> Result<()> {
        (**self).skip(skip)
    }

    fn buf(&self) -> &[u8] {
        (**self).buf()
    }

    fn off(&self) -> usize {
        (**self).off()
    }

    fn len(&self) -> usize {
        (**self).len()
    }

    fn cap(&self) -> usize {
        (**self).cap()
    }

    fn peek_bytes(&mut self, len: usize) -> Result<Self::Bytes> {
        (**self).peek_bytes(len)
    }
}

impl OctetsWrite for OctetsMutRev<'_> {
    #[inline]
    fn put_varint(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_varint(v)
    }

    #[inline]
    fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        self.put_u8(v)
    }

    #[inline]
    fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        self.put_u16(v)
    }

    #[inline]
    fn put_u24(&mut self, v: u32) -> Result<&mut [u8]> {
        self.put_u24(v)
    }

    #[inline]
    fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        self.put_u32(v)
    }

    #[inline]
    fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_u64(v)
    }

    #[inline]
    fn put_varint_with_len(&mut self, v: u64, len: usize) -> Result<&mut [u8]> {
        self.put_varint_with_len(v, len)
    }

    #[inline]
    fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        self.put_bytes(v)
    }

    #[inline]
    fn skip(&mut self, skip: usize) -> Result<()> {
        self.skip(skip)
    }

    #[inline]
    fn rewind(&mut self, rewind: usize) -> Result<()> {
        self.rewind(rewind)
    }

    #[inline]
    fn cap(&self) -> usize {
        self.cap()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    #[inline]
    fn off(&self) -> usize {
        self.off()
    }

    #[inline]
    fn buf(&self) -> &[u8] {
        self.buf()
    }

    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        self.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_u() {
        let d = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 18);
        assert_eq!(b.off(), 0);
        assert_eq!(b.get_u8().unwrap(), 1);
        assert_eq!(b.cap(), 17);
        assert_eq!(b.off(), 1);
        assert_eq!(b.get_u16().unwrap(), 0x203);
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 3);
        assert_eq!(b.get_u24().unwrap(), 0x40506);
        assert_eq!(b.cap(), 12);
        assert_eq!(b.off(), 6);
        assert_eq!(b.get_u32().unwrap(), 0x0708090a);
        assert_eq!(b.cap(), 8);
        assert_eq!(b.off(), 10);
        assert_eq!(b.get_u64().unwrap(), 0x0b0c0d0e0f101112);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 18);
        assert!(b.get_u8().is_err());
        assert!(b.get_u16().is_err());
        assert!(b.get_u24().is_err());
        assert!(b.get_u32().is_err());
        assert!(b.get_u64().is_err());
    }

    #[test]
    fn get_u_mut() {
        let mut d = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 18);
        assert_eq!(b.off(), 0);
        assert_eq!(b.get_u8().unwrap(), 1);
        assert_eq!(b.cap(), 17);
        assert_eq!(b.off(), 1);
        assert_eq!(b.get_u16().unwrap(), 0x203);
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 3);
        assert_eq!(b.get_u24().unwrap(), 0x40506);
        assert_eq!(b.cap(), 12);
        assert_eq!(b.off(), 6);
        assert_eq!(b.get_u32().unwrap(), 0x0708090a);
        assert_eq!(b.cap(), 8);
        assert_eq!(b.off(), 10);
        assert_eq!(b.get_u64().unwrap(), 0x0b0c0d0e0f101112);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 18);
        assert!(b.get_u8().is_err());
        assert!(b.get_u16().is_err());
        assert!(b.get_u24().is_err());
        assert!(b.get_u32().is_err());
        assert!(b.get_u64().is_err());
    }

    #[test]
    fn peek_u() {
        let d = [1, 2];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);
        b.get_u16().unwrap();
        assert!(b.peek_u8().is_err());
    }

    #[test]
    fn peek_u_mut() {
        let mut d = [1, 2];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);
        b.get_u16().unwrap();
        assert!(b.peek_u8().is_err());
    }

    #[test]
    fn get_bytes() {
        let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.get_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 5);
        assert_eq!(b.off(), 5);
        assert_eq!(b.get_bytes(3).unwrap().as_ref(), [6, 7, 8]);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);
        assert!(b.get_bytes(3).is_err());
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);
        assert_eq!(b.get_bytes(2).unwrap().as_ref(), [9, 10]);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 10);
        assert!(b.get_bytes(2).is_err());
    }

    #[test]
    fn get_bytes_mut() {
        let mut d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.get_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 5);
        assert_eq!(b.off(), 5);
        assert_eq!(b.get_bytes(3).unwrap().as_ref(), [6, 7, 8]);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);
        assert!(b.get_bytes(3).is_err());
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);
        assert_eq!(b.get_bytes(2).unwrap().as_ref(), [9, 10]);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 10);
        assert!(b.get_bytes(2).is_err());
    }

    #[test]
    fn peek_bytes() {
        let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        b.get_bytes(5).unwrap();
    }

    #[test]
    fn peek_bytes_mut() {
        let mut d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        b.get_bytes(5).unwrap();
    }

    #[test]
    fn get_varint() {
        let d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 151288809941952652);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 8);
        let d = [0x9d, 0x7f, 0x3e, 0x7d];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 494878333);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 4);
        let d = [0x7b, 0xbd];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 15293);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);
        let d = [0x40, 0x25];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);
        let d = [0x25];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 1);
    }

    #[test]
    fn get_varint_rev_test() {
        let d = [0x24];
        let mut b = OctetsRev::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 9);
        assert_eq!(b.off(), 0);
        let d = [0x25, 0x25];
        let mut b = OctetsRev::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 2377);
        assert_eq!(b.off(), 0);
        let d = [0x7b, 0x9d, 0x25, 0x16];
        let mut b = OctetsRev::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 518474053);
        assert_eq!(b.off(), 0);
        let d = [0x19, 0xc2, 0x5e, 0x7b, 0x9d, 0x25, 0x16, 0x17];
        let mut b = OctetsRev::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 464037470360126853);
        assert_eq!(b.off(), 0);
    }

    #[test]
    fn get_varint_mut() {
        let mut d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 151288809941952652);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 8);
        let mut d = [0x9d, 0x7f, 0x3e, 0x7d];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 494878333);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 4);
        let mut d = [0x7b, 0xbd];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 15293);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);
        let mut d = [0x40, 0x25];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);
        let mut d = [0x25];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 1);
    }

    #[test]
    fn put_varint() {
        let mut d = [0; 8];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(151288809941952652).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 8);
        }
        let exp = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        assert_eq!(&d, &exp);
        let mut d = [0; 4];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(494878333).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 4);
        }
        let exp = [0x9d, 0x7f, 0x3e, 0x7d];
        assert_eq!(&d, &exp);
        let mut d = [0; 2];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(15293).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 2);
        }
        let exp = [0x7b, 0xbd];
        assert_eq!(&d, &exp);
        let mut d = [0; 1];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(37).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 1);
        }
        let exp = [0x25];
        assert_eq!(&d, &exp);
        let mut d = [0; 3];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(151288809941952652).is_err());
            assert_eq!(b.cap(), 3);
            assert_eq!(b.off(), 0);
        }
        let exp = [0; 3];
        assert_eq!(&d, &exp);
    }

    #[test]
    fn put_varint_rev_test() {
        let mut d = [0; 1];
        {
            let mut b = OctetsMutRev::with_slice(&mut d);
            assert!(b.put_varint(9).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 0);
        }
        let exp = [0x24];
        assert_eq!(&d, &exp);
        let mut d = [0; 2];
        {
            let mut b = OctetsMutRev::with_slice(&mut d);
            assert!(b.put_varint(2377).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 0);
        }
        let exp = [0x25, 0x25];
        assert_eq!(&d, &exp);
        let mut d = [0; 4];
        {
            let mut b = OctetsMutRev::with_slice(&mut d);
            assert!(b.put_varint(518474053).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 0);
        }
        let exp = [0x7b, 0x9d, 0x25, 0x16];
        assert_eq!(&d, &exp);
        let mut d = [0; 8];
        {
            let mut b = OctetsMutRev::with_slice(&mut d);
            assert!(b.put_varint(464037470360126853).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 0);
        }
        let exp = [0x19, 0xc2, 0x5e, 0x7b, 0x9d, 0x25, 0x16, 0x17];
        assert_eq!(&d, &exp);
    }

    #[test]
    #[should_panic]
    fn varint_too_large() {
        let mut d = [0; 3];
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(u64::MAX).is_err());
    }

    #[test]
    fn put_u() {
        let mut d = [0; 18];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert_eq!(b.cap(), 18);
            assert_eq!(b.off(), 0);
            assert!(b.put_u8(1).is_ok());
            assert_eq!(b.cap(), 17);
            assert_eq!(b.off(), 1);
            assert!(b.put_u16(0x203).is_ok());
            assert_eq!(b.cap(), 15);
            assert_eq!(b.off(), 3);
            assert!(b.put_u24(0x40506).is_ok());
            assert_eq!(b.cap(), 12);
            assert_eq!(b.off(), 6);
            assert!(b.put_u32(0x0708090a).is_ok());
            assert_eq!(b.cap(), 8);
            assert_eq!(b.off(), 10);
            assert!(b.put_u64(0x0b0c0d0e0f101112).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 18);
            assert!(b.put_u8(1).is_err());
        }
        let exp = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        assert_eq!(&d, &exp);
    }
}
