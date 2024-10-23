// Copyright (C) 2023, Cloudflare, Inc.
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

use std::cmp;
use std::time;

use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::Error;
use crate::Result;

use crate::flowcontrol;

use super::RecvBufInfo;
use super::DEFAULT_STREAM_WINDOW;
use crate::range_buf::RangeBuf;
use std::collections::btree_map;

use likely_stable::if_likely;

const MAX_STREAM_FRAME_LENGTH: usize = 1310;

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Todo -- compare speed with BTreeMap
    // heap: BinaryHeap<std::cmp::Reverse<RecvBufInfo>>,
    pub heap: BTreeMap<u64, RecvBufInfo>,
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: BTreeMap<u64, RangeBuf>,

    /// Set of max offsets of stream frames for which the stream is not fin
    /// and we're expecting bytes. Ideally if every frames are received in
    /// order, then this would not contain any element. Otherwise, this set
    /// contains as many offsets as we have 'holes' due receiving data not
    /// in order. We store the max offset of a given Stream frame, and the
    /// length since the last hole in the buffer. They eventually get
    /// cleaned when the app receive the data.
    pub maxoffs_order: BTreeMap<u64, usize>,

    /// The lowest data offset that has yet to be read by the application.
    pub off: u64,

    /// The highest contiguous data offset that has yet to be read by the
    /// application.
    pub contiguous_off: u64,

    /// The total length of data received on this stream.
    len: u64,

    /// Receiver flow controller.
    pub flow_control: flowcontrol::FlowControl,

    /// The final stream offset received from the peer, if any.
    fin_off: Option<u64>,

    /// In v3, set to true if we have to deliver the fin bit to the
    /// application without any data.
    pub deliver_fin: bool,

    /// The error code received via RESET_STREAM.
    error: Option<u64>,

    /// Whether incoming data is validated but not buffered.
    drain: bool,

    pub version: u32,
}

impl RecvBuf {
    /// Creates a new receive buffer.
    pub fn new(max_data: u64, max_window: u64, version: u32) -> RecvBuf {
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(
                max_data,
                cmp::min(max_data, DEFAULT_STREAM_WINDOW),
                max_window,
            ),
            version,
            ..RecvBuf::default()
        }
    }

    /// Inserts the given chunk of data in the buffer.
    ///
    /// This also takes care of enforcing stream flow control limits, as well
    /// as handling incoming data that overlaps data that is already in the
    /// buffer.
    pub fn write(&mut self, buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControl);
        }

        if let Some(fin_off) = self.fin_off {
            // Stream's size is known, forbid data beyond that point.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSize);
            }

            // Stream's size is already known, forbid changing it.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if buf.fin() && buf.max_off() < self.len {
            return Err(Error::FinalSize);
        }

        // We already saved the final offset, so there's nothing else we
        // need to keep from the RangeBuf if it's empty.
        if self.fin_off.is_some() && buf.is_empty() {
            return Ok(());
        }

        if buf.fin() {
            self.fin_off = Some(buf.max_off());
        }

        // No need to store empty buffer that doesn't carry the fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // Check if data is fully duplicate, that is the buffer's max offset is
        // lower or equal to the offset already stored in the recv buffer.
        if self.off >= buf.max_off() {
            // An exception is applied to empty range buffers, because an empty
            // buffer's max offset matches the max offset of the recv buffer.
            //
            // By this point all spurious empty buffers should have already been
            // discarded, so allowing empty buffers here should be safe.
            if !buf.is_empty() {
                return Ok(());
            }
        }

        let mut tmp_bufs = VecDeque::with_capacity(2);
        tmp_bufs.push_back(buf);

        'tmp: while let Some(mut buf) = tmp_bufs.pop_front() {
            // Discard incoming data below current stream offset. Bytes up to
            // `self.off` have already been received so we should not buffer
            // them again. This is also important to make sure `ready()` doesn't
            // get stuck when a buffer with lower offset than the stream's is
            // buffered.
            if self.off_front() > buf.off() {
                buf = buf.split_off((self.off_front() - buf.off()) as usize);
            }

            // Handle overlapping data. If the incoming data's starting offset
            // is above the previous maximum received offset, there is clearly
            // no overlap so this logic can be skipped. However do still try to
            // merge an empty final buffer (i.e. an empty buffer with the fin
            // flag set, which is the only kind of empty buffer that should
            // reach this point).
            if buf.off() < self.max_off() || buf.is_empty() {
                for (_, b) in self.data.range(buf.off()..) {
                    let off = buf.off();

                    // We are past the current buffer.
                    if b.off() > buf.max_off() {
                        break;
                    }

                    // New buffer is fully contained in existing buffer.
                    if off >= b.off() && buf.max_off() <= b.max_off() {
                        continue 'tmp;
                    }

                    // New buffer's start overlaps existing buffer.
                    if off >= b.off() && off < b.max_off() {
                        buf = buf.split_off((b.max_off() - off) as usize);
                    }

                    // New buffer's end overlaps existing buffer.
                    if off < b.off() && buf.max_off() > b.off() {
                        tmp_bufs
                            .push_back(buf.split_off((b.off() - off) as usize));
                    }
                }
            }

            self.len = cmp::max(self.len, buf.max_off());

            if !self.drain {
                self.data.insert(buf.max_off(), buf);
            }
        }

        Ok(())
    }

    pub fn write_v3(&mut self, mut buf: RecvBufInfo) -> Result<()> {
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControl);
        }
        if let Some(fin_off) = self.fin_off {
            // Stream's size is known, forbid data beyond that point.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSize);
            }

            // Stream's size is already known, forbid changing it.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSize);
            }
        }
        // Stream's known size is lower than data already received.
        if buf.fin() && buf.max_off() < self.len {
            return Err(Error::FinalSize);
        }

        // We already saved the final offset, so there's nothing else we
        // need to keep from the RangeBuf if it's empty.
        if self.fin_off.is_some() && buf.is_empty() {
            return Ok(());
        }

        if buf.fin() {
            self.fin_off = Some(buf.max_off());
            if buf.is_empty() && !self.drain {
                self.deliver_fin = true;
            }
        }

        // No need to store empty buffer that doesn't carry the fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // Check if data is fully duplicate, that is the buffer's max offset is
        // lower or equal to the offset already stored in the recv buffer.
        if self.off >= buf.max_off() {
            // An exception is applied to empty range buffers, because an empty
            // buffer's max offset matches the max offset of the recv buffer.
            //
            // By this point all spurious empty buffers should have already been
            // discarded, so allowing empty buffers here should be safe.
            if !buf.is_empty() {
                return Ok(());
            }
        }

        if buf.start_off < self.contiguous_off {
            // overlap with contiguous received data not yet read.
            // This should not happen because the overlap is checked before
            // decryption, and the packet is dropped.
            return Err(Error::InvalidOffset);
        }

        // Should overlapping ranges be treated as PROTOCOL_VIOLATION?  This
        // likely can get abused by middleboxes. Indeed, Stream DATA isn't
        // globally AE-Secure because of this, which could be considered a
        // missuse of the AEAD primitive. Note: this is not particularly
        // an issue of quiceh, but rather something silly in the Quic design
        // itself, due to UDP.

        if self.off_front() > buf.off() && self.off_front() < buf.max_off() {
            buf.len = (buf.off() + buf.len as u64 - self.off_front()) as usize;
            buf.start_off = self.off_front();
        }

        self.len = cmp::max(self.len, buf.max_off());

        if !self.drain && self.contiguous_off != buf.start_off {
            self.heap.insert(buf.start_off, buf);
        } else if self.contiguous_off == buf.start_off {
            self.contiguous_off += buf.len as u64;
        }

        Ok(())
    }

    /// Writes data from the receive buffer into the given output buffer.
    ///
    /// Only contiguous data is written to the output buffer, starting from
    /// offset 0. The offset is incremented as data is read out of the receive
    /// buffer into the application buffer. If there is no data at the expected
    /// read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read, and a flag indicating if there is
    /// no more data in the buffer, are returned as a tuple.
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();

        if !self.ready() {
            return Err(Error::Done);
        }

        // The stream was reset, so clear its data and return the error code
        // instead.
        if let Some(e) = self.error {
            self.data.clear();
            return Err(Error::StreamReset(e));
        }

        while cap > 0 && self.ready() {
            let mut entry = match self.data.first_entry() {
                Some(entry) => entry,
                None => break,
            };

            let buf = entry.get_mut();

            let buf_len = cmp::min(buf.len(), cap);

            out[len..len + buf_len].copy_from_slice(&buf[..buf_len]);

            self.off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // We reached the maximum capacity, so end here.
                break;
            }

            entry.remove();
        }

        // Update consumed bytes for flow control.
        self.flow_control.add_consumed(len as u64);

        Ok((len, self.is_fin()))
    }

    /// Resets the stream at the given offset.
    pub fn reset(&mut self, error_code: u64, final_size: u64) -> Result<usize> {
        // Stream's size is already known, forbid changing it.
        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if final_size < self.len {
            return Err(Error::FinalSize);
        }

        // Calculate how many bytes need to be removed from the connection flow
        // control.
        let max_data_delta = final_size - self.len;

        if self.error.is_some() {
            return Ok(max_data_delta as usize);
        }

        self.error = Some(error_code);

        // Clear all data already buffered.
        self.off = final_size;

        if_likely! { self.version == crate::PROTOCOL_VERSION_VREVERSO => {
            self.contiguous_off = final_size;
            self.heap.clear();

            let bufinfo = RecvBufInfo::from(final_size, 0, true);
            self.write_v3(bufinfo)?;
        } else {
            self.data.clear();

            // In order to ensure the application is notified when the stream is
            // reset, enqueue a zero-length buffer at the final size offset.
            let buf = RangeBuf::from(b"", final_size, true);
            self.write(buf)?;
        }};

        Ok(max_data_delta as usize)
    }

    /// Check whether the incoming data is in order.
    pub fn not_in_order(&mut self, metadata: &RecvBufInfo) -> bool {
        if metadata.start_off > self.contiguous_off {
            // several cases
            // 1) start_off matches a key within the map, and the length
            // of the data down to the 'hole' is large enough that we don't risk
            // overwriting control information over multiple stream frames in case
            // of unordered packets In that case, the packet is
            // considered in order, and zerocopy is safe to apply.
            // 2) start_off maches a key within the hashmap, but the length of
            // the data down to the 'hole' isn't large enough. Mark the packet not
            // in order but update the stored offset and increase the
            // length of the data by the value this metadata provides.
            // Zerocopy isn't safe to apply; so we retain a copy of the
            // packet.
            // 3) start_off doesnt match a key within the hashmap. Oups, we have a
            //    hole right before this packet! insert a new element within the
            //    map, and eventually make a copy of this stream frame.
            match self.maxoffs_order.entry(metadata.start_off) {
                btree_map::Entry::Occupied(o) => {
                    let (_, len) = o.remove_entry();
                    self.maxoffs_order
                        .insert(metadata.max_off(), len + metadata.len);
                    return len <= MAX_STREAM_FRAME_LENGTH;
                },
                btree_map::Entry::Vacant(_o) => {
                    self.maxoffs_order.insert(metadata.max_off(), metadata.len);
                    return true;
                },
            }
        }
        false
    }

    pub fn has_error(&self) -> Option<u64> {
        self.error
    }

    /// Commits the new max_data limit.
    pub fn update_max_data(&mut self, now: time::Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Return the new max_data limit.
    pub fn max_data_next(&mut self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Return the current flow control limit.
    pub fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Return the current window.
    pub fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the window size.
    pub fn autotune_window(&mut self, now: time::Instant, rtt: time::Duration) {
        self.flow_control.autotune_window(now, rtt);
    }

    /// Shuts down receiving data.
    pub fn shutdown(&mut self) -> Result<()> {
        if self.drain {
            return Err(Error::Done);
        }

        self.drain = true;

        if_likely! {self.version == crate::PROTOCOL_VERSION_VREVERSO => {
            self.heap.clear();
            self.deliver_fin = false;
            self.contiguous_off = self.max_off();
        } else {
            self.data.clear();
        }};

        self.off = self.max_off();

        Ok(())
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        self.off
    }

    /// Returns the highest contiguous offset that has yet to be read by
    /// the application.
    pub fn contiguous_off(&self) -> u64 {
        self.contiguous_off
    }

    /// Returns true if we need to update the local flow control limit.
    pub fn almost_full(&self) -> bool {
        self.fin_off.is_none() && self.flow_control.should_update_max_data()
    }

    /// Returns the largest offset ever received.
    pub fn max_off(&self) -> u64 {
        self.len
    }

    /// Returns true if the receive-side of the stream is complete.
    ///
    /// This happens when the stream's receive final size is known, and the
    /// application has read all data from the stream.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the stream is not storing incoming data.
    pub fn is_draining(&self) -> bool {
        self.drain
    }

    /// Returns true if the stream has data to be read.
    pub fn ready(&self) -> bool {
        let ready = if_likely! {self.version == crate::PROTOCOL_VERSION_VREVERSO => {
            match self.heap.first_key_value() {
                Some((_, recvinfo)) => recvinfo.start_off <= self.contiguous_off,
                None => return false,
            }
        } else {
            let (_, buf) = match self.data.first_key_value() {
                Some(v) => v,
                None => return false,
            };
            buf.off() == self.off
        }};
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range_buf::DefaultBufFactory;
    use crate::stream::app_recv_buf::AppRecvBuf;

    #[test]
    fn empty_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn empty_stream_frame() {
        let mut recv =
            RecvBuf::new(15, DEFAULT_STREAM_WINDOW, crate::PROTOCOL_VERSION);
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        let bufinfo = RecvBufInfo::from(0, 5, false);
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);

        let mut buf = [0; 32];

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Ok((5, false)));
        } else {
            assert_eq!(
                (app_buf.read_mut(&mut recv).unwrap().len(), recv.is_fin()),
                (5, false)
            );
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 5).is_ok());
        }

        // Don't store non-fin empty buffer.
        let buf = RangeBuf::from(b"", 10, false);
        let bufinfo = RecvBufInfo::from(10, 0, false);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);

        // Check flow control for empty buffer.
        let buf = RangeBuf::from(b"", 16, false);
        let bufinfo = RecvBufInfo::from(16, 0, false);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.write(buf), Err(Error::FlowControl));
        } else {
            assert_eq!(recv.write_v3(bufinfo), Err(Error::FlowControl));
        }

        // Store fin empty buffer.
        let buf = RangeBuf::from(b"", 5, true);
        let bufinfo = RecvBufInfo::from(5, 0, true);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            // In v3 we don't store it if it is in order, but we mark the stream
            // as fin.
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);

        // Don't store additional fin empty buffers.
        let buf = RangeBuf::from(b"", 5, true);
        let bufinfo = RecvBufInfo::from(5, 0, true);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);

        // Don't store additional fin non-empty buffers.
        let buf = RangeBuf::from(b"aa", 3, true);
        let bufinfo = RecvBufInfo::from(3, 2, true);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);

        // Validate final size with fin empty buffers.
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            let buf = RangeBuf::from(b"", 6, true);
            assert_eq!(recv.write(buf), Err(Error::FinalSize));
            let buf = RangeBuf::from(b"", 4, true);
            assert_eq!(recv.write(buf), Err(Error::FinalSize));
            let mut buf = [0; 32];
            assert_eq!(recv.emit(&mut buf), Ok((0, true)));
        } else {
            let bufinfo = RecvBufInfo::from(6, 0, true);
            assert_eq!(recv.write_v3(bufinfo), Err(Error::FinalSize));
            let bufinfo = RecvBufInfo::from(4, 0, true);
            assert_eq!(recv.write_v3(bufinfo), Err(Error::FinalSize));
            assert_eq!(
                (app_buf.read_mut(&mut recv).unwrap().len(), recv.is_fin()),
                (0, true)
            );
        }
    }

    #[test]
    fn ordered_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);

        let first = RangeBuf::from(b"hello", 0, false);
        let firstinfo = RecvBufInfo::from(0, 5, false);
        let second = RangeBuf::from(b"world", 5, false);
        let secondinfo = RecvBufInfo::from(5, 5, false);
        let third = RangeBuf::from(b"something", 10, true);
        let thirdinfo = RecvBufInfo::from(10, 9, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            // If we have nothing to read, we return a 0 length slice
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
            assert_eq!(len, 19);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"helloworldsomething");
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 19);
        }
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn split_read() {
        // TODO Double check; we don't need split logic in V3.
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            let mut recv = RecvBuf::new(
                u64::MAX,
                DEFAULT_STREAM_WINDOW,
                crate::PROTOCOL_VERSION,
            );
            assert_eq!(recv.len, 0);

            let mut buf = [0; 32];

            let first = RangeBuf::from(b"something", 0, false);
            let second = RangeBuf::from(b"helloworld", 9, true);

            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);

            assert!(recv.write(second).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);

            let (len, fin) = recv.emit(&mut buf[..10]).unwrap();
            assert_eq!(len, 10);
            assert!(!fin);
            assert_eq!(&buf[..len], b"somethingh");
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 10);

            let (len, fin) = recv.emit(&mut buf[..5]).unwrap();
            assert_eq!(len, 5);
            assert!(!fin);
            assert_eq!(&buf[..len], b"ellow");
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 15);

            let (len, fin) = recv.emit(&mut buf[..10]).unwrap();
            assert_eq!(len, 4);
            assert!(fin);
            assert_eq!(&buf[..len], b"orld");
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 19);
        }
    }

    #[test]
    fn incomplete_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"helloworld", 9, true);
        let secondinfo = RecvBufInfo::from(9, 10, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }

        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 19);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"somethinghelloworld");
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 19);
            assert_eq!(recv.is_fin(), true);
        }
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn zero_len_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"", 9, true);
        let secondinfo = RecvBufInfo::from(9, 0, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            // contiguous, hence not stored in the heap.
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 9);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"something");
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 9);
            assert_eq!(recv.is_fin(), true);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
    }

    #[test]
    fn past_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let secondinfo = RecvBufInfo::from(3, 5, false);
        let third = RangeBuf::from(b"ello", 4, true);
        let thirdinfo = RecvBufInfo::from(4, 4, true);
        let fourth = RangeBuf::from(b"ello", 5, true);
        let fourthinfo = RecvBufInfo::from(5, 4, true);

        if crate::PROTOCOL_VERSION != crate::PROTOCOL_VERSION_VREVERSO {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 1);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 9);
            assert_eq!(fin, false);
            assert_eq!(&buf[..len], b"something");
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 9);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 9).is_ok());
            assert_eq!(recv.is_fin(), false);
        }

        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION != crate::PROTOCOL_VERSION_VREVERSO {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION != crate::PROTOCOL_VERSION_VREVERSO {
            assert_eq!(recv.write(third), Err(Error::FinalSize));
        } else {
            assert_eq!(recv.write_v3(thirdinfo), Err(Error::FinalSize));
        }

        if crate::PROTOCOL_VERSION != crate::PROTOCOL_VERSION_VREVERSO {
            assert!(recv.write(fourth).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 9);
            assert_eq!(recv.data.len(), 0);
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert!(recv.write_v3(fourthinfo).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 9);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"hello", 4, false);
        let secondinfo = RecvBufInfo::from(4, 5, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 1);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 9);
            assert_eq!(fin, false);
            assert_eq!(&buf[..len], b"something");
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(secondinfo).is_err());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 9);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 9).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read2() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"hello", 4, false);
        let secondinfo = RecvBufInfo::from(4, 5, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 2);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 9);
            assert_eq!(fin, false);
            assert_eq!(&buf[..len], b"somehello");
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 9);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 9).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read3() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let secondinfo = RecvBufInfo::from(3, 5, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }

        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 3);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 9);
            assert_eq!(fin, false);
            assert_eq!(&buf[..len], b"somhellog");
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 1);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 9);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 9).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }

        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read_multi() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"somethingsomething", 0, false);
        let firstinfo = RecvBufInfo::from(0, 18, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let secondinfo = RecvBufInfo::from(3, 5, false);
        let third = RangeBuf::from(b"hello", 12, false);
        let thirdinfo = RecvBufInfo::from(12, 5, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 17);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 18);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 5);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 18);
            assert_eq!(fin, false);
            assert_eq!(&buf[..len], b"somhellogsomhellog");
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 18);
            assert_eq!(recv.off, 0);
            // firstinfo is contiguous; it does not go through the heap.
            assert_eq!(recv.heap.len(), 2);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 18);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 18).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 18);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn overlapping_start_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"hello", 8, true);
        let secondinfo = RecvBufInfo::from(8, 5, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.len, 13);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 2);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 13);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"somethingello");
            assert_eq!(recv.len, 13);
            assert_eq!(recv.off, 13);
        } else {
            // That sort of overlap can't happen in v3
            // because the second packet would not be decrypted
            assert!(recv.write_v3(secondinfo).is_err());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 9);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 9).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 9);
        }
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn overlapping_end_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let firstinfo = RecvBufInfo::from(0, 5, false);
        let second = RangeBuf::from(b"something", 3, true);
        let secondinfo = RecvBufInfo::from(3, 9, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.len, 12);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 2);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 12);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"helsomething");
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.len, 12);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 1);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 12);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 12).is_ok());
            assert!(recv.is_fin());
        }
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 12);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn overlapping_end_twice_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"he", 0, false);
        let firstinfo = RecvBufInfo::from(0, 2, false);
        let second = RangeBuf::from(b"ow", 4, false);
        let secondinfo = RecvBufInfo::from(4, 2, false);
        let third = RangeBuf::from(b"rl", 7, false);
        let thirdinfo = RecvBufInfo::from(7, 2, false);
        let fourth = RangeBuf::from(b"helloworld", 0, true);
        let fourthinfo = RecvBufInfo::from(0, 10, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 3);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(fourth).is_ok());
            assert_eq!(recv.len, 10);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 6);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 10);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"helloworld");
            assert_eq!(recv.len, 10);
            assert_eq!(recv.off, 10);
        } else {
            assert!(recv.write_v3(fourthinfo).is_err());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 2);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 2);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 2).is_ok());
            assert!(!recv.is_fin());
        }

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn overlapping_end_twice_and_contained_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hellow", 0, false);
        let firstinfo = RecvBufInfo::from(0, 5, false);
        let second = RangeBuf::from(b"barfoo", 10, true);
        let secondinfo = RecvBufInfo::from(10, 6, true);
        let third = RangeBuf::from(b"rl", 7, false);
        let thirdinfo = RecvBufInfo::from(7, 2, false);
        let fourth = RangeBuf::from(b"elloworldbarfoo", 1, true);
        let fourthinfo = RecvBufInfo::from(1, 15, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 3);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(fourth).is_ok());
            assert_eq!(recv.len, 16);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 5);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 16);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"helloworldbarfoo");
            assert_eq!(recv.len, 16);
            assert_eq!(recv.off, 16);
        } else {
            assert!(recv.write_v3(fourthinfo).is_err());
            assert_eq!(recv.len, 16);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 2);
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 5);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 5).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.len, 16);
            assert_eq!(recv.off, 5);
        }

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn partially_multi_overlapping_reordered_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 8, false);
        let firstinfo = RecvBufInfo::from(8, 5, false);
        let second = RangeBuf::from(b"something", 0, false);
        let secondinfo = RecvBufInfo::from(0, 9, false);
        let third = RangeBuf::from(b"moar", 11, true);
        let thirdinfo = RecvBufInfo::from(11, 4, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.len, 15);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 3);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 15);
            assert_eq!(fin, true);
            assert_eq!(&buf[..len], b"somethinhelloar");
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert_eq!(recv.len, 15);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 2);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 15);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 15).is_ok());
            assert!(recv.is_fin());
        }
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 15);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }

    #[test]
    fn partially_multi_overlapping_reordered_read2() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION,
        );
        let mut app_buf = AppRecvBuf::new(1, Some(42), 100, 1000);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"aaa", 0, false);
        let firstinfo = RecvBufInfo::from(0, 3, false);
        let second = RangeBuf::from(b"bbb", 2, false);
        let secondinfo = RecvBufInfo::from(2, 3, false);
        let third = RangeBuf::from(b"ccc", 4, false);
        let thirdinfo = RecvBufInfo::from(4, 3, false);
        let fourth = RangeBuf::from(b"ddd", 6, false);
        let fourthinfo = RecvBufInfo::from(6, 3, false);
        let fifth = RangeBuf::from(b"eee", 9, false);
        let fifthinfo = RecvBufInfo::from(9, 3, false);
        let sixth = RangeBuf::from(b"fff", 11, false);
        let sixthinfo = RecvBufInfo::from(11, 3, false);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(fourth).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(fourthinfo).is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.data.len(), 3);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert_eq!(recv.heap.len(), 3);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 4);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert_eq!(recv.heap.len(), 3);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(sixth).is_ok());
            assert_eq!(recv.data.len(), 5);
        } else {
            assert!(recv.write_v3(sixthinfo).is_ok());
            assert_eq!(recv.heap.len(), 4);
        }
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(fifth).is_ok());
            assert_eq!(recv.len, 14);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), 6);
            let (len, fin) = recv.emit(&mut buf).unwrap();
            assert_eq!(len, 14);
            assert_eq!(fin, false);
            assert_eq!(&buf[..len], b"aabbbcdddeefff");
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(fifthinfo).is_ok());
            assert_eq!(recv.len, 14);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 5);
            assert!(app_buf.advance_if_possible(&mut recv).is_ok());
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 14);
            assert!(app_buf.has_consumed::<DefaultBufFactory>(None, 14).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 14);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(app_buf.read_mut(&mut recv).unwrap().len(), 0);
        }
    }
}
