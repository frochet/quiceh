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

use super::Chunk;
use super::RecvBufInfo;
use super::DEFAULT_STREAM_WINDOW;
use crate::bufpool::pool_or_default;
use crate::range_buf::RangeBuf;
use buffer_pool::Reuse;
use std::collections::btree_map;
use std::ops::Index;
use std::ops::IndexMut;
use std::ops::Range;
use std::ops::RangeFrom;
use std::ops::RangeFull;
use std::ops::RangeTo;

use branches::likely;

const MAX_STREAM_FRAME_LENGTH: usize = 1310;

/// Memory chunk containing contiguous stream frames' data
#[derive(Eq, PartialEq, Ord, PartialOrd, Default, Debug, Clone)]
pub struct StreamChunk {
    /// The offset value beginning this chunk of memory.
    pub(crate) stream_offset_start: u64,
    /// Data chunk.
    pub(crate) inner: Vec<u8>,
    /// number of bytes already consumed from inner.
    pub(crate) consumed: usize,
    /// offset indicating the position of the lowest non-readable byte.
    pub(crate) contiguous_off: usize,
}

impl Reuse for StreamChunk {
    fn reuse(&mut self, _trim: usize) -> bool {
        self.consumed = 0;
        self.contiguous_off = 0;
        self.stream_offset_start = u64::MAX;
        self.inner.len() > 0
    }
}

fn streamchunk_init(
    chunk: &mut StreamChunk, capacity: usize, stream_offset_start: u64,
) {
    let len = chunk.inner.len();
    if len < capacity {
        trace!(
            "Changing inner size. Was {}, now: {}",
            chunk.inner.len(),
            capacity
        );
        chunk.inner.reserve_exact(capacity - len);
        unsafe {
            chunk.inner.set_len(capacity);
        }
    } else if len > capacity {
        chunk.inner.truncate(capacity);
    }
    chunk.stream_offset_start = stream_offset_start;
}

impl StreamChunk {
    /// How many bytes are available to read in this chunk.
    pub fn len(&self) -> usize {
        self.contiguous_off.saturating_sub(self.consumed)
    }

    #[inline]
    pub(crate) fn capacity(&self) -> u64 {
        self.inner.len() as u64
    }

    #[inline]
    pub(crate) fn fill_from(&mut self, buf: &[u8], start_off: u64) -> usize {
        debug_assert!(
            start_off >= self.stream_offset_start
                && start_off < self.stream_offset_start + self.capacity(),
            "start_off is not into the correct range. start_off:{},\
                      chunk.stream_start_off:{}",
            start_off,
            self.stream_offset_start
        );
        let from = (start_off - self.stream_offset_start) as usize;
        let written = std::cmp::min(self.inner.len() - from, buf.len());
        self.inner[from..from + written].copy_from_slice(&buf[..written]);
        written
    }

    /// Tells whether the chunk is fully consumed.
    pub(crate) fn is_consumed(&self) -> bool {
        self.consumed == self.capacity() as usize
    }

    /// Returns the maximum offset this chunk may contain
    pub(crate) fn max_off(&self) -> u64 {
        self.stream_offset_start.saturating_add(self.capacity())
    }

    #[inline]
    /// provides ready-to-read reference to contiguous bytes.
    pub fn read<'a>(&'a self) -> &'a [u8] {
        &self.inner[self.consumed..self.contiguous_off]
    }
}

impl Index<usize> for StreamChunk {
    type Output = u8;

    fn index(&self, idx: usize) -> &Self::Output {
        let index = self.consumed + idx;
        if index > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.inner[index]
    }
}

impl IndexMut<usize> for StreamChunk {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        let index = self.consumed + idx;
        if index > self.contiguous_off {
            panic!("Out of bound access");
        }

        &mut self.inner[index]
    }
}

impl Index<Range<usize>> for StreamChunk {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        let start = range.start + self.consumed;
        let end = range.end + self.consumed;
        if start > self.contiguous_off || end > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.inner[start..end]
    }
}

impl IndexMut<Range<usize>> for StreamChunk {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        let start = range.start + self.consumed;
        let end = range.end + self.consumed;
        if start > self.contiguous_off || end > self.contiguous_off {
            panic!("Out of bound access");
        }

        &mut self.inner[start..end]
    }
}

impl Index<RangeFrom<usize>> for StreamChunk {
    type Output = [u8];

    fn index(&self, rangefrom: RangeFrom<usize>) -> &Self::Output {
        let start = rangefrom.start + self.consumed;
        if start > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.inner[start..self.contiguous_off]
    }
}

impl IndexMut<RangeFrom<usize>> for StreamChunk {
    fn index_mut(&mut self, rangefrom: RangeFrom<usize>) -> &mut Self::Output {
        let start = rangefrom.start + self.consumed;
        if start > self.contiguous_off {
            panic!("Out of bound access");
        }

        &mut self.inner[start..self.contiguous_off]
    }
}

impl Index<RangeTo<usize>> for StreamChunk {
    type Output = [u8];

    fn index(&self, rangeto: RangeTo<usize>) -> &Self::Output {
        let end = rangeto.end + self.consumed;
        if end > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.inner[self.consumed..end]
    }
}

impl IndexMut<RangeTo<usize>> for StreamChunk {
    fn index_mut(&mut self, rangeto: RangeTo<usize>) -> &mut Self::Output {
        let end = rangeto.end + self.consumed;
        if end > self.contiguous_off {
            panic!("Out of bound access");
        }

        &mut self.inner[self.consumed..end]
    }
}

impl Index<RangeFull> for StreamChunk {
    type Output = [u8];

    fn index(&self, _rangefull: RangeFull) -> &Self::Output {
        &self.inner[self.consumed..self.contiguous_off]
    }
}

impl IndexMut<RangeFull> for StreamChunk {
    fn index_mut(&mut self, _rangefull: RangeFull) -> &mut Self::Output {
        &mut self.inner[self.consumed..self.contiguous_off]
    }
}

impl AsRef<[u8]> for StreamChunk {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..]
    }
}

impl AsMut<[u8]> for StreamChunk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..]
    }
}

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

    /// chunks of the stream buf
    pub chunks: VecDeque<StreamChunk>,
    /// Max size of a StreamChunk's buffer
    max_chunklen: usize,

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
    pub fn new(
        max_data: u64, max_window: u64, max_chunklen: usize, version: u32,
    ) -> RecvBuf {
        let mut chunks = VecDeque::new();
        let chunk = pool_or_default()
            .get_with(|pooled| streamchunk_init(pooled, max_chunklen, 0));

        chunks.push_back(chunk.into_inner());
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(
                max_data,
                cmp::min(max_data, DEFAULT_STREAM_WINDOW),
                max_window,
            ),
            chunks,
            max_chunklen,
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

    pub(crate) fn advance_contiguous_bytes_if_any(&mut self) -> Result<()> {
        let mut max_off = self.off;
        debug_assert!(!self.chunks.is_empty(), "Should never be empty");
        let mut chunks_iter = self.chunks.iter_mut();
        // Chunks should never be empty when this function is called
        let mut chunk = chunks_iter
            .next()
            .expect("BUG: self.chunks should not be empty");
        while let Some((_, value)) = self.heap.first_key_value() {
            if value.start_off > self.contiguous_off {
                break;
            }
            let (_, recvbufinfo) = self.heap.pop_first().unwrap();

            // packets received not in order created a "full" overlap that we
            // might simply just safely ignore. I.e., the lower offest
            // info was last to be decrypted for this entry to be
            // there.
            if recvbufinfo.max_off() < max_off {
                // not <= to allow handling 0bytes FIN
                continue;
            }
            max_off = recvbufinfo.max_off();
            let mut this_len = recvbufinfo.len as u64;
            let this_offset = recvbufinfo.start_off;
            debug_assert!(
                this_offset > chunk.stream_offset_start,
                "Current chunk's starting offest is smaller than expected"
            );

            while chunk.max_off() < this_offset {
                chunk = chunks_iter.next().unwrap();
            }
            // We need to copy in case some out of order packet decryption
            // happened to avoid data corruption.
            if let Some(buf) = recvbufinfo.data() {
                trace!("Packet wasn't received in order; a copy is necessary");
                let mut written = chunk.fill_from(buf, this_offset);
                while written < recvbufinfo.len {
                    // we need to write into the next chunk
                    trace!("We need copying across chunks");
                    chunk = chunks_iter.next().expect(
                        "BUG: we should have available chunk to copy within",
                    );
                    let inter_write = chunk
                        .fill_from(&buf[written..], chunk.stream_offset_start);
                    written += inter_write;
                }
            }
            if recvbufinfo.start_off < self.contiguous_off {
                // We have a partial overlap. This could be caused by a
                // retransmission? Normally this event does not happen;
                // XXX I believe we reject these packets
                trace!(
                    "Partial overlap happened -- Could happen if this packet is\
                received first"
                );
                this_len = this_len
                    .saturating_sub(self.contiguous_off - recvbufinfo.start_off);
            }
            trace!(
                "Advancing self.contiguous_off to from {} to {}",
                self.contiguous_off,
                self.contiguous_off + this_len
            );
            self.contiguous_off += this_len;
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

    #[inline]
    pub fn emit_zc(&mut self) -> Result<(Chunk, bool)> {
        if let Some(e) = self.has_error() {
            self.heap.clear();
            self.deliver_fin = false;
            return Err(Error::StreamReset(e));
        }

        let chunk = self.chunks.front_mut().ok_or(Error::Done)?;
        if self.off < self.contiguous_off {
            if self.contiguous_off > chunk.max_off() {
                let len = chunk.capacity() - chunk.consumed as u64;
                chunk.contiguous_off = chunk.capacity() as usize;
                self.off += len;
            } else {
                let len = self.contiguous_off - self.off;
                self.off += len;
                chunk.contiguous_off += len as usize;
            }
        }

        if self.contiguous_off < chunk.max_off() && !self.is_fin() {
            return Err(Error::Done); // Maybe add a new error type to tell how
                                     // much may be read
                                     // from stream_peek()?
        }

        let chunk = self.chunks.pop_front().ok_or(Error::Done)?;
        // cleanup any hole.
        while let Some(entry) = self.maxoffs_order.first_entry() {
            if *entry.key() < self.contiguous_off {
                entry.remove_entry();
            } else {
                break;
            }
        }

        self.flow_control.add_consumed(chunk.len() as u64);

        let pooled = pool_or_default().from_owned(chunk);

        Ok((pooled, self.is_fin()))
    }

    /// Gives contiguous bytes as a mutable slice from the stream buffer's front.
    ///
    /// This function also increases self.off, which makes quiceh assumes
    /// these bytes have been delivered to the app.
    #[inline]
    pub fn read<'a>(&'a mut self) -> Result<(&'a [u8], bool)> {
        // We have received data in order, we can read it right away.
        let chunk = self.chunks.front_mut().ok_or(Error::Done)?;

        if self.off < self.contiguous_off
            && chunk.contiguous_off < chunk.capacity() as usize
        {
            if self.contiguous_off > chunk.max_off() {
                let len = chunk.capacity() - chunk.consumed as u64;
                chunk.contiguous_off = chunk.capacity() as usize;
                self.off += len;
            } else {
                let len = self.contiguous_off - self.off;
                self.off += len;
                chunk.contiguous_off =
                    (self.contiguous_off - chunk.stream_offset_start) as usize;
            }
        }
        // self.is_fin() is &self, but chunk is &mut self borrow
        let fin = self.fin_off == Some(self.off);

        Ok((chunk.read(), fin))
    }

    /// This function needs to be called to tell how much of the stream's buffer
    /// has been consumed by the application. It returns whether the buffer
    /// can be collected, and how many bytes are available for read.
    #[inline]
    pub fn mark_consumed(&mut self, consumed: usize) -> Result<(bool, usize)> {
        let chunk = self.chunks.front_mut().unwrap();
        if chunk.stream_offset_start == u64::MAX
            || chunk.consumed + consumed > chunk.capacity() as usize
        {
            return Err(Error::InvalidAPICall(
                "You may consuming more than what is available to read",
            ));
        }

        let checked_sub = chunk
            .contiguous_off
            .checked_sub(chunk.consumed + consumed)
            .ok_or(Error::InvalidAPICall(
                "Consumed more than what is available",
            ))?;

        chunk.consumed += consumed;

        trace!(
            "Consuming {} bytes, we have {} bytes left in chunk",
            consumed,
            chunk.len()
        );

        if consumed > 0 {
            self.flow_control.add_consumed(consumed as u64);
        }

        if let Some(entry) = self.maxoffs_order.first_entry() {
            if *entry.key() < self.contiguous_off {
                entry.remove_entry();
            }
        }

        let is_fully_consumed = chunk.is_consumed();
        let does_consumed_reach_coff = chunk.consumed == chunk.contiguous_off;

        // Serveral cases:
        // - did not consume all contiguous_off bytes (is_fin or !is_fin should be same behavior)
        // - consumed all contiguous_bytes but contiguous_bytes < chunk.capacity() && !is_fin
        // - consumed all contiguous_bytes and is_fin

        // let's recycle
        if is_fully_consumed || (does_consumed_reach_coff && self.is_fin()) {
            trace!("Chunk fully consumed. Sending it back to the pool");
            pool_or_default().from_owned(
                self.chunks.pop_front().expect("BUG: Chunks is empty"),
            );
        }

        if self.is_fin() && self.deliver_fin {
            self.deliver_fin = false;
        }

        Ok((
            self.heap.is_empty() && does_consumed_reach_coff && self.is_fin(),
            checked_sub,
        ))

        // TODO fixme: make sure we can still stream_peek() as long as
        // stream_consumed() wasn't called up the end of the stream.
        //else if chunk.contiguous_off == chunk.consumed {
        //// The stream has been collected, and the application has read
        //// everything. We can collect the buffer as well.
        //Ok((true, 0))
        //} else {
        //// The stream has been collected but the application didn't fully read
        //// the available data yet.
        //Ok((false, chunk.len()))
        //}
    }

    #[inline]
    pub(crate) fn is_contiguous_bytes_consumed(&self) -> bool {
        if let Some(chunk) = self.chunks.front() {
            // Should work if this is a recycled chunk too
            return chunk.contiguous_off == chunk.consumed;
        }
        // No more chunks; we delivered all of them.
        true
    }

    #[inline]
    pub(crate) fn insert_stream_chunk(&mut self, chunk: StreamChunk) -> usize {
        let idx = self.chunks.partition_point(|ch| {
            ch.stream_offset_start < chunk.stream_offset_start
        });
        self.chunks.insert(idx, chunk);
        idx + 1
    }

    /// From a given index in `self.chunks`, creates the chunks if it does not
    /// exist and set the appropriate stream_offset_start value for that
    /// chunk. If the chunk's capacity isn't large enough to contain `len`
    /// bytes, create more chunks until we can fit `len` bytes.
    #[inline]
    pub fn create_missing_chunks_and_copy(
        &mut self, idx: usize, buf: &[u8], toffset: u64,
    ) -> Result<()> {
        let mut idx = idx;
        let mut toffset = toffset;
        let mut written = 0;
        while written < buf.len() {
            match self.chunks.get_mut(idx) {
                Some(chunk) => {
                    if toffset < chunk.stream_offset_start {
                        // We have a gap and we need creating and inserting a new
                        // chunk to fill it (or part of the gap).
                        trace!(
                            "Copying across chunks: Adding a chunk to fill a gap"
                        );
                        let mut chunk = pool_or_default().get_with(|pooled| {
                            streamchunk_init(pooled, self.max_chunklen, toffset)
                        });
                        written += chunk.fill_from(&buf[written..], toffset);
                        toffset += chunk.capacity();
                        self.chunks.insert(idx, chunk.into_inner());
                    } else {
                        debug_assert!(
                            toffset == chunk.stream_offset_start,
                            "toffset: {}, stream_offset_start: {}",
                            toffset,
                            chunk.stream_offset_start
                        );
                        written += chunk.fill_from(
                            &buf[written..],
                            chunk.stream_offset_start,
                        );
                        toffset += chunk.capacity();
                    }
                    idx += 1;
                },
                None => {
                    trace!("Creating missing memory chunk at offset {} and {} bytes left to write", toffset, buf.len() - written);
                    let chunk = pool_or_default().get_with(|pooled| {
                        streamchunk_init(pooled, self.max_chunklen, toffset)
                    });
                    let mut chunk = chunk.into_inner();
                    written += chunk
                        .fill_from(&buf[written..], chunk.stream_offset_start);
                    toffset += chunk.capacity();
                    self.chunks.push_back(chunk);
                    idx += 1;
                },
            }
        }

        Ok(())
    }

    /// Returns a `Chunk` supposed to hold bytes starting at stream_offset % chunk_len
    #[inline]
    pub fn get_stream_chunk(&mut self, stream_offset: u64) -> Result<Chunk> {
        if stream_offset < self.contiguous_off {
            trace!(
                "We've received a packet holding an offset {} already \
                in our contiguous buffer but not yet read by the application.",
                stream_offset,
            );
            // In V3, we do not accept a packet that would overlap a contiguous
            // range of data already processed but not yet read by the
            // application. This could happen due to aggressive
            // retransmission; or intentional duplication. The packet is
            // dropped before payload decryption.
            return Err(Error::InvalidOffset);
        }

        if self.chunks.is_empty() {
            let chunk = pool_or_default().get_with(|pooled| {
                streamchunk_init(
                    pooled,
                    self.max_chunklen,
                    stream_offset - (stream_offset % self.max_chunklen as u64),
                )
            });

            self.chunks.push_back(chunk.into_inner());
        }

        let relative_buf_offset = stream_offset % self.max_chunklen as u64;

        if let Ok(index) = self.chunks.binary_search_by(|chunk| {
            if (chunk.stream_offset_start
                ..chunk.stream_offset_start.saturating_add(chunk.capacity()))
                .contains(&stream_offset)
            {
                std::cmp::Ordering::Equal
            } else if chunk.stream_offset_start < stream_offset {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        }) {
            // We have found the chunk which should the decrypted data. Does the
            // data fits within the chunk or is it data across chunks?
            let chunk = self.chunks.remove(index).unwrap();
            Ok(pool_or_default().from_owned(chunk))
        } else {
            // Not found. We have a hole, so we need a new chunk.
            let stream_offset_start = stream_offset - relative_buf_offset;
            trace!("Creating missing memory chunk");
            Ok(pool_or_default().get_with(|pooled| {
                streamchunk_init(pooled, self.max_chunklen, stream_offset_start)
            }))
        }
    }

    pub(crate) fn collect(&mut self) {
        for chunk in self.chunks.drain(..) {
            let _ = pool_or_default().from_owned(chunk);
        }
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

        if likely(self.version == crate::PROTOCOL_VERSION_VREVERSO) {
            self.contiguous_off = final_size;
            self.heap.clear();
            // clear all buffered data
            self.collect();
            // chunks should always have at least one element as long as
            // the fin flag is not consumed.
            let chunk = pool_or_default().get_with(|pooled| {
                streamchunk_init(pooled, self.max_chunklen, 0)
            });

            self.chunks.push_back(chunk.into_inner());

            let bufinfo = RecvBufInfo::from(final_size, 0, true);
            self.write_v3(bufinfo)?;
        } else {
            self.data.clear();

            // In order to ensure the application is notified when the stream is
            // reset, enqueue a zero-length buffer at the final size offset.
            let buf = RangeBuf::from(b"", final_size, true);
            self.write(buf)?;
        }

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

        if likely(self.version == crate::PROTOCOL_VERSION_VREVERSO) {
            self.heap.clear();
            self.deliver_fin = false;
            self.contiguous_off = self.max_off();
        } else {
            self.data.clear();
        };

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
        let ready = if likely(self.version == crate::PROTOCOL_VERSION_VREVERSO) {
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
        };
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHUNK_LEN;

    #[test]
    fn empty_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            let mut buf = [0; 32];

            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert!(recv.emit_zc().is_err());
        }
    }

    #[test]
    fn empty_stream_frame() {
        let mut recv = RecvBuf::new(
            15,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        let bufinfo = RecvBufInfo::from(0, 5, false);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(bufinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);

        let mut buf = [0; 32];

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Ok((5, false)));
        } else {
            assert_eq!((recv.read().unwrap().0.len(), recv.is_fin()), (5, false));
            assert!(recv.mark_consumed(5).is_ok());
        }

        // Don't store non-fin empty buffer.
        let buf = RangeBuf::from(b"", 10, false);
        let bufinfo = RecvBufInfo::from(10, 0, false);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(buf).is_ok());
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(bufinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert_eq!((recv.read().unwrap().0.len(), recv.is_fin()), (0, true));
        }
    }

    #[test]
    fn ordered_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.read().unwrap().0.len(), 0);
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.read().unwrap().0.len(), 0);
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.read().unwrap().0.len(), 19);
        }
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn split_read() {
        // TODO Double check; we don't need split logic in reverso since
        // we explicetly disallow overlapping contiguous bytes
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            let mut recv = RecvBuf::new(
                u64::MAX,
                DEFAULT_STREAM_WINDOW,
                DEFAULT_CHUNK_LEN,
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
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"helloworld", 9, true);
        let secondinfo = RecvBufInfo::from(9, 10, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.read().unwrap().0.len(), 0);
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 19);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.read().unwrap().0.len(), 19);
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
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let firstinfo = RecvBufInfo::from(0, 9, false);
        let second = RangeBuf::from(b"", 9, true);
        let secondinfo = RecvBufInfo::from(9, 0, true);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 1);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert_eq!(recv.read().unwrap().0.len(), 9);
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
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 9);
            assert!(recv.mark_consumed(9).is_ok());
            assert_eq!(recv.is_fin(), false);
        }

        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION != crate::PROTOCOL_VERSION_VREVERSO {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 0);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 9);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 9);
            assert!(recv.mark_consumed(9).is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read2() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.read().unwrap().0.len(), 9);
            assert!(recv.mark_consumed(9).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read3() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 9);
            assert!(recv.mark_consumed(9).is_ok());
        }

        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn fully_overlapping_read_multi() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 18);
            assert_eq!(recv.off, 0);
            // firstinfo is contiguous; it does not go through the heap.
            // However it allows to make progress on what was inside
            // the heap.
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 18);
            assert!(recv.mark_consumed(18).is_ok());
        }
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 18);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn overlapping_start_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 9);
            assert!(recv.mark_consumed(9).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 9);
        }
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn overlapping_end_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 12);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 12);
            assert!(recv.mark_consumed(12).is_ok());
            assert!(recv.is_fin());
        }
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 12);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read(), Err(Error::Done));
        }
    }

    #[test]
    fn overlapping_end_twice_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 3);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 9);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 2);
            assert_eq!(recv.read().unwrap().0.len(), 2);
            assert!(recv.mark_consumed(2).is_ok());
            assert!(!recv.is_fin());
        }

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn overlapping_end_twice_and_contained_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 3);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 16);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 2);
            assert_eq!(recv.read().unwrap().0.len(), 5);
            assert!(recv.mark_consumed(5).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.len, 16);
            assert_eq!(recv.off, 5);
        }

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn partially_multi_overlapping_reordered_read() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(second).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(secondinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 0);
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
            assert_eq!(recv.len, 15);
            assert_eq!(recv.off, 15);
        } else {
            assert_eq!(recv.write_v3(thirdinfo), Err(Error::InvalidOffset));
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 13);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 13);
            assert!(recv.mark_consumed(13).is_ok());
            assert!(!recv.is_fin());
            assert_eq!(recv.len, 13);
            assert_eq!(recv.off, 13);
        }

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            // We're not fin yet but we have nothing to read, so read returns 0 bytes.
            // Should we do Error::Done?
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn partially_multi_overlapping_reordered_read2() {
        let mut recv = RecvBuf::new(
            u64::MAX,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_CHUNK_LEN,
            crate::PROTOCOL_VERSION,
        );
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 1);
        }
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(fourth).is_ok());
            assert_eq!(recv.data.len(), 2);
        } else {
            assert!(recv.write_v3(fourthinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 2);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(third).is_ok());
            assert_eq!(recv.data.len(), 3);
        } else {
            assert!(recv.write_v3(thirdinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 3);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(first).is_ok());
            assert_eq!(recv.data.len(), 4);
        } else {
            assert!(recv.write_v3(firstinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 0);
        }
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert!(recv.write(sixth).is_ok());
            assert_eq!(recv.data.len(), 5);
        } else {
            assert!(recv.write_v3(sixthinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 1);
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
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.len, 14);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.heap.len(), 0);
            assert_eq!(recv.read().unwrap().0.len(), 14);
            assert!(recv.mark_consumed(14).is_ok());
            assert!(!recv.is_fin());
        }
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 14);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(recv.emit(&mut buf), Err(Error::Done));
        } else {
            assert_eq!(recv.read().unwrap().0.len(), 0);
        }
    }

    #[test]
    fn indexable_chunks() {
        let mut chunk = pool_or_default()
            .get_with(|pooled| streamchunk_init(pooled, 42, 0))
            .into_inner();
        chunk.inner = vec![0; 42]; // override init
        chunk.contiguous_off = 42;
        assert_eq!(chunk.len(), 42);
        chunk[10] = 66;
        // consume 1 byte
        chunk.consumed = 1;
        assert_eq!(chunk.len(), 41);
        assert_eq!(chunk[9], 66);
        assert_eq!(chunk[..10], [0, 0, 0, 0, 0, 0, 0, 0, 0, 66]);
        chunk.consumed = 2;
        assert_eq!(chunk[..10], [0, 0, 0, 0, 0, 0, 0, 0, 66, 0]);
        assert_eq!(chunk[..].len(), 40);
    }

    #[test]
    fn empty_stream_frame_emitted() {
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            let mut recv = RecvBuf::new(
                15,
                DEFAULT_STREAM_WINDOW,
                DEFAULT_CHUNK_LEN,
                crate::PROTOCOL_VERSION,
            );

            let bufinfo = RecvBufInfo::from(0, 5, false);
            assert!(recv.write_v3(bufinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 0);

            assert_eq!(recv.off, 0);
            // We have 5 bytes in without the fin bit set, and the chunk is 100
            // bytes wide, we cannot emit.
            assert!(recv.emit_zc().is_err());

            // Store fin empty buffer.
            let bufinfo = RecvBufInfo::from(5, 0, true);
            assert!(recv.write_v3(bufinfo).is_ok());
            assert!(recv.advance_contiguous_bytes_if_any().is_ok());
            assert_eq!(recv.heap.len(), 0);

            assert_eq!(recv.off, 5);

            // An empty stream frame with a fin bit has been received, we should
            // now be emit the chunk
            let (chunk, fin) = recv.emit_zc().unwrap();
            assert_eq!((chunk.len(), fin), (5, true));

            // There is nothing else to emit.
            assert!(recv.emit_zc().is_err());
        }
    }
}
