//! An internal zero-copy (in expectation) QUIC buffering for QUIC VReverso
//!
//! A [`AppRecvBufMap`] is an object holding all receiving stream buffers for the current QUIC VReverso
//! connection. One must be created per QUIC connection.
//!
//! Each buffer is cut into chunks of `chunklen` length and can be set by the caller using
//! [`set_expected_chunklen_to_consume()`]. The caller would chose a length (in bytes) linked to
//! how much it would expect to consume data at once. If this length is larger than a Stream Frame,
//! data will be moved in zero-copy. Copies happen at the boundary of a chunk. The larger are the
//! chunks, the less likely a copy could be needed while received Stream data.
//!
//! The maximum memory that could be consumed would depends on [`set_max_chunks_buffered()`] that
//! limits the maximum number of chunks that could be created.
//!
//! This object's data in manipulated through [`stream_peek()`], [`stream_consumed()`] and
//! [`stream_recv_zc()`]
//!
//!
//! [`AppRecvBufMap`]: struct.AppRecvBufMap
//! [`set_expected_chunklen_to_consume()`]: struct.AppRecvBufMap.html#method.set_expected_chunklen_to_consume
//! [`set_max_chunks_buffered()`]: struct.AppRecvBufMap.html#method.set_max_chunks_buffered
//! [`set_max_chunks_recycled`]: struct.AppRecvBufMap.html#method.set_max_chunks_recycled
//! [`stream_peek()`] struct.Connection.html#method.stream_peek
//! [`stream_consumed()`] struct.Connection.html#method.stream_consumed
//! [`stream_recv_zc()`] struct.Connection.html#method.stream_recv_zc

use super::recv_buf::RecvBuf;
use super::Stream;
use super::DEFAULT_STREAM_WINDOW;
use crate::BufFactory;
use std::collections::hash_map;
use std::collections::VecDeque;
use std::num::NonZero;
use std::ops::Index;
use std::ops::IndexMut;
use std::ops::Range;
use std::ops::RangeFrom;
use std::ops::RangeFull;
use std::ops::RangeTo;

use crate::Error;
use crate::Result;


/// Buffer map containing the stream buffers
pub struct AppRecvBufMap {
    /// The stream buffers.
    buffers: crate::stream::StreamIdHashMap<AppRecvBuf>,

    /// Contains heap-allocated AppRecvBuf that could be recycled if needed.
    recycled_buffers: VecDeque<AppRecvBuf>,

    /// Maximum number of memory chunks buffered
    max_chunks_buffered: u64,

    /// Maximum number of bidi buffers that could exist at anytime.
    max_streams_bidi: u64,

    /// Maximum number of peer uni buffers that could exist at anytime.
    max_streams_uni_remote: u64,

    current_bidi: u64,
    current_remote: u64,

    /// The application tells us how much it expects to read before consuming.
    chunklen: Option<usize>,

    /// Max number of chunks to keep into a recycled buffer
    max_chunks_recycled: Option<usize>,
}

impl Default for AppRecvBufMap {
    fn default() -> Self {
        AppRecvBufMap {
            buffers: crate::stream::StreamIdHashMap::<AppRecvBuf>::default(),
            recycled_buffers: VecDeque::with_capacity(3),
            max_chunks_buffered: 328, /* 10MiB with chunklen being
                                       * DEFAULT_STREAM_WINDOW. This */
            // should ideally be slightly higher than stream limits to
            // hold temporary controls.
            max_streams_bidi: 100_000,
            max_streams_uni_remote: 100_000,
            current_bidi: 0,
            current_remote: 0,
            chunklen: Some(DEFAULT_STREAM_WINDOW as usize),
            max_chunks_recycled: None,
        }
    }
}

impl AppRecvBufMap {
    /// new map passing config information about stream management
    pub fn new(
        recycled_capacity: usize, max_streams_bidi: u64,
        max_streams_uni_remote: u64,
    ) -> AppRecvBufMap {
        AppRecvBufMap {
            recycled_buffers: VecDeque::with_capacity(recycled_capacity),
            max_streams_bidi,
            max_streams_uni_remote,
            ..Default::default()
        }
    }

    /// The application should set the expected chunklen they expect to consume
    /// after one or more `stream_peek()` are called.
    #[inline]
    pub fn set_expected_chunklen_to_consume(
        &mut self, chunklen: std::num::NonZeroUsize,
    ) -> Result<()> {
        let chunklen = chunklen.get().into();
        if chunklen < crate::PAYLOAD_MIN_LEN_WITH_TAG {
            return Err(Error::InvalidAPICall("chunklen cannot be smaller than {crate::PAYLOAD_MIN_LEN_WITH_TAG}"));
        }

        self.chunklen = Some(chunklen);

        Ok(())
    }

    /// Limits the amount of recycled chunks within a recycled buffer.
    #[inline]
    pub fn set_max_chunks_recycled(&mut self, max_chunks_recycled: usize) {
        self.max_chunks_recycled = Some(max_chunks_recycled);
    }

    /// Limits the number of chunks within a buffer.
    #[inline]
    pub fn set_max_chunks_buffered(&mut self, max_chunks_buffered: u64) {
        self.max_chunks_buffered = max_chunks_buffered
    }

    /// retrieve or create a stream buffer for a given stream_id
    pub(crate) fn get_or_create_stream_buffer(
        &mut self, stream_id: u64,
    ) -> Result<&mut AppRecvBuf> {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                let buf = if let Some(mut buf) = self.recycled_buffers.pop_front()
                {
                    buf.stream_id = stream_id;
                    buf
                } else {
                    if super::is_bidi(stream_id) {
                        self.current_bidi += 1;
                    } else if !super::is_even(stream_id) {
                        // Todo change this to check is_remote_uni
                        self.current_remote += 1;
                    }

                    if self.current_bidi > self.max_streams_bidi ||
                        self.current_remote > self.max_streams_uni_remote
                    {
                        return Err(Error::IdLimit);
                    }

                    AppRecvBuf::new(
                        stream_id,
                        self.chunklen
                            .unwrap_or(super::DEFAULT_STREAM_WINDOW as usize),
                        self.max_chunks_buffered,
                    )
                };
                Ok(v.insert(buf))
            },
            hash_map::Entry::Occupied(v) => Ok(v.into_mut()),
        }
    }

    /// get the stream_id's buffer starting at the first non-consumed byte.
    pub fn get(&self, stream_id: u64) -> Option<&[u8]> {
        self.buffers.get(&stream_id).map(|buf| buf.get())
    }

    /// get a mutable reference to the stream_id's buffer starting at the first
    /// non-consumed byte.
    pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut [u8]> {
        self.buffers.get_mut(&stream_id).map(|buf| buf.get_mut())
    }

    pub(crate) fn read_mut<F: BufFactory>(
        &mut self, stream_id: u64, stream: &mut Stream<F>,
    ) -> Result<&mut [u8]> {
        let buf = match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => {
                return Err(Error::AppRecvBufNotFound);
            },
            hash_map::Entry::Occupied(v) =>
                v.into_mut().read_mut(&mut stream.recv)?,
        };
        Ok(buf)
    }

    pub(crate) fn emit<F: BufFactory>(
        &mut self, stream_id: u64, stream: &mut Stream<F>,
    ) -> Result<(StreamChunk, bool)> {
        let buf = match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => {
                return Err(Error::AppRecvBufNotFound);
            },
            hash_map::Entry::Occupied(v) =>
                v.into_mut().emit(&mut stream.recv)?,
        };
        Ok(buf)
    }

    pub(crate) fn advance_if_possible<F: BufFactory>(
        &mut self, stream_id: u64, stream: &mut Stream<F>,
    ) -> Result<()> {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => Err(Error::AppRecvBufNotFound),
            hash_map::Entry::Occupied(v) =>
                v.into_mut().advance_if_possible(&mut stream.recv),
        }
    }

    pub(crate) fn has_consumed<F: BufFactory>(
        &mut self, stream_id: u64, stream: Option<&Stream<F>>, consumed: usize,
    ) -> Result<usize> {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Occupied(v) => {
                // Registers how much the app has read on this stream buffer. If
                // we don't have a stream, it means it has been
                // collected. We need to collect our stream buffer
                // as well assuming the application has read everything that was
                // readable.
                let (to_collect, remaining_data) =
                    v.into_mut().has_consumed(stream, consumed)?;
                if to_collect {
                    self.collect(stream_id);
                }
                Ok(remaining_data)
            },
            _ => Ok(0),
        }
    }

    pub(crate) fn is_consumed(&self, stream_id: u64) -> bool {
        match self.buffers.get(&stream_id) {
            Some(v) => v.is_contiguous_bytes_consumed(),
            _ => true,
        }
    }

    pub(crate) fn collect(&mut self, stream_id: u64) {
        if let Some(mut buf) = self.buffers.remove(&stream_id) {
            if self.recycled_buffers.len() < self.recycled_buffers.capacity() {
                if let Some(max_chunks_recycled) = self.max_chunks_recycled {
                    if buf.chunks.len() > max_chunks_recycled {
                        buf.chunks.drain(max_chunks_recycled..);
                    }
                }
                // clear any chunks
                for chunk in buf.chunks.iter_mut() {
                    chunk.stream_offset_start = u64::MAX;
                    chunk.consumed = 0;
                    chunk.contiguous_off = 0;
                }
                self.recycled_buffers.push_back(buf);
            }
        }
    }
}

pub(crate) enum StreamChunkMem {
    NewlyAllocated(StreamChunk, usize),
    /// MayNeedCopyAcross means this StreamChunk may only hold
    /// part of the stream data about to be decrypted. We don't
    /// know yet since control info is encrypted within.
    NewlyAllocatedMayNeedCopyAcross(StreamChunk),
    NotNewlyAllocated(StreamChunk, usize),
    NotNewlyAllocatedMayNeedCopyAcross(StreamChunk),
}

impl std::ops::Deref for StreamChunkMem {
    type Target = StreamChunk;

    fn deref(&self) -> &Self::Target {
        match self {
            StreamChunkMem::NewlyAllocated(c, _) => c,
            StreamChunkMem::NewlyAllocatedMayNeedCopyAcross(c) => c,
            StreamChunkMem::NotNewlyAllocated(c, _) => c,
            StreamChunkMem::NotNewlyAllocatedMayNeedCopyAcross(c) => c,
        }
    }
}

impl std::ops::DerefMut for StreamChunkMem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            StreamChunkMem::NewlyAllocated(c, _) => c,
            StreamChunkMem::NewlyAllocatedMayNeedCopyAcross(c) => c,
            StreamChunkMem::NotNewlyAllocated(c, _) => c,
            StreamChunkMem::NotNewlyAllocatedMayNeedCopyAcross(c) => c,
        }
    }
}

/// Memory chunk containing contiguous stream frames' data
#[derive(Eq, PartialEq, Ord, PartialOrd, Default, Clone)]
pub struct StreamChunk {
    /// The offset value beginning this chunk of memory.
    pub(crate) stream_offset_start: u64,
    /// Data chunk.
    pub(crate) outbuf: Box<[u8]>,
    /// number of bytes already consumed from outbuf.
    pub(crate) consumed: usize,
    /// offset indicating the position of the lowest non-readable byte.
    pub(crate) contiguous_off: usize,
}

impl StreamChunk {
    fn new(capacity: std::num::NonZeroUsize, stream_offset_start: u64) -> Self {
        StreamChunk {
            outbuf: vec![0; capacity.get().into()].into_boxed_slice(),
            stream_offset_start,
            ..Default::default()
        }
    }

    /// How many bytes are available to read in this chunk.
    pub fn len(&self) -> usize {
        self.contiguous_off.saturating_sub(self.consumed)
    }

    pub(crate) fn capacity(&self) -> u64 {
        self.outbuf.len() as u64
    }

    pub(crate) fn fill_from(&mut self, buf: &[u8], start_off: u64) -> usize {
        debug_assert!(
            start_off >= self.stream_offset_start &&
                start_off < self.stream_offset_start + self.capacity(),
            "start_off is not into the correct range. start_off:{},\
                      chunk.stream_start_off:{}",
            start_off,
            self.stream_offset_start
        );
        let from = (start_off - self.stream_offset_start) as usize;
        let written = std::cmp::min(self.outbuf.len() - from, buf.len());
        self.outbuf[from..from + written].copy_from_slice(&buf[..written]);
        written
    }

    /// Tells whether the chunk is fully consumed.
    pub(crate) fn is_consumed(&self) -> bool {
        self.consumed == self.capacity() as usize
    }

    pub(crate) fn max_off(&self) -> u64 {
        self.stream_offset_start.saturating_add(self.capacity())
    }

    #[inline]
    /// provides ready-to-read mutable reference to contiguous bytes.
    pub fn unread_mut(&mut self) -> &mut [u8] {
        &mut self.outbuf[self.consumed..self.contiguous_off]
    }
}

impl Index<usize> for StreamChunk {
    type Output = u8;

    fn index(&self, idx: usize) -> &Self::Output {
        let index = self.consumed + idx;
        if index > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.outbuf[index]
    }
}

impl IndexMut<usize> for StreamChunk {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        let index = self.consumed + idx;
        if index > self.contiguous_off {
            panic!("Out of bound access");
        }

        &mut self.outbuf[index]
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

        &self.outbuf[start..end]
    }
}

impl Index<RangeFrom<usize>> for StreamChunk {
    type Output = [u8];

    fn index(&self, rangefrom: RangeFrom<usize>) -> &Self::Output {
        let start = rangefrom.start + self.consumed;
        if start > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.outbuf[start..self.contiguous_off]
    }
}

impl Index<RangeTo<usize>> for StreamChunk {
    type Output = [u8];

    fn index(&self, rangeto: RangeTo<usize>) -> &Self::Output {
        let end = rangeto.end + self.consumed;
        if end > self.contiguous_off {
            panic!("Out of bound access");
        }

        &self.outbuf[self.consumed..end]
    }
}

impl Index<RangeFull> for StreamChunk {
    type Output = [u8];

    fn index(&self, _rangefull: RangeFull) -> &Self::Output {
        &self.outbuf[self.consumed..self.contiguous_off]
    }
}

impl AsRef<[u8]> for StreamChunk {
    fn as_ref(&self) -> &[u8] {
        &self.outbuf[..]
    }
}

impl AsMut<[u8]> for StreamChunk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.outbuf[..]
    }
}

/// A stream buffer. This is where received data gets decrypted.
#[derive(Default)]
pub struct AppRecvBuf {
    /// chunks of the stream buf
    pub chunks: VecDeque<StreamChunk>,
    /// Stream id of the stream linked to this buffer.
    stream_id: u64,
    /// Max size of a StreamChunk's buffer
    max_chunklen: usize,
    /// Max number of chunks that should hold chunks
    max_chunks_buffered: u64,
}

impl AppRecvBuf {
    pub fn new(
        stream_id: u64, app_chunklen: usize, max_chunks_buffered: u64,
    ) -> AppRecvBuf {
        let mut chunks = VecDeque::new();
        chunks
            .push_back(StreamChunk::new(NonZero::new(app_chunklen).unwrap(), 0));
        AppRecvBuf {
            chunks,
            stream_id,
            max_chunklen: app_chunklen,
            max_chunks_buffered,
            ..Default::default()
        }
    }

    pub fn advance_if_possible(&mut self, recv: &mut RecvBuf) -> Result<()> {
        let mut max_off = recv.off;
        debug_assert!(self.chunks.len() > 0, "Should never be empty");
        let mut chunks_iter = self.chunks.iter_mut();
        // Chunks should never be empty when this function is called
        let mut chunk = chunks_iter.next().unwrap();
        while recv.ready() {
            // ready() already ensures we have something to pop()
            let entry = recv.heap.first_entry().unwrap();
            let recvbufinfo = entry.remove();
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
            debug_assert!(this_offset > chunk.stream_offset_start, "Current chunk's starting offest is smaller than expected");

            while chunk.max_off() < this_offset {
                chunk = chunks_iter.next().unwrap();
            }
            // We need to copy in case some out of order packet decryption
            // happened to avoid data corruption.
            if let Some(buf) = recvbufinfo.data() {
                trace!("Packet wasn't received in order; a copy is necessary");
                let mut written = chunk.fill_from(&buf, this_offset);
                while written < recvbufinfo.len {
                    // we need to write into the next chunk
                    trace!("We need copying across chunks");
                    chunk = chunks_iter.next().unwrap();
                    let inter_write = chunk
                        .fill_from(&buf[written..], chunk.stream_offset_start);
                    written += inter_write;
                }
            }
            if recvbufinfo.start_off < recv.contiguous_off {
                // We have a partial overlap. This could be caused by a
                // retransmission? Normally this event does not happen;
                // XXX I believe we reject these packets
                trace!(
                    "Partial overlap happened -- Could happen if this packet is\
                received first"
                );
                this_len = this_len
                    .saturating_sub(recv.contiguous_off - recvbufinfo.start_off);
            }
            trace!("Advancing recv.contiguous_off to {}", recv.contiguous_off);
            recv.contiguous_off += this_len;
        }
        Ok(())
    }

    #[inline]
    pub fn emit(&mut self, recv: &mut RecvBuf) -> Result<(StreamChunk, bool)> {
        if let Some(e) = recv.has_error() {
            recv.heap.clear();
            recv.deliver_fin = false;
            return Err(Error::StreamReset(e));
        }

        let chunk = self.chunks.get_mut(0).ok_or(Error::Done)?;
        if recv.off < recv.contiguous_off {
            if recv.contiguous_off > chunk.max_off() {
                let len = chunk.capacity() - chunk.consumed as u64;
                chunk.contiguous_off = chunk.capacity() as usize;
                recv.off += len;
            } else {
                let len = recv.contiguous_off - recv.off;
                recv.off += len;
                chunk.contiguous_off = len as usize;
            }
        }

        if recv.contiguous_off < chunk.max_off() && !recv.is_fin() {
            return Err(Error::Done); // Maybe add a new error type to tell how
                                     // much may be read
                                     // from stream_peek()?
        }

        let chunk = self.chunks.pop_front().ok_or(Error::Done)?;
        // cleanup any hole.
        while let Some(entry) = recv.maxoffs_order.first_entry() {
            if *entry.key() < recv.contiguous_off {
                entry.remove_entry();
            } else {
                break;
            }
        }

        recv.flow_control.add_consumed(chunk.len() as u64);

        Ok((chunk, recv.is_fin()))
    }

    /// gives contiguous bytes as a mutable slice from the stream buffer.
    #[inline]
    pub fn read_mut(&mut self, recv: &mut RecvBuf) -> Result<&mut [u8]> {
        let mut len = 0;
        // We have received data in order, we can read it right away.
        let chunk = self.chunks.get_mut(0).unwrap();
        if recv.contiguous_off > recv.off &&
            chunk.contiguous_off < chunk.capacity() as usize
        {
            if recv.contiguous_off < chunk.max_off() {
                len += recv.contiguous_off - recv.off;
                recv.off += len;
                chunk.contiguous_off =
                    (recv.contiguous_off - chunk.stream_offset_start) as usize;
            } else {
                len += chunk.max_off() - recv.off;
                recv.off += len;
                chunk.contiguous_off = chunk.capacity() as usize;
            }
        }

        // cleanup any hole.
        while let Some(entry) = recv.maxoffs_order.first_entry() {
            if *entry.key() < recv.contiguous_off {
                entry.remove_entry();
            } else {
                break;
            }
        }

        if recv.is_fin() && recv.deliver_fin {
            recv.deliver_fin = false;
        }

        if len > 0 {
            recv.flow_control.add_consumed(len);
        }

        Ok(chunk.unread_mut())
    }

    /// This function needs to be called to tell how much of the stream's buffer
    /// has been consumed by the application. It returns whether the buffer
    /// can be collected, and how many bytes are available for read.
    #[inline]
    pub fn has_consumed<F: BufFactory>(
        &mut self, stream: Option<&Stream<F>>, consumed: usize,
    ) -> Result<(bool, usize)> {
        let chunk = self.chunks.get_mut(0).unwrap();
        if chunk.stream_offset_start == u64::MAX  || chunk.consumed + consumed > chunk.capacity() as usize {
            return Err(Error::InvalidAPICall(
                "You may consuming more than what is available to read",
            ));
        }

        chunk.consumed += consumed;
        trace!("Consuming {} bytes, we have {} bytes left in chunk", consumed, chunk.len());

        if let Some(stream) = stream {
            if stream.recv.heap.is_empty() &&
                chunk.contiguous_off == chunk.consumed &&
                !stream.recv.is_fin()
            {
                // let's recycle
                if chunk.is_consumed() {
                    trace!("Chunk fully consumed. Rotating.");
                    chunk.consumed = 0;
                    chunk.contiguous_off = 0;
                    chunk.stream_offset_start = u64::MAX;
                    self.chunks.rotate_left(1);
                }
                // we don't want to collect our buffer.
                Ok((false, 0))
            } else {
                // either the stream is_fin() but the app didn't fully read it
                // yet. Or the stream !is_fin() and the app didn't
                // fully read what was available. In either case, the
                // buffer needs to remain available for the application.
                let checked_sub =
                    chunk.contiguous_off.checked_sub(chunk.consumed);
                // let's recycle
                if chunk.is_consumed() {
                    trace!("Chunk fully consumed. Rotating.");
                    chunk.consumed = 0;
                    chunk.contiguous_off = 0;
                    chunk.stream_offset_start = u64::MAX;
                    self.chunks.rotate_left(1);
                }
                // we don't want to collect our buffer.
                Ok((
                    false,
                    checked_sub.ok_or(Error::InvalidAPICall(
                        "You may have consumed more than what was \
                             available to read",
                    ))?,
                ))
            }
        } else if chunk.contiguous_off == chunk.consumed {
            // The stream has been collected, and the application has read
            // everything. We can collect the buffer as well.
            Ok((true, 0))
        } else {
            // The stream has been collected but the application didn't fully read
            // the available data yet.
            Ok((false, chunk.len()))
        }
    }

    /// Get a reference to the whole lowest chunk
    #[inline]
    pub fn get(&self) -> &[u8] {
        self.chunks.get(0).unwrap().as_ref()
    }

    /// Get a mutable reference to the whole lowest chunk
    #[inline]
    pub fn get_mut(&mut self) -> &mut [u8] {
        self.chunks.get_mut(0).unwrap().as_mut()
    }

    #[inline]
    pub fn is_contiguous_bytes_consumed(&self) -> bool {
        if let Some(chunk) = self.chunks.get(0) {
            // Should work if this is a recycled chunk too
            return chunk.contiguous_off == chunk.consumed
        }
        // No more chunks; we delivered all of them.
        true
    }

    #[inline]
    pub fn insert_stream_chunk(&mut self, chunk: StreamChunk) -> usize {
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
                    if chunk.stream_offset_start == u64::MAX {
                        // this is a recycled chunk
                        chunk.stream_offset_start = toffset;
                    }
                    if toffset < chunk.stream_offset_start {
                        // We have a gap and we need creating and inserting a new
                        // chunk to fill it (or part of the gap).
                        trace!("Copying acrosss chunks: Adding a chunk to fill a gap");
                        let mut chunk = StreamChunk::new(
                            NonZero::new(self.max_chunklen).unwrap(),
                            toffset,
                        );
                        written += chunk
                            .fill_from(&buf[written..], toffset);
                        toffset += chunk.capacity();
                        self.chunks.insert(idx, chunk);
                    } else {

                        debug_assert!(
                            toffset == chunk.stream_offset_start,
                            "toffset: {}, stream_offset_start: {}",
                            toffset,
                            chunk.stream_offset_start
                        );
                        written += chunk
                            .fill_from(&buf[written..], chunk.stream_offset_start);
                        toffset += chunk.capacity();
                    }
                    idx += 1;
                },
                None => {
                    trace!("Creating missing memory chunk");
                    let mut chunk = StreamChunk::new(
                        NonZero::new(self.max_chunklen).unwrap(),
                        toffset,
                    );
                    written += chunk
                        .fill_from(&buf[written..], chunk.stream_offset_start);
                    toffset += chunk.capacity();
                    self.chunks.push_back(chunk);
                    idx += 1;
                },
            }
        }
        // We send an error back after copying to avoid loosing acknowledged bytes
        if self.chunks.len() as u64 > self.max_chunks_buffered {
            trace!("Too many chunks! {}", self.chunks.len());
            return Err(Error::TooManyChunksBuffered);
        }

        Ok(())
    }

    /// Returns a chunk of memory and tells the caller whether the chunk already
    /// existed or was created to comply to the demand. It always returns a
    /// memory chunk, unless the provided offset is below already received
    /// contiguous data.
    ///
    /// Returns a `StreamChunkMem` enum variant.
    #[inline]
    pub fn get_stream_chunk(
        &mut self, stream_offset: u64, to_reserve: u64, recv: &RecvBuf,
    ) -> Result<StreamChunkMem> {
        if stream_offset < recv.contiguous_off {
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
            let chunk = StreamChunk::new(
                NonZero::new(self.max_chunklen).unwrap(),
                stream_offset - (stream_offset % self.max_chunklen as u64),
            );
            self.chunks.push_back(chunk);
        }

        let relative_buf_offset = stream_offset % self.max_chunklen as u64;

        if let Ok(index) = self.chunks.binary_search_by(|chunk| {
            if (chunk.stream_offset_start..
                chunk.stream_offset_start.saturating_add(chunk.capacity()))
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
            if stream_offset + to_reserve <= chunk.max_off() {
                Ok(StreamChunkMem::NotNewlyAllocated(
                    chunk,
                    relative_buf_offset as usize,
                ))
            } else {
                Ok(StreamChunkMem::NotNewlyAllocatedMayNeedCopyAcross(chunk))
            }
        } else {
            // Not found. We have a hole, so we need a new chunk. -- try to
            // recycle one first.
            let (chunk, newly_alloc) = {
                let chunk = self.chunks.back().unwrap();
                if chunk.stream_offset_start == u64::MAX {
                    let mut chunk = self.chunks.pop_back().unwrap();
                    chunk.stream_offset_start =
                        stream_offset - relative_buf_offset;
                    (chunk, false)
                } else {
                    let stream_offset_start = stream_offset - relative_buf_offset;
                    if self.chunks.len() as u64 >= self.max_chunks_buffered {
                        trace!("Too many chunks! {}", self.chunks.len());
                        return Err(Error::TooManyChunksBuffered);
                    }
                    trace!("Creating missing memory chunk");
                    (StreamChunk::new(
                        NonZero::new(self.max_chunklen).unwrap(),
                        stream_offset_start,
                    ),
                    true)
                }
            };

            if stream_offset + to_reserve <= chunk.max_off() {
                if newly_alloc {
                    Ok(StreamChunkMem::NewlyAllocated(
                        chunk,
                        relative_buf_offset as usize,
                    ))
                } else {
                    Ok(StreamChunkMem::NotNewlyAllocated(
                            chunk,
                            relative_buf_offset as usize,
                    ))
                }
            } else {
                if newly_alloc {
                    Ok(StreamChunkMem::NewlyAllocatedMayNeedCopyAcross(chunk))
                } else {
                    Ok(StreamChunkMem::NotNewlyAllocatedMayNeedCopyAcross(chunk))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::RecvBufInfo;

    #[test]
    fn create_and_collect_bufs() {
        let mut app_buf = AppRecvBufMap::new(3, 10, 10);
        let _buf_stream_4 = app_buf.get_or_create_stream_buffer(4).unwrap();

        app_buf.collect(4);
        assert_eq!(app_buf.recycled_buffers.len(), 1);
        let _buf_stream_8 = app_buf.get_or_create_stream_buffer(8).unwrap();
        // use a collected buffer.
        assert_eq!(app_buf.recycled_buffers.len(), 0);
    }

    #[test]
    fn appbuf_streambuffer_read() {
        let mut recv = RecvBuf::new(
            100,
            DEFAULT_STREAM_WINDOW,
            crate::PROTOCOL_VERSION_VREVERSO,
        );
        let mut app_buf = AppRecvBufMap::new(3, 10, 10);
        let buf_stream_4 = app_buf.get_or_create_stream_buffer(4).unwrap();

        let writeinfo = RecvBufInfo::from(0, 5, false);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            assert!(recv.write_v3(writeinfo).is_ok());
            assert_eq!(buf_stream_4.read_mut(&mut recv).unwrap().len(), 5);
        }
    }

    #[test]
    fn indexable_chunks() {
        let mut chunk = StreamChunk::new(NonZero::new(42).unwrap(), 0);
        chunk.contiguous_off = 42;
        assert_eq!(chunk.len(), 42);
        chunk[10] = 66;
        // consume 1 byte
        chunk.consumed = 1;
        assert_eq!(chunk.len(), 41);
        assert_eq!(chunk[9], 66);
        assert_eq!(chunk[0..10], [0, 0, 0, 0, 0, 0, 0, 0, 0, 66]);
        chunk.consumed = 2;
        assert_eq!(chunk[..10], [0, 0, 0, 0, 0, 0, 0, 0, 66, 0]);
        assert_eq!(chunk[..].len(), 40);
    }

    #[test]
    fn empty_stream_frame_emitted() {
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            let mut recv =
                RecvBuf::new(15, DEFAULT_STREAM_WINDOW, crate::PROTOCOL_VERSION);

            let bufinfo = RecvBufInfo::from(0, 5, false);
            let mut app_buf = AppRecvBuf::new(1, 100, 1000);
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);

            assert_eq!(recv.off, 0);
            // We have 5 bytes in without the fin bit set, and the chunk is 100
            // bytes wide, we cannot emit.
            assert!(app_buf.emit(&mut recv).is_err());

            // Store fin empty buffer.
            let bufinfo = RecvBufInfo::from(5, 0, true);
            assert!(recv.write_v3(bufinfo).is_ok());
            assert_eq!(recv.heap.len(), 0);

            assert_eq!(recv.off, 5);

            // An empty stream frame with a fin bit has been received, we should
            // now be emit the chunk
            let (chunk, fin) = app_buf.emit(&mut recv).unwrap();
            assert_eq!((chunk.len(), fin), (5, true));

            // There is nothing else to emit.
            assert!(app_buf.emit(&mut recv).is_err());
        }
    }
}
