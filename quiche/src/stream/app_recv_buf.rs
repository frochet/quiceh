use std::collections::hash_map;
use std::collections::VecDeque;
use super::Stream;
use super::recv_buf::RecvBuf;
use super::DEFAULT_STREAM_WINDOW;

use crate::Error;
use crate::Result;

/// Todo
#[derive(Default)]
pub struct AppRecvBufMap {
    buffers: crate::stream::StreamIdHashMap<AppRecvBuf>,

    recycled_buffers: VecDeque<AppRecvBuf>,

    //Todo: add memory configs?
}

impl AppRecvBufMap {

    /// Todo
    pub fn new(recycled_capacity: usize) -> AppRecvBufMap {
        AppRecvBufMap {
            recycled_buffers: VecDeque::with_capacity(recycled_capacity),
            ..Default::default()
        }
    }


    pub(crate) fn get_or_create_stream_buffer(&mut self, stream_id: u64) -> &mut AppRecvBuf {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                let buf = if let Some(mut buf) = self.recycled_buffers.pop_front() {
                    buf.stream_id = stream_id;
                    buf
                } else {
                    AppRecvBuf::new(stream_id, None)
                };
                v.insert(buf)
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }

    /// Todo
    pub fn get(&self, stream_id: u64) -> Option<&[u8]> {
        match self.buffers.get(&stream_id) {
            Some(buf) => Some(buf.get_consumed()),
            None => None,
        }
    }

    /// Todo
    pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut [u8]> {
        match self.buffers.get_mut(&stream_id) {
            Some(buf) => Some(buf.get_mut_consumed()),
            None => None,
         }
    }

    pub(crate) fn read_mut(&mut self, stream_id: u64, stream: &mut Stream) -> Result<&mut [u8]> {
        let buf = match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => {
                return Err(Error::AppRecvBufNotFound);
            }
            hash_map::Entry::Occupied(v) => v.into_mut().read_mut(&mut stream.recv)?,
        };
        Ok(buf)
    }

    pub(crate) fn has_consumed(&mut self, stream_id: u64, stream: Option<&Stream>, consumed: usize) -> Result<usize>{
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Occupied(v) => {
                // Registers how much the app has read on this stream buffer. If we don't
                // have a stream, it means it has been collected. We need to collect our stream
                // buffer as well assuming the application has read everything that was readable.
                let (to_collect, remaining_data) = v.into_mut().has_consumed(stream, consumed)?;
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
            Some(v) => {
                v.is_consumed()
            }
            _ => true,
        }
    }

    pub(crate) fn collect(&mut self, stream_id: u64) {
        if let Some(mut buf) = self.buffers.remove(&stream_id) {
            if self.recycled_buffers.len() < self.recycled_buffers.capacity() {
                buf.clear();
                self.recycled_buffers.push_back(buf);
            }
        }
    }

}

#[derive(Default)]
pub struct AppRecvBuf {

    /// Stream data gets decrypted within this buffer instead of inplace decryption+copy. V3
    /// specific. A slice of this buffer is what is recv by the application.
    pub outbuf: Vec<u8>,

    /// Keep track by how much the output's offsets have been rewinded. Typically, this happens
    /// when the application reads all available data within outbuf. Rewinding then does only
    /// require changing output_off to 0 and adding its previous value to tot_rewind.
    /// If there's still data info within the heap; we need to memmove the whole remaining window
    /// back to 0, and add the offset difference to tot_rewind. Hopefully this only happens under
    /// bad networking conditions (e.g., intense loss over high-bandwidth), when the window has
    /// already been maxed. V3 specific.
    tot_rewind: u64,

    /// indicates to which offset data within outbuf has already been marked consumed by the
    /// application. V3 specific.
    consumed: usize,

    /// Track the offset of contiguous data within outbuf.
    output_off: u64,

    /// Stream id of the stream linked to this buffer.
    stream_id: u64,

    /// Max authorized size for this buffer.
    max_size: usize,

    /// Configured by the application; default to a full congestion window
    almost_full_window: u64,
}

impl AppRecvBuf {

    pub fn new(stream_id: u64, capacity: Option<usize>) -> AppRecvBuf {
        if let Some(capacity) = capacity {
            let mut appbuf = AppRecvBuf {
                stream_id,
                outbuf: vec![0; capacity],
                max_size: super::MAX_STREAM_WINDOW as usize,
                almost_full_window: super::DEFAULT_STREAM_WINDOW / 2,
                ..Default::default()
            };
            // set_len is safe assuming
            // 1) the data is initialized
            // 2) the new len is <= capacity
            unsafe { appbuf.outbuf.set_len(capacity) };
            appbuf
        } else {
            let mut appbuf = AppRecvBuf {
                stream_id,
                outbuf: vec![0; DEFAULT_STREAM_WINDOW as usize],
                max_size: super::MAX_STREAM_WINDOW as usize,
                almost_full_window: super::DEFAULT_STREAM_WINDOW / 2,
                ..Default::default()
            };
            unsafe { appbuf.outbuf.set_len(DEFAULT_STREAM_WINDOW as usize) };
            appbuf
        }
    }

    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.outbuf
    }

    pub fn get_consumed(&self) -> &[u8] {
        &self.outbuf[self.consumed..]
    }

    pub fn get_mut_consumed(&mut self) -> &mut [u8] {
        &mut self.outbuf[self.consumed..]
    }

    #[inline]
    pub fn read_mut(&mut self, recv: &mut RecvBuf) -> Result<&mut [u8]> {
        let mut len = 0;
        let mut max_off = 0;
        while recv.ready() {
            // ready() already ensures we have something to pop()
            let entry = recv.heap.first_entry().unwrap();
            let recvbufinfo = entry.remove();
            // packets received not in order created a "full" overlap that we might
            // simply just safely ignore. I.e., the lower offest info was last
            // to be decrypted for this entry to be there.
            if recvbufinfo.max_off() < max_off {
                // not <= to allow handling 0bytes FIN
                continue
            }
            max_off = recvbufinfo.max_off();
            let mut this_len = recvbufinfo.len as u64;
            let mut this_offset = recvbufinfo.start_off;
            // This was already checked before, and should be safe.
            this_offset = this_offset - self.tot_rewind;
            // We need to copy in case some out of order packet decryption happened :'(
            // Hopefully rare event; especially if we make sure packets are in order before
            // starting to decrypt them from the read() buffer.
            if let Some(buf) = recvbufinfo.data() {
                trace!(
                    "Packet wasn't received in order; a copy is necessary",
                );
                self.outbuf[this_offset as usize..this_offset as usize+recvbufinfo.len as
                    usize].copy_from_slice(&buf[..recvbufinfo.len]);
            }
            if this_offset < self.output_off {
                // We have a partial overlap. This could be caused by a retransmission?
                this_len = this_len.checked_sub(self.output_off - this_offset).unwrap_or(0);
            }
            len += this_len;
            recv.off += this_len;
            self.output_off += this_len;
        }

        recv.contiguous_off = recv.off;

        recv.flow_control.add_consumed(len);

        Ok(&mut self.outbuf[self.consumed..self.output_off as usize])
    }

    #[inline]
    pub fn has_consumed(&mut self, stream: Option<&Stream>, consumed: usize) -> Result<(bool, usize)> {
        self.consumed = self.consumed.saturating_add(consumed);
        if let Some(stream) = stream {
            if stream.recv.heap.is_empty() && self.consumed as u64 == self.output_off &&
                !stream.recv.is_fin() {
                self.tot_rewind = self.tot_rewind.saturating_add(self.consumed as u64);
                self.consumed = 0;
                self.output_off = 0;
                // we don't want to collect our buffer.
                Ok((false, 0))
            } else {
                // either the stream is_fin() but the app didn't fully read it yet. Or the stream
                // !is_fin() and the app didn't fully read what was available. In either case, the
                // buffer needs to remain available for the application.
                Ok((false, self.output_off.checked_sub(self.consumed as u64)
                                          .ok_or(Error::InvalidAPICall(
                                                  "You may have consumed more than what was
                                                  available to read"))? as usize))
            }
        } else if self.consumed as u64 == self.output_off {
            // The stream has been collected, and the application has read everything. We can
            // collect the buffer as well.
            Ok((true, 0))
        } else {
            // The stream has been collected but the application didn't fully read the available
            // data yet.
            Ok((false, self.output_off.checked_sub(self.consumed as u64)
                                      .ok_or(Error::InvalidAPICall(
                                              "You may have consumed more than what was
                                                  available to read"))? as usize))
        }
        // TODO should we memmove the data in self.outbuf in the case where self.consumed ==
        // self.output_off_end but the heap isn't empty?
    }

    #[inline]
    pub fn is_consumed(&self) -> bool {
        self.consumed as u64 == self.output_off
    }

    /// Returns the offset to where the packet should be decrypted in
    /// PROTOCOL_VERSION_V3.
    /// Make sure that this offset is within our outbuf's range.
    /// Make sure we didn't already received contiguous data above stream_offset.
    /// if that's the case, decrypting this packet could lead to overwrite contiguous
    /// data not yet read by the application.
    #[inline]
    pub fn to_outbuf_offset(&mut self, stream_offset: u64, to_reserve: usize, recv: &RecvBuf) -> Result<u64> {
        if stream_offset < recv.contiguous_off {
            // In V3, we do not accept a packet that would overlap a contiguous range of data already
            // processed but not yet read by the application. This could happen due to aggressive
            // retransmission; or intentional duplication.
            return Err(Error::InvalidOffset);
        }

        if self.is_almost_full() {
            // If the application has a correct pacing, this should not happen.
            trace!(
                "We're almost full! Copying {} bytes", self.max_size - self.consumed,
            );
            self.outbuf.copy_within(self.consumed..self.max_size, 0);
            self.tot_rewind = self.tot_rewind.saturating_add(self.consumed as u64);
            self.output_off = self.output_off - self.consumed as u64;
            self.consumed = 0;
        }

        let outbuf_off = stream_offset.checked_sub(self.tot_rewind)
            .ok_or(Error::InvalidOffset)?;

        // TODO I need the configured stream_window here instead.
        // We're having an offset that is definitely outside of logical bounds.
        if outbuf_off > self.output_off + super::DEFAULT_STREAM_WINDOW as u64 {
            return Err(Error::InvalidOffset);
        }

        // If this triggers a BufferToShort Error, it may be sign the application didn't consume.
        // We lose the packet and return the error to the application.
        self.ensures_size(outbuf_off as usize + to_reserve)?;

        if outbuf_off > self.outbuf.capacity().checked_sub(to_reserve).ok_or(Error::InvalidOffset)?  as u64 {
            return Err(Error::BufferTooShort);
        }

        Ok(outbuf_off)
    }

    /// todo
    fn ensures_size(&mut self, size: usize) -> Result<()> {
        if self.outbuf.capacity() <  size && size <= self.max_size {
            // In case we don't have enough room to store the data; we double the size of outbuf,
            // or set to size
            let minmax = std::cmp::min(std::cmp::max(self.outbuf.capacity() * 2, size), self.max_size);
            trace!(
                "Resizing the output buffer of stream {} to {}", self.stream_id, minmax,
            );
            self.outbuf.resize(minmax, 0);
            unsafe { self.outbuf.set_len(minmax) };
        } else if size > self.max_size {
            return Err(Error::BufferTooShort);
        }

        Ok(())
    }

    ///todo
    fn is_almost_full(&self) -> bool {
        let available_space = (self.max_size - self.consumed) as u64;

        // The notion of "almost full" for the application buffer depends
        // on the chunk size that the application consumes. The application should
        // set almost_full_window to their larger chunk size they could be waiting on.
        available_space  < self.almost_full_window
    }

    /// Clear the buffer meta-data
    #[inline]
    pub fn clear(&mut self) {
        self.tot_rewind = 0;
        self.consumed = 0;
        self.output_off = 0;
        self.stream_id = 0;
    }
}
