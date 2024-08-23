use super::recv_buf::RecvBuf;
use super::Stream;
use super::DEFAULT_STREAM_WINDOW;
use std::collections::hash_map;
use std::collections::VecDeque;

use crate::Error;
use crate::Result;

/// Buffer map containing the stream buffers
pub struct AppRecvBufMap {
    /// The stream buffers.
    buffers: crate::stream::StreamIdHashMap<AppRecvBuf>,

    /// Contains heap-allocated AppRecvBuf that could be recycled if needed.
    recycled_buffers: VecDeque<AppRecvBuf>,

    /// Max quantity of data that the buffer can hold. Default to
    /// max_streams_data.
    max_buffer_data: u64,

    /// Maximum number of bidi buffers that could exist at anytime.
    max_streams_bidi: u64,

    /// Maximum number of peer uni buffers that could exist at anytime.
    max_streams_uni_remote: u64,

    current_bidi: u64,
    current_remote: u64,

    /// The application tells us how much it expects to read before consuming.
    chunklen: Option<u64>,

    /// If this option is set, when collected, a buffer would be truncated if
    /// its memory is larger than max_recycled_buffer_size.
    max_recycled_buffer_size: Option<usize>,
}

impl Default for AppRecvBufMap {
    fn default() -> Self {
        AppRecvBufMap {
            buffers: crate::stream::StreamIdHashMap::<AppRecvBuf>::default(),
            recycled_buffers: VecDeque::with_capacity(3),
            max_buffer_data: 2097152,
            max_streams_bidi: 100_000,
            max_streams_uni_remote: 100_000,
            current_bidi: 0,
            current_remote: 0,
            chunklen: Some(DEFAULT_STREAM_WINDOW),
            max_recycled_buffer_size: None,
        }
    }
}

impl AppRecvBufMap {
    /// new map passing config information about stream management
    pub fn new(
        recycled_capacity: usize, max_buffer_data: u64, max_streams_bidi: u64,
        max_streams_uni_remote: u64,
    ) -> AppRecvBufMap {
        AppRecvBufMap {
            recycled_buffers: VecDeque::with_capacity(recycled_capacity),
            max_buffer_data,
            max_streams_bidi,
            max_streams_uni_remote,
            ..Default::default()
        }
    }

    /// The application should set the expected chunklen they expect to consume
    /// after one or more `stream_recv_v3()` are called.
    #[inline]
    pub fn set_expected_chunklen_to_consume(
        &mut self, chunklen: u64,
    ) -> Result<()> {
        if chunklen > self.max_buffer_data / 2 {
            return Err(Error::InvalidAPICall("chunklen cannot be greater \
                                              than half of the configured max data for streams"));
        }
        self.chunklen = Some(chunklen);

        Ok(())
    }

    /// truncate recycled buffers to the specified size.
    #[inline]
    pub fn set_max_recycled_buffer_size(
        &mut self, max_recycled_buffer_size: usize,
    ) {
        self.max_recycled_buffer_size = Some(max_recycled_buffer_size);
    }

    /// Maximum data that can be buffered in a given stream buffer. This can be
    /// made higher than the stream_max_data, but is the expected value.
    #[inline]
    pub fn set_max_buffer_data(&mut self, max_buffer_data: u64) {
        self.max_buffer_data = max_buffer_data;
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
                        None,
                        self.chunklen.unwrap_or(super::DEFAULT_STREAM_WINDOW),
                        self.max_buffer_data,
                    )
                };
                Ok(v.insert(buf))
            },
            hash_map::Entry::Occupied(v) => Ok(v.into_mut()),
        }
    }

    /// get the stream_id's buffer starting at the first non-consumed byte.
    pub fn get(&self, stream_id: u64) -> Option<&[u8]> {
        match self.buffers.get(&stream_id) {
            Some(buf) => Some(buf.get_consumed()),
            None => None,
        }
    }

    /// get a mutable reference to the stream_id's buffer starting at the first
    /// non-consumed byte.
    pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut [u8]> {
        match self.buffers.get_mut(&stream_id) {
            Some(buf) => Some(buf.get_mut_consumed()),
            None => None,
        }
    }

    pub(crate) fn read_mut(
        &mut self, stream_id: u64, stream: &mut Stream,
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

    pub(crate) fn advance_if_possible(
        &mut self, stream_id: u64,  stream: &mut Stream,
    ) -> Result<()> {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => {
                Err(Error::AppRecvBufNotFound)
            },
            hash_map::Entry::Occupied(v) =>
                v.into_mut().advance_if_possible(&mut stream.recv),
        }
    }

    pub(crate) fn has_consumed(
        &mut self, stream_id: u64, stream: Option<&Stream>, consumed: usize,
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
            Some(v) => v.is_consumed(),
            _ => true,
        }
    }

    pub(crate) fn collect(&mut self, stream_id: u64) {
        if let Some(mut buf) = self.buffers.remove(&stream_id) {
            if self.recycled_buffers.len() < self.recycled_buffers.capacity() {
                if let Some(max_recycled_buffer_size) =
                    self.max_recycled_buffer_size
                {
                    if max_recycled_buffer_size < buf.outbuf.capacity() {
                        buf.outbuf.truncate(max_recycled_buffer_size);
                    }
                }
                buf.clear();
                self.recycled_buffers.push_back(buf);
            }
        }
    }
}

/// A stream buffer. This is where received data gets decrypted.
#[derive(Default)]
pub struct AppRecvBuf {
    /// Stream data gets decrypted within this buffer instead of inplace
    /// decryption+copy. V3 specific. A slice of this buffer is what is recv
    /// by the application.
    pub outbuf: Vec<u8>,

    /// Keep track by how much the output's offsets have been rewinded.
    /// Typically, this happens when the application reads all available
    /// data within outbuf. Rewinding then does only require changing
    /// output_off to 0 and adding its previous value to tot_rewind.
    /// If there's still data info within the heap; we need to memmove the whole
    /// remaining window back to 0, and add the offset difference to
    /// tot_rewind. Hopefully this only happens under bad networking
    /// conditions (e.g., intense loss over high-bandwidth), when the window has
    /// already been maxed. V3 specific.
    tot_rewind: u64,

    /// indicates to which offset data within outbuf has already been marked
    /// consumed by the application. V3 specific.
    consumed: usize,

    /// Track the offset of contiguous data within outbuf.
    output_off: u64,

    /// Stream id of the stream linked to this buffer.
    stream_id: u64,

    /// Max authorized size for this buffer.
    max_buffer_data: usize,

    /// Configured by the application -- depends on the application's choice of
    /// size of consumed recv data
    almost_full_window: u64,
}

impl AppRecvBuf {
    pub fn new(
        stream_id: u64, capacity: Option<usize>, app_chunklen: u64,
        max_buffer_data: u64,
    ) -> AppRecvBuf {
        if let Some(capacity) = capacity {
            let mut appbuf = AppRecvBuf {
                stream_id,
                outbuf: vec![0; capacity],
                max_buffer_data: max_buffer_data as usize,
                almost_full_window: app_chunklen,
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
                max_buffer_data: max_buffer_data as usize,
                almost_full_window: app_chunklen,
                ..Default::default()
            };
            unsafe { appbuf.outbuf.set_len(DEFAULT_STREAM_WINDOW as usize) };
            appbuf
        }
    }

    /// get a mutable reference to the stream buffer.
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.outbuf
    }

    /// get a reference to the non-consumed bytes within the stream buffer.
    pub fn get_consumed(&self) -> &[u8] {
        &self.outbuf[self.consumed..]
    }

    /// get a mutable reference to the non-consumed bytes within the stream
    /// buffer.
    pub fn get_mut_consumed(&mut self) -> &mut [u8] {
        &mut self.outbuf[self.consumed..]
    }

    pub fn advance_if_possible(&mut self, recv: &mut RecvBuf) -> Result<()> {

        let mut max_off = recv.off;
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
            let mut this_offset = recvbufinfo.start_off;
            // This was already checked before, and should be safe.
            this_offset -= self.tot_rewind;
            // We need to copy in case some out of order packet decryption
            // happened :'( Hopefully rare event; altough this can be improved
            // by changing the API (we need ownership on bytes read from the udp
            // socket).
            if let Some(buf) = recvbufinfo.data() {
                trace!("Packet wasn't received in order; a copy is necessary",);
                self.outbuf[this_offset as usize..
                    this_offset as usize + recvbufinfo.len]
                    .copy_from_slice(&buf[..recvbufinfo.len]);
            }
            if this_offset < recv.contiguous_off {
                // We have a partial overlap. This could be caused by a
                // retransmission? Normally this event does not happen;
                trace!("Partial overlap happened -- Could happen if this packet is\
                received first");
                this_len = this_len.saturating_sub(recv.contiguous_off - recvbufinfo.start_off);
            }
            recv.contiguous_off += this_len;
        }
        Ok(())
    }
    /// gives ontiguous bytes as a mutable slice from the stream buffer.
    #[inline]
    pub fn read_mut(&mut self, recv: &mut RecvBuf) -> Result<&mut [u8]> {
        let mut len = 0;
        // We have received data in order, we can read it right away.
        if recv.contiguous_off > recv.off {
            len += recv.contiguous_off - recv.off;
            recv.off += len;
            self.output_off += len;
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

        Ok(&mut self.outbuf[self.consumed..self.output_off as usize])
    }

    /// This function needs to be called to tell how much of the stream's buffer
    /// has been consumed by the application. It returns whether the buffer
    /// can be collected, and how many bytes are available for read.
    #[inline]
    pub fn has_consumed(
        &mut self, stream: Option<&Stream>, consumed: usize,
    ) -> Result<(bool, usize)> {
        self.consumed = self.consumed.saturating_add(consumed);
        if let Some(stream) = stream {
            if stream.recv.heap.is_empty() &&
                self.consumed as u64 == self.output_off &&
                !stream.recv.is_fin()
            {
                self.tot_rewind =
                    self.tot_rewind.saturating_add(self.consumed as u64);
                self.consumed = 0;
                self.output_off = 0;
                // we don't want to collect our buffer.
                Ok((false, 0))
            } else {
                // either the stream is_fin() but the app didn't fully read it
                // yet. Or the stream !is_fin() and the app didn't
                // fully read what was available. In either case, the
                // buffer needs to remain available for the application.
                Ok((
                    false,
                    self.output_off.checked_sub(self.consumed as u64).ok_or(
                        Error::InvalidAPICall(
                            "You may have consumed more than what was \
                             available to read",
                        ),
                    )? as usize,
                ))
            }
        } else if self.consumed as u64 == self.output_off {
            // The stream has been collected, and the application has read
            // everything. We can collect the buffer as well.
            Ok((true, 0))
        } else {
            // The stream has been collected but the application didn't fully read
            // the available data yet.
            Ok((
                false,
                self.output_off.checked_sub(self.consumed as u64).ok_or(
                    Error::InvalidAPICall(
                        "You may have consumed more than what was
                                                  available to read",
                    ),
                )? as usize,
            ))
        }
        // TODO should we memmove the data in self.outbuf in the case where
        // self.consumed == self.output_off_end but the heap isn't
        // empty?
    }

    #[inline]
    pub fn is_consumed(&self) -> bool {
        self.consumed as u64 == self.output_off
    }

    /// Returns the offset to where the packet should be decrypted in
    /// PROTOCOL_VERSION_VREVERSO.
    /// Make sure that this offset is within our outbuf's range.
    /// Make sure we didn't already received contiguous data above
    /// stream_offset. if that's the case, decrypting this packet could lead
    /// to overwrite contiguous data not yet read by the application.
    #[inline]
    pub fn get_outbuf_offset(
        &mut self, stream_offset: u64, to_reserve: usize, recv: &RecvBuf,
    ) -> Result<u64> {
        if stream_offset < recv.contiguous_off {
            trace!(
                "We've received a packet holding an offset {} already \
                in our contiguous buffer but not yet read by the application. \
                consumed index is {} and output offset is {}",
                stream_offset,
                self.consumed,
                self.output_off
            );
            // In V3, we do not accept a packet that would overlap a contiguous
            // range of data already processed but not yet read by the
            // application. This could happen due to aggressive
            // retransmission; or intentional duplication. The packet is
            // dropped before payload decryption.
            return Err(Error::InvalidOffset);
        }

        let mut outbuf_off = stream_offset
            .checked_sub(self.tot_rewind)
            .ok_or(Error::InvalidOffset)?;

        if self.is_almost_full(outbuf_off)? && self.consumed > 0 {
            trace!(
                "We're almost full! memmoving {} bytes",
                self.max_buffer_data as u64 - outbuf_off,
            );
            self.outbuf
                .copy_within(self.consumed..outbuf_off as usize, 0);
            self.tot_rewind =
                self.tot_rewind.saturating_add(self.consumed as u64);
            self.output_off -= self.consumed as u64;
            outbuf_off -= self.consumed as u64;
            self.consumed = 0;
        }

        // If this triggers a BufferToShort Error, it may be sign the application
        // didn't consume. We lose the packet and return the error to the
        // application. This would returns a BufferTooShort error. Should
        // we return something more specific? XXX
        self.ensures_size(outbuf_off as usize + to_reserve)?;

        Ok(outbuf_off)
    }

    /// Check that the stream buffer's capacity is large enough to old the
    /// packet about to be decrypted. If not, and if we have room, double
    /// the buffer's capacity.
    fn ensures_size(&mut self, size: usize) -> Result<()> {
        if self.outbuf.capacity() < size && size <= self.max_buffer_data {
            // In case we don't have enough room to store the data; we double the
            // size of outbuf, or set to size
            let minmax = std::cmp::min(
                std::cmp::max(self.outbuf.capacity() * 2, size),
                self.max_buffer_data,
            );
            trace!(
                "Resizing the output buffer of stream {} to {}",
                self.stream_id,
                minmax,
            );
            self.outbuf.resize(minmax, 0);
            unsafe { self.outbuf.set_len(minmax) };
        } else if size > self.max_buffer_data {
            trace!(
                "BUG: asking for a size bigger than {}",
                self.max_buffer_data
            );
            return Err(Error::BufferTooShort);
        }

        Ok(())
    }

    /// Check wether we're almost full. This depends on the choice of the
    /// application's maximum chunk to keep buffered before consuming.
    fn is_almost_full(&self, output_off: u64) -> Result<bool> {
        let available_space = (self.max_buffer_data as u64)
            .checked_sub(output_off)
            .ok_or(Error::InvalidOffset)?;

        // The notion of "almost full" for the application buffer depends
        // on the chunk size that the application consumes. The application should
        // set almost_full_window to their larger chunk size they could be waiting
        // on.
        Ok(available_space < self.almost_full_window)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::RecvBufInfo;

    #[test]
    fn create_and_collect_bufs() {
        let mut app_buf = AppRecvBufMap::new(3, 100, 10, 10);
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
        let mut app_buf = AppRecvBufMap::new(3, 100, 10, 10);
        let buf_stream_4 = app_buf.get_or_create_stream_buffer(4).unwrap();

        let writeinfo = RecvBufInfo::from(0, 5, false);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            assert!(recv.write_v3(writeinfo).is_ok());
            assert_eq!(buf_stream_4.read_mut(&mut recv).unwrap().len(), 5);
        }
    }
    // TODO write actual good testing. This ain't gonna help getting published
    // but it is the way. *sigh*.
}
