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

use std::convert::TryInto;

use crate::Error;
use crate::Result;

use crate::packet;
use crate::range_buf::RangeBuf;
use crate::ranges;
use crate::stream;
use likely_stable::if_likely;

#[cfg(feature = "qlog")]
use qlog::events::quic::AckedRanges;
#[cfg(feature = "qlog")]
use qlog::events::quic::ErrorSpace;
#[cfg(feature = "qlog")]
use qlog::events::quic::QuicFrame;
#[cfg(feature = "qlog")]
use qlog::events::quic::StreamType;

pub const MAX_CRYPTO_OVERHEAD: usize = 8;
pub const MAX_DGRAM_OVERHEAD: usize = 2;
pub const MAX_STREAM_OVERHEAD: usize = 12;
pub const MAX_STREAM_SIZE: u64 = 1 << 62;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    Padding {
        len: usize,
    },

    Ping {
        // Attach metadata to the Ping frame. This doesn't appear on the wire,
        // but does tell us if this frame was part of a PMTUD probe and how
        // large the probe was. This will only show up on sent frames and be
        // None otherwise. This is the total size of the QUIC packet in the
        // probe.
        mtu_probe: Option<usize>,
    },

    ACK {
        ack_delay: u64,
        ranges: ranges::RangeSet,
        ecn_counts: Option<EcnCounts>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        data: RangeBuf,
    },

    CryptoHeader {
        offset: u64,
        length: usize,
    },

    NewToken {
        token: Vec<u8>,
    },

    Stream {
        stream_id: u64,
        data: RangeBuf,
    },

    StreamV3 {
        stream_id: u64,
        metadata: stream::RecvBufInfo,
    },

    StreamHeader {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
    },

    MaxData {
        max: u64,
    },

    MaxStreamData {
        stream_id: u64,
        max: u64,
    },

    MaxStreamsBidi {
        max: u64,
    },

    MaxStreamsUni {
        max: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlockedBidi {
        limit: u64,
    },

    StreamsBlockedUni {
        limit: u64,
    },

    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: Vec<u8>,
        reset_token: [u8; 16],
    },

    RetireConnectionId {
        seq_num: u64,
    },

    PathChallenge {
        data: [u8; 8],
    },

    PathResponse {
        data: [u8; 8],
    },

    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },

    ApplicationClose {
        error_code: u64,
        reason: Vec<u8>,
    },

    HandshakeDone,

    Datagram {
        data: Vec<u8>,
    },

    DatagramHeader {
        length: usize,
    },
}

impl Frame {
    pub fn from_bytes(
        b: &mut octets_rev::Octets, pkt: packet::Type, version: u32,
    ) -> Result<Frame> {
        let frame_type = if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
            b.get_varint_reverse()?
        } else {
            b.get_varint()?
        }};
        // Parse frames according either to the V3 format or to the previous Quic
        // format. In V3, frames are reversed, meaning that:
        //  - Elements order is reversed
        //  - Elements are encoded and decoded with the set of [..]_reverse()
        //    Octets functions to enable reading them from the back of the buffer
        //    towards the beginning (Manga-like).
        let frame: Frame = match frame_type {
            0x00 => {
                let mut len = 1;
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    while b.peek_u8_reverse() == Ok(0x00) {
                        b.get_u8_reverse()?;

                        len += 1;
                    }
                } else {
                    while b.peek_u8() == Ok(0x00) {
                        b.get_u8()?;

                        len += 1;
                    }
                }};

                Frame::Padding { len }
            },

            0x01 => Frame::Ping { mtu_probe: None },

            0x02..=0x03 => parse_ack_frame(frame_type, b, version)?,

            0x04 => if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                Frame::ResetStream {
                    stream_id: b.get_varint_reverse()?,
                    error_code: b.get_varint_reverse()?,
                    final_size: b.get_varint_reverse()?,
                }
            } else {
                Frame::ResetStream {
                    stream_id: b.get_varint()?,
                    error_code: b.get_varint()?,
                    final_size: b.get_varint()?,
                }
            }},

            0x05 => if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                Frame::StopSending {
                    stream_id: b.get_varint_reverse()?,
                    error_code: b.get_varint_reverse()?,
                }
            } else {
                Frame::StopSending {
                    stream_id: b.get_varint()?,
                    error_code: b.get_varint()?,
                }
            }},

            0x06 => {
                let (offset, data) = if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    (b.get_varint_reverse()?,
                    b.get_bytes_with_varint_length_reverse()?)
                } else {
                    (b.get_varint()?,
                    b.get_bytes_with_varint_length()?)
                }};
                // TODO protocol reverso could get rid of RangeBuf.
                let data = <RangeBuf>::from(data.as_ref(), offset, false);

                Frame::Crypto { data }
            },

            0x07 => Frame::NewToken {
                token: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    let len = b.get_varint_reverse()?;
                    if len == 0 {
                        return Err(Error::InvalidFrame);
                    }
                    b.get_bytes_reverse(len as usize)?.to_vec()
                } else {
                    let len = b.get_varint()?;
                    if len == 0 {
                        return Err(Error::InvalidFrame);
                    }
                    b.get_bytes(len as usize)?.to_vec()
                }},
            },

            0x08..=0x0f => parse_stream_frame(frame_type, b, version)?,

            0x10 => Frame::MaxData {
                max: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x11 => if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                Frame::MaxStreamData {
                    stream_id: b.get_varint_reverse()?,
                    max: b.get_varint_reverse()?,
                }
            } else {
                Frame::MaxStreamData {
                    stream_id: b.get_varint()?,
                    max: b.get_varint()?,
                }
            }},

            0x12 => Frame::MaxStreamsBidi {
                max: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x13 => Frame::MaxStreamsUni {
                max: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x14 => Frame::DataBlocked {
                limit: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x15 => if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                Frame::StreamDataBlocked {
                    stream_id: b.get_varint_reverse()?,
                    limit: b.get_varint_reverse()?,
                }
            } else {
                Frame::StreamDataBlocked {
                    stream_id: b.get_varint()?,
                    limit: b.get_varint()?,
                }
            }},

            0x16 => Frame::StreamsBlockedBidi {
                limit: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x17 => Frame::StreamsBlockedUni {
                limit: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x18 => if_likely! { version == crate::PROTOCOL_VERSION_VREVERSO => {
                let seq_num = b.get_varint_reverse()?;
                let retire_prior_to = b.get_varint_reverse()?;
                let conn_id_len = b.get_u8_reverse()?;

                if !(1..=packet::MAX_CID_LEN).contains(&conn_id_len) {
                    return Err(Error::InvalidFrame);
                }

                Frame::NewConnectionId {
                    seq_num,
                    retire_prior_to,
                    conn_id: b.get_bytes_reverse(conn_id_len as usize)?.to_vec(),
                    reset_token: b
                        .get_bytes_reverse(16)?
                        .buf()
                        .try_into()
                        .map_err(|_| Error::BufferTooShort)?,
                }
            } else {
                let seq_num = b.get_varint()?;
                let retire_prior_to = b.get_varint()?;
                let conn_id_len = b.get_u8()?;

                if !(1..=packet::MAX_CID_LEN).contains(&conn_id_len) {
                    return Err(Error::InvalidFrame);
                }

                Frame::NewConnectionId {
                    seq_num,
                    retire_prior_to,
                    conn_id: b.get_bytes(conn_id_len as usize)?.to_vec(),
                    reset_token: b
                        .get_bytes(16)?
                        .buf()
                        .try_into()
                        .map_err(|_| Error::BufferTooShort)?,
                }
            }},

            0x19 => Frame::RetireConnectionId {
                seq_num: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.get_varint_reverse()?
                } else {
                    b.get_varint()?
                }},
            },

            0x1a => Frame::PathChallenge {
                data: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO =>{
                    b
                    .get_bytes_reverse(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?
                } else {
                    b
                    .get_bytes(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?
                }},
            },

            0x1b => Frame::PathResponse {
                data: if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO =>{
                    b
                    .get_bytes_reverse(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?
                } else {
                    b
                    .get_bytes(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?
                }},
            },

            0x1c => if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                Frame::ConnectionClose {
                    error_code: b.get_varint_reverse()?,
                    frame_type: b.get_varint_reverse()?,
                    reason: b.get_bytes_with_varint_length_reverse()?.to_vec(),
                }
            } else {
                Frame::ConnectionClose {
                    error_code: b.get_varint()?,
                    frame_type: b.get_varint()?,
                    reason: b.get_bytes_with_varint_length()?.to_vec(),
                }
            }},

            0x1d => if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                Frame::ApplicationClose {
                    error_code: b.get_varint_reverse()?,
                    reason: b.get_bytes_with_varint_length_reverse()?.to_vec(),
                }
            } else {
                Frame::ApplicationClose {
                    error_code: b.get_varint()?,
                    reason: b.get_bytes_with_varint_length()?.to_vec(),
                }
            }},

            0x1e => Frame::HandshakeDone,

            0x30 | 0x31 => parse_datagram_frame(frame_type, b, version)?,

            _ => return Err(Error::InvalidFrame),
        };

        let allowed = match (pkt, &frame) {
            // PADDING and PING are allowed on all packet types.
            (_, Frame::Padding { .. }) | (_, Frame::Ping { .. }) => true,

            // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and
            // RETIRE_CONNECTION_ID can't be sent on 0-RTT packets.
            (packet::Type::ZeroRTT, Frame::ACK { .. }) => false,
            (packet::Type::ZeroRTT, Frame::Crypto { .. }) => false,
            (packet::Type::ZeroRTT, Frame::HandshakeDone) => false,
            (packet::Type::ZeroRTT, Frame::NewToken { .. }) => false,
            (packet::Type::ZeroRTT, Frame::PathResponse { .. }) => false,
            (packet::Type::ZeroRTT, Frame::RetireConnectionId { .. }) => false,
            (packet::Type::ZeroRTT, Frame::ConnectionClose { .. }) => false,

            // ACK, CRYPTO and CONNECTION_CLOSE can be sent on all other packet
            // types.
            (_, Frame::ACK { .. }) => true,
            (_, Frame::Crypto { .. }) => true,
            (_, Frame::ConnectionClose { .. }) => true,

            // All frames are allowed on 0-RTT and 1-RTT packets.
            (packet::Type::Short, _) => true,
            (packet::Type::ZeroRTT, _) => true,

            // All other cases are forbidden.
            (..) => false,
        };

        if !allowed {
            return Err(Error::InvalidPacket);
        }

        Ok(frame)
    }

    pub fn to_bytes(
        &self, b: &mut octets_rev::OctetsMut, version: u32,
    ) -> Result<usize> {
        let before = b.cap();

        match self {
            Frame::Padding { len } => {
                let mut left = *len;

                while left > 0 {
                    if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                        b.put_varint_reverse(0x00)?;
                    } else {
                        b.put_varint(0x00)?;
                    }};
                    left -= 1;
                }
            },

            Frame::Ping { .. } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(0x01)?;
                } else {
                    b.put_varint(0x01)?;
                }};
            },

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    // ecn first
                    if let Some(ecn) = ecn_counts {
                        b.put_varint_reverse(ecn.ecn_ce_count)?;
                        b.put_varint_reverse(ecn.ect1_count)?;
                        b.put_varint_reverse(ecn.ect0_count)?;
                    }
                    // This is a bit more mindtricking. On V1, ack ranges
                    // are actually reversed to start reading from the largest_ack.
                    // On V3, we can put the acks on the natural ordering, since it
                    // is read backwards.
                    let mut it = ranges.iter();
                    let first = it.next().unwrap();
                    let len = it.len();
                    let last = it.next_back();
                    let mut smallest_ack_end = first.end;
                    let mut ack_block = (first.end - 1) - first.start;
                    for block in it {
                        let gap = block.start - smallest_ack_end - 1;
                        b.put_varint_reverse(ack_block)?;
                        b.put_varint_reverse(gap)?;
                        ack_block = (block.end - 1) - block.start;
                        smallest_ack_end = block.end;
                    }
                    // XXX Is there a better implementation possible to eliminate the control flow
                    // for the last element?
                    if let Some(block) = last {
                        // last
                        let gap = block.start - smallest_ack_end - 1;
                        b.put_varint_reverse(ack_block)?;
                        b.put_varint_reverse(gap)?;
                        ack_block = (block.end - 1) - block.start;
                        b.put_varint_reverse(ack_block)?;
                        b.put_varint_reverse(len as u64)?;
                        b.put_varint_reverse(*ack_delay)?;
                        b.put_varint_reverse(block.end - 1)?;
                    } else {
                        // We actually just had one element
                        b.put_varint_reverse(ack_block)?;
                        b.put_varint_reverse(len as u64)?;
                        b.put_varint_reverse(*ack_delay)?;
                        b.put_varint_reverse(first.end - 1)?;
                    }

                    if ecn_counts.is_none() {
                        b.put_varint_reverse(0x02)?;
                    } else {
                        b.put_varint_reverse(0x03)?;
                    }

                } else {

                    if ecn_counts.is_none() {
                        b.put_varint(0x02)?;
                    } else {
                        b.put_varint(0x03)?;
                    }

                    let mut it = ranges.iter().rev();

                    let first = it.next().unwrap();
                    let ack_block = (first.end - 1) - first.start;

                    b.put_varint(first.end - 1)?;
                    b.put_varint(*ack_delay)?;
                    b.put_varint(it.len() as u64)?;
                    b.put_varint(ack_block)?;

                    let mut smallest_ack = first.start;

                    for block in it {
                        let gap = smallest_ack - block.end - 1;
                        let ack_block = (block.end - 1) - block.start;

                        b.put_varint(gap)?;
                        b.put_varint(ack_block)?;

                        smallest_ack = block.start;
                    }

                    if let Some(ecn) = ecn_counts {
                        b.put_varint(ecn.ect0_count)?;
                        b.put_varint(ecn.ect1_count)?;
                        b.put_varint(ecn.ecn_ce_count)?;
                    }
                }};
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*final_size)?;
                    b.put_varint_reverse(*error_code)?;
                    b.put_varint_reverse(*stream_id)?;

                    b.put_varint_reverse(0x04)?;
                } else {
                    b.put_varint(0x04)?;

                    b.put_varint(*stream_id)?;
                    b.put_varint(*error_code)?;
                    b.put_varint(*final_size)?;
                }};
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*error_code)?;
                    b.put_varint_reverse(*stream_id)?;

                    b.put_varint_reverse(0x05)?;
                } else {
                    b.put_varint(0x05)?;

                    b.put_varint(*stream_id)?;
                    b.put_varint(*error_code)?;
                }};
            },

            Frame::Crypto { data } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(data)?;

                    encode_crypto_footer(data.off(), data.len() as u64, b)?;
                } else {
                    encode_crypto_header(data.off(), data.len() as u64, b)?;

                    b.put_bytes(data)?;
                }};
            },

            Frame::CryptoHeader { .. } => (),

            Frame::NewToken { token } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(token)?;
                    b.put_varint_reverse(token.len() as u64)?;

                    b.put_varint_reverse(0x07)?;
                } else {
                    b.put_varint(0x07)?;

                    b.put_varint(token.len() as u64)?;
                    b.put_bytes(token)?;
                }};
            },

            // We don't use it to send data; we only use that for some test.
            Frame::StreamV3 { .. } => (),

            Frame::Stream { stream_id, data } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(data)?;

                    encode_stream_footer(
                        *stream_id,
                        data.off(),
                        data.len() as u64,
                        data.fin(),
                        b,
                    )?;
                } else {
                    encode_stream_header(
                        *stream_id,
                        data.off(),
                        data.len() as u64,
                        data.fin(),
                        b
                    )?;

                    b.put_bytes(data)?;
                }};
            },

            Frame::StreamHeader { .. } => (),

            Frame::MaxData { max } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*max)?;

                    b.put_varint_reverse(0x10)?;
                } else {
                    b.put_varint(0x10)?;

                    b.put_varint(*max)?;
                }};
            },

            Frame::MaxStreamData { stream_id, max } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*max)?;
                    b.put_varint_reverse(*stream_id)?;

                    b.put_varint_reverse(0x11)?;
                } else {
                    b.put_varint(0x11)?;

                    b.put_varint(*stream_id)?;
                    b.put_varint(*max)?;
                }};
            },

            Frame::MaxStreamsBidi { max } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*max)?;

                    b.put_varint_reverse(0x12)?;
                } else {
                    b.put_varint(0x12)?;

                    b.put_varint(*max)?;
                }};
            },

            Frame::MaxStreamsUni { max } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*max)?;

                    b.put_varint_reverse(0x13)?;
                } else {
                    b.put_varint(0x13)?;

                    b.put_varint(*max)?;
                }};
            },

            Frame::DataBlocked { limit } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*limit)?;

                    b.put_varint_reverse(0x14)?;
                } else {
                    b.put_varint(0x14)?;

                    b.put_varint(*limit)?;
                }};
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*limit)?;
                    b.put_varint_reverse(*stream_id)?;

                    b.put_varint_reverse(0x15)?;
                } else {
                    b.put_varint(0x15)?;

                    b.put_varint(*stream_id)?;
                    b.put_varint(*limit)?;
                }};
            },

            Frame::StreamsBlockedBidi { limit } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*limit)?;

                    b.put_varint_reverse(0x16)?;
                } else {
                    b.put_varint(0x16)?;

                    b.put_varint(*limit)?;
                }};
            },

            Frame::StreamsBlockedUni { limit } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*limit)?;

                    b.put_varint_reverse(0x17)?;
                } else {
                    b.put_varint(0x17)?;

                    b.put_varint(*limit)?;
                }};
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(reset_token.as_ref())?;
                    b.put_bytes(conn_id.as_ref())?;
                    b.put_u8(conn_id.len() as u8)?;
                    b.put_varint_reverse(*retire_prior_to)?;
                    b.put_varint_reverse(*seq_num)?;

                    b.put_varint_reverse(0x18)?;
                } else {
                    b.put_varint(0x18)?;

                    b.put_varint(*seq_num)?;
                    b.put_varint(*retire_prior_to)?;
                    b.put_u8(conn_id.len() as u8)?;
                    b.put_bytes(conn_id.as_ref())?;
                    b.put_bytes(reset_token.as_ref())?;
                }};
            },

            Frame::RetireConnectionId { seq_num } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(*seq_num)?;

                    b.put_varint_reverse(0x19)?;
                } else {
                    b.put_varint(0x19)?;

                    b.put_varint(*seq_num)?;
                }};
            },

            Frame::PathChallenge { data } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(data.as_ref())?;

                    b.put_varint_reverse(0x1a)?;
                } else {
                    b.put_varint(0x1a)?;

                    b.put_bytes(data.as_ref())?;
                }};
            },

            Frame::PathResponse { data } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(data.as_ref())?;

                    b.put_varint_reverse(0x1b)?;
                } else {
                    b.put_varint(0x1b)?;

                    b.put_bytes(data.as_ref())?;
                }};
            },

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(reason.as_ref())?;
                    b.put_varint_reverse(reason.len() as u64)?;
                    b.put_varint_reverse(*frame_type)?;
                    b.put_varint_reverse(*error_code)?;

                    b.put_varint_reverse(0x1c)?;
                } else {
                    b.put_varint(0x1c)?;

                    b.put_varint(*error_code)?;
                    b.put_varint(*frame_type)?;
                    b.put_varint(reason.len() as u64)?;
                    b.put_bytes(reason.as_ref())?;
                }};
            },

            Frame::ApplicationClose { error_code, reason } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(reason.as_ref())?;

                    b.put_varint_reverse(reason.len() as u64)?;
                    b.put_varint_reverse(*error_code)?;

                    b.put_varint_reverse(0x1d)?;
                } else {
                    b.put_varint(0x1d)?;

                    b.put_varint(*error_code)?;
                    b.put_varint(reason.len() as u64)?;
                    b.put_bytes(reason.as_ref())?;
                }};
            },

            Frame::HandshakeDone => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_varint_reverse(0x1e)?;
                } else {
                    b.put_varint(0x1e)?;
                }};
            },

            Frame::Datagram { data } => {
                if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
                    b.put_bytes(data.as_ref())?;

                    encode_dgram_footer(data.len() as u64, b)?;
                } else {
                    encode_dgram_header(data.len() as u64, b)?;

                    b.put_bytes(data.as_ref())?;
                }};
            },

            Frame::DatagramHeader { .. } => (),
        }

        Ok(before - b.cap())
    }

    pub fn wire_len(&self) -> usize {
        match self {
            Frame::Padding { len } => *len,

            Frame::Ping { .. } => 1,

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let mut it = ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                let mut len = 1 + // frame type
                    octets_rev::varint_len(first.end - 1) + // largest_ack
                    octets_rev::varint_len(*ack_delay) + // ack_delay
                    octets_rev::varint_len(it.len() as u64) + // block_count
                    octets_rev::varint_len(ack_block); // first_block

                let mut smallest_ack = first.start;

                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;

                    len += octets_rev::varint_len(gap) + // gap
                           octets_rev::varint_len(ack_block); // ack_block

                    smallest_ack = block.start;
                }

                if let Some(ecn) = ecn_counts {
                    len += octets_rev::varint_len(ecn.ect0_count) +
                        octets_rev::varint_len(ecn.ect1_count) +
                        octets_rev::varint_len(ecn.ecn_ce_count);
                }

                len
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(*error_code) + // error_code
                octets_rev::varint_len(*final_size) // final_size
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(*error_code) // error_code
            },

            Frame::Crypto { data } => {
                1 + // frame type
                octets_rev::varint_len(data.off()) + // offset
                2 + // length, always encode as 2-byte varint
                data.len() // data
            },

            Frame::CryptoHeader { offset, length, .. } => {
                1 + // frame type
                octets_rev::varint_len(*offset) + // offset
                2 + // length, always encode as 2-byte varint
                length // data
            },

            Frame::NewToken { token } => {
                1 + // frame type
                octets_rev::varint_len(token.len() as u64) + // token length
                token.len() // token
            },
            // Only used in the received pipeline
            Frame::StreamV3 {
                stream_id,
                metadata,
            } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(metadata.off()) + // offset
                2 + // length, always encode as 2-byte varint
                metadata.len() // data
            },

            Frame::Stream { stream_id, data } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(data.off()) + // offset
                2 + // length, always encode as 2-byte varint
                data.len() // data
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                ..
            } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(*offset) + // offset
                2 + // length, always encode as 2-byte varint
                length // data
            },

            Frame::MaxData { max } => {
                1 + // frame type
                octets_rev::varint_len(*max) // max
            },

            Frame::MaxStreamData { stream_id, max } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(*max) // max
            },

            Frame::MaxStreamsBidi { max } => {
                1 + // frame type
                octets_rev::varint_len(*max) // max
            },

            Frame::MaxStreamsUni { max } => {
                1 + // frame type
                octets_rev::varint_len(*max) // max
            },

            Frame::DataBlocked { limit } => {
                1 + // frame type
                octets_rev::varint_len(*limit) // limit
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                1 + // frame type
                octets_rev::varint_len(*stream_id) + // stream_id
                octets_rev::varint_len(*limit) // limit
            },

            Frame::StreamsBlockedBidi { limit } => {
                1 + // frame type
                octets_rev::varint_len(*limit) // limit
            },

            Frame::StreamsBlockedUni { limit } => {
                1 + // frame type
                octets_rev::varint_len(*limit) // limit
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                1 + // frame type
                octets_rev::varint_len(*seq_num) + // seq_num
                octets_rev::varint_len(*retire_prior_to) + // retire_prior_to
                1 + // conn_id length
                conn_id.len() + // conn_id
                reset_token.len() // reset_token
            },

            Frame::RetireConnectionId { seq_num } => {
                1 + // frame type
                octets_rev::varint_len(*seq_num) // seq_num
            },

            Frame::PathChallenge { .. } => {
                1 + // frame type
                8 // data
            },

            Frame::PathResponse { .. } => {
                1 + // frame type
                8 // data
            },

            Frame::ConnectionClose {
                frame_type,
                error_code,
                reason,
                ..
            } => {
                1 + // frame type
                octets_rev::varint_len(*error_code) + // error_code
                octets_rev::varint_len(*frame_type) + // frame_type
                octets_rev::varint_len(reason.len() as u64) + // reason_len
                reason.len() // reason
            },

            Frame::ApplicationClose { reason, error_code } => {
                1 + // frame type
                octets_rev::varint_len(*error_code) + // error_code
                octets_rev::varint_len(reason.len() as u64) + // reason_len
                reason.len() // reason
            },

            Frame::HandshakeDone => {
                1 // frame type
            },

            Frame::Datagram { data } => {
                1 + // frame type
                2 + // length, always encode as 2-byte varint
                data.len() // data
            },

            Frame::DatagramHeader { length } => {
                1 + // frame type
                2 + // length, always encode as 2-byte varint
                *length // data
            },
        }
    }

    pub fn ack_eliciting(&self) -> bool {
        // Any other frame is ack-eliciting (note the `!`).
        !matches!(
            self,
            Frame::Padding { .. } |
                Frame::ACK { .. } |
                Frame::ApplicationClose { .. } |
                Frame::ConnectionClose { .. }
        )
    }

    pub fn probing(&self) -> bool {
        matches!(
            self,
            Frame::Padding { .. } |
                Frame::NewConnectionId { .. } |
                Frame::PathChallenge { .. } |
                Frame::PathResponse { .. }
        )
    }

    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self) -> QuicFrame {
        match self {
            Frame::Padding { len } => QuicFrame::Padding {
                length: None,
                payload_length: *len as u32,
            },

            Frame::Ping { .. } => QuicFrame::Ping {
                length: None,
                payload_length: None,
            },

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let ack_ranges = AckedRanges::Double(
                    ranges.iter().map(|r| (r.start, r.end - 1)).collect(),
                );

                let (ect0, ect1, ce) = match ecn_counts {
                    Some(ecn) => (
                        Some(ecn.ect0_count),
                        Some(ecn.ect1_count),
                        Some(ecn.ecn_ce_count),
                    ),

                    None => (None, None, None),
                };

                QuicFrame::Ack {
                    ack_delay: Some(*ack_delay as f32 / 1000.0),
                    acked_ranges: Some(ack_ranges),
                    ect1,
                    ect0,
                    ce,
                    length: None,
                    payload_length: None,
                }
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => QuicFrame::ResetStream {
                stream_id: *stream_id,
                error_code: *error_code,
                final_size: *final_size,
                length: None,
                payload_length: None,
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => QuicFrame::StopSending {
                stream_id: *stream_id,
                error_code: *error_code,
                length: None,
                payload_length: None,
            },

            Frame::Crypto { data } => QuicFrame::Crypto {
                offset: data.off(),
                length: data.len() as u64,
            },

            Frame::CryptoHeader { offset, length } => QuicFrame::Crypto {
                offset: *offset,
                length: *length as u64,
            },

            Frame::NewToken { token } => QuicFrame::NewToken {
                token: qlog::Token {
                    // TODO: pick the token type some how
                    ty: Some(qlog::TokenType::Retry),
                    raw: Some(qlog::events::RawInfo {
                        data: qlog::HexSlice::maybe_string(Some(token)),
                        length: Some(token.len() as u64),
                        payload_length: None,
                    }),
                    details: None,
                },
            },

            Frame::StreamV3 {
                stream_id,
                metadata,
            } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: metadata.off(),
                length: metadata.len() as u64,
                fin: metadata.fin().then_some(true),
                raw: None,
            },

            Frame::Stream { stream_id, data } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: data.off(),
                length: data.len() as u64,
                fin: data.fin().then_some(true),
                raw: None,
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: *offset,
                length: *length as u64,
                fin: fin.then(|| true),
                raw: None,
            },

            Frame::MaxData { max } => QuicFrame::MaxData { maximum: *max },

            Frame::MaxStreamData { stream_id, max } => QuicFrame::MaxStreamData {
                stream_id: *stream_id,
                maximum: *max,
            },

            Frame::MaxStreamsBidi { max } => QuicFrame::MaxStreams {
                stream_type: StreamType::Bidirectional,
                maximum: *max,
            },

            Frame::MaxStreamsUni { max } => QuicFrame::MaxStreams {
                stream_type: StreamType::Unidirectional,
                maximum: *max,
            },

            Frame::DataBlocked { limit } =>
                QuicFrame::DataBlocked { limit: *limit },

            Frame::StreamDataBlocked { stream_id, limit } =>
                QuicFrame::StreamDataBlocked {
                    stream_id: *stream_id,
                    limit: *limit,
                },

            Frame::StreamsBlockedBidi { limit } => QuicFrame::StreamsBlocked {
                stream_type: StreamType::Bidirectional,
                limit: *limit,
            },

            Frame::StreamsBlockedUni { limit } => QuicFrame::StreamsBlocked {
                stream_type: StreamType::Unidirectional,
                limit: *limit,
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => QuicFrame::NewConnectionId {
                sequence_number: *seq_num as u32,
                retire_prior_to: *retire_prior_to as u32,
                connection_id_length: Some(conn_id.len() as u8),
                connection_id: format!("{}", qlog::HexSlice::new(conn_id)),
                stateless_reset_token: qlog::HexSlice::maybe_string(Some(
                    reset_token,
                )),
            },

            Frame::RetireConnectionId { seq_num } =>
                QuicFrame::RetireConnectionId {
                    sequence_number: *seq_num as u32,
                },

            Frame::PathChallenge { .. } =>
                QuicFrame::PathChallenge { data: None },

            Frame::PathResponse { .. } => QuicFrame::PathResponse { data: None },

            Frame::ConnectionClose {
                error_code, reason, ..
            } => QuicFrame::ConnectionClose {
                error_space: Some(ErrorSpace::TransportError),
                error_code: Some(*error_code),
                error_code_value: None, // raw error is no different for us
                reason: Some(String::from_utf8_lossy(reason).into_owned()),
                trigger_frame_type: None, // don't know trigger type
            },

            Frame::ApplicationClose { error_code, reason } => {
                QuicFrame::ConnectionClose {
                    error_space: Some(ErrorSpace::ApplicationError),
                    error_code: Some(*error_code),
                    error_code_value: None, // raw error is no different for us
                    reason: Some(String::from_utf8_lossy(reason).into_owned()),
                    trigger_frame_type: None, // don't know trigger type
                }
            },

            Frame::HandshakeDone => QuicFrame::HandshakeDone,

            Frame::Datagram { data } => QuicFrame::Datagram {
                length: data.len() as u64,
                raw: None,
            },

            Frame::DatagramHeader { length } => QuicFrame::Datagram {
                length: *length as u64,
                raw: None,
            },
        }
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Padding { len } => {
                write!(f, "PADDING len={len}")?;
            },

            Frame::Ping { mtu_probe } => {
                write!(f, "PING mtu_probe={mtu_probe:?}")?;
            },

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                write!(
                    f,
                    "ACK delay={ack_delay} blocks={ranges:?} ecn_counts={ecn_counts:?}"
                )?;
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                write!(
                    f,
                    "RESET_STREAM stream={stream_id} err={error_code:x} size={final_size}"
                )?;
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                write!(f, "STOP_SENDING stream={stream_id} err={error_code:x}")?;
            },

            Frame::Crypto { data } => {
                write!(f, "CRYPTO off={} len={}", data.off(), data.len())?;
            },

            Frame::CryptoHeader { offset, length } => {
                write!(f, "CRYPTO off={offset} len={length}")?;
            },

            Frame::NewToken { token } => {
                write!(f, "NEW_TOKEN len={}", token.len())?;
            },

            Frame::StreamV3 {
                stream_id,
                metadata,
            } => {
                write!(
                    f,
                    "STREAMV3 id={} off={} len={} fin={}",
                    stream_id,
                    metadata.off(),
                    metadata.len(),
                    metadata.fin()
                )?;
            },

            Frame::Stream { stream_id, data } => {
                write!(
                    f,
                    "STREAM id={} off={} len={} fin={}",
                    stream_id,
                    data.off(),
                    data.len(),
                    data.fin()
                )?;
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => {
                write!(
                    f,
                    "STREAM id={stream_id} off={offset} len={length} fin={fin}"
                )?;
            },

            Frame::MaxData { max } => {
                write!(f, "MAX_DATA max={max}")?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                write!(f, "MAX_STREAM_DATA stream={stream_id} max={max}")?;
            },

            Frame::MaxStreamsBidi { max } => {
                write!(f, "MAX_STREAMS type=bidi max={max}")?;
            },

            Frame::MaxStreamsUni { max } => {
                write!(f, "MAX_STREAMS type=uni max={max}")?;
            },

            Frame::DataBlocked { limit } => {
                write!(f, "DATA_BLOCKED limit={limit}")?;
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                write!(
                    f,
                    "STREAM_DATA_BLOCKED stream={stream_id} limit={limit}"
                )?;
            },

            Frame::StreamsBlockedBidi { limit } => {
                write!(f, "STREAMS_BLOCKED type=bidi limit={limit}")?;
            },

            Frame::StreamsBlockedUni { limit } => {
                write!(f, "STREAMS_BLOCKED type=uni limit={limit}")?;
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                write!(
                    f,
                    "NEW_CONNECTION_ID seq_num={seq_num} retire_prior_to={retire_prior_to} conn_id={conn_id:02x?} reset_token={reset_token:02x?}",
                )?;
            },

            Frame::RetireConnectionId { seq_num } => {
                write!(f, "RETIRE_CONNECTION_ID seq_num={seq_num}")?;
            },

            Frame::PathChallenge { data } => {
                write!(f, "PATH_CHALLENGE data={data:02x?}")?;
            },

            Frame::PathResponse { data } => {
                write!(f, "PATH_RESPONSE data={data:02x?}")?;
            },

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                write!(
                    f,
                    "CONNECTION_CLOSE err={error_code:x} frame={frame_type:x} reason={reason:x?}"
                )?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                write!(
                    f,
                    "APPLICATION_CLOSE err={error_code:x} reason={reason:x?}"
                )?;
            },

            Frame::HandshakeDone => {
                write!(f, "HANDSHAKE_DONE")?;
            },

            Frame::Datagram { data } => {
                write!(f, "DATAGRAM len={}", data.len())?;
            },

            Frame::DatagramHeader { length } => {
                write!(f, "DATAGRAM len={length}")?;
            },
        }

        Ok(())
    }
}

fn parse_ack_frame(
    ty: u64, b: &mut octets_rev::Octets, version: u32,
) -> Result<Frame> {
    let first = ty as u8;
    let mut ranges = ranges::RangeSet::default();

    let (largest_ack, ack_delay, block_count, ack_block) = if_likely! { version==crate::PROTOCOL_VERSION_VREVERSO => {
        (b.get_varint_reverse()?, b.get_varint_reverse()?, b.get_varint_reverse()?, b.get_varint_reverse()?)
    } else {
        (b.get_varint()?, b.get_varint()?, b.get_varint()?, b.get_varint()?)
    }};

    if largest_ack < ack_block {
        return Err(Error::InvalidFrame);
    }

    let mut smallest_ack = largest_ack - ack_block;

    ranges.insert(smallest_ack..largest_ack + 1);

    for _ in 0..block_count {
        let gap = if_likely! {version ==  crate::PROTOCOL_VERSION_VREVERSO => {
            b.get_varint_reverse()?
        } else {
            b.get_varint()?
        }};

        if smallest_ack < 2 + gap {
            return Err(Error::InvalidFrame);
        }

        let largest_ack = (smallest_ack - gap) - 2;
        let ack_block = if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
            b.get_varint_reverse()?
        } else {
            b.get_varint()?
        }};

        if largest_ack < ack_block {
            return Err(Error::InvalidFrame);
        }

        smallest_ack = largest_ack - ack_block;

        ranges.insert(smallest_ack..largest_ack + 1);
    }

    let ecn_counts = if first & 0x01 != 0 {
        let ecn = if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
            EcnCounts {
                ect0_count: b.get_varint_reverse()?,
                ect1_count: b.get_varint_reverse()?,
                ecn_ce_count: b.get_varint_reverse()?,
            }
        } else {
            EcnCounts {
                ect0_count: b.get_varint()?,
                ect1_count: b.get_varint()?,
                ecn_ce_count: b.get_varint()?,
            }
        }};
        Some(ecn)
    } else {
        None
    };

    Ok(Frame::ACK {
        ack_delay,
        ranges,
        ecn_counts,
    })
}

pub fn encode_crypto_header(
    offset: u64, length: u64, b: &mut octets_rev::OctetsMut,
) -> Result<()> {
    b.put_varint(0x06)?;

    b.put_varint(offset)?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

pub fn encode_crypto_footer(
    offset: u64, length: u64, b: &mut octets_rev::OctetsMut,
) -> Result<()> {
    b.put_varint_with_len_reverse(length, 2)?;

    b.put_varint_reverse(offset)?;

    b.put_varint_reverse(0x06)?;

    Ok(())
}

pub fn encode_stream_header(
    stream_id: u64, offset: u64, length: u64, fin: bool,
    b: &mut octets_rev::OctetsMut,
) -> Result<()> {
    let mut ty: u8 = 0x08;

    // Always encode offset.
    ty |= 0x04;

    // Always encode length.
    ty |= 0x02;

    if fin {
        ty |= 0x01;
    }
    b.put_varint(u64::from(ty))?;
    b.put_varint(stream_id)?;
    b.put_varint(offset)?;
    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;
    Ok(())
}
pub fn encode_stream_footer(
    stream_id: u64, offset: u64, length: u64, fin: bool,
    b: &mut octets_rev::OctetsMut,
) -> Result<()> {
    let mut ty: u8 = 0x08;

    // Always encode offset.
    ty |= 0x04;

    // Always encode length.
    ty |= 0x02;

    if fin {
        ty |= 0x01;
    }
    // Always encode length field as 2-byte varint.
    b.put_varint_with_len_reverse(length, 2)?;
    b.put_varint_reverse(offset)?;
    b.put_varint_reverse(stream_id)?;

    b.put_varint_reverse(u64::from(ty))?;

    Ok(())
}

pub fn encode_dgram_footer(
    length: u64, b: &mut octets_rev::OctetsMut,
) -> Result<()> {
    let mut ty: u8 = 0x30;

    // Always encode length
    ty |= 0x01;

    b.put_varint_with_len_reverse(length, 2)?;
    b.put_varint_reverse(u64::from(ty))?;

    Ok(())
}

pub fn encode_dgram_header(
    length: u64, b: &mut octets_rev::OctetsMut,
) -> Result<()> {
    let mut ty: u8 = 0x30;

    // Always encode length
    ty |= 0x01;

    b.put_varint(u64::from(ty))?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

fn parse_stream_frame(
    ty: u64, b: &mut octets_rev::Octets, version: u32,
) -> Result<Frame> {
    let first = ty as u8;

    if_likely! { version == crate::PROTOCOL_VERSION_VREVERSO => {

        let stream_id = b.get_varint_reverse()?;

        let offset = if first & 0x04 != 0 {
            b.get_varint_reverse()?
        } else {
            0
        };

        let len = if first & 0x02 != 0 {
            b.get_varint_reverse()? as usize
        } else {
            // should be all bytes until the begining of the buffer
            b.off()
        };

        if offset + len as u64 >= MAX_STREAM_SIZE {
            return Err(Error::InvalidFrame);
        }

        let fin = first & 0x01 != 0;
        b.rewind(len)?;
        // This avoids cloning the buffer, as does the RangeBuf.
        let metadata = stream::RecvBufInfo::from(offset, len, fin);

        Ok(Frame::StreamV3 { stream_id, metadata})

    } else {

        let stream_id = b.get_varint()?;

        let offset = if first & 0x04 != 0 {
            b.get_varint()?
        } else {
            0
        };

        let len = if first & 0x02 != 0 {
            b.get_varint()? as usize
        } else {
            b.cap()
        };

        if offset + len as u64 >= MAX_STREAM_SIZE {
            return Err(Error::InvalidFrame);
        }

        let fin = first & 0x01 != 0;

        let data = b.get_bytes(len)?;
        let data = <RangeBuf>::from(data.as_ref(), offset, fin);

        Ok(Frame::Stream { stream_id, data })
    }}
}

fn parse_datagram_frame(
    ty: u64, b: &mut octets_rev::Octets, version: u32,
) -> Result<Frame> {
    let first = ty as u8;

    let data = if_likely! {version == crate::PROTOCOL_VERSION_VREVERSO => {
        let len = if first & 0x01 != 0 {
            b.get_varint_reverse()? as usize
        }
        else {
            // this is equal to b.off(), but having a "reversed" function
            // should help for understanding the code.
            b.cap_reverse()
        };
        b.get_bytes_reverse(len)?
    } else {
        let len = if first & 0x01 != 0 {
            b.get_varint()? as usize
        } else {
            b.cap()
        };
        b.get_bytes(len)?
    }};

    Ok(Frame::Datagram {
        data: Vec::from(data.buf()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        let mut d = [42; 128];

        let frame = Frame::Padding { len: 128 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 128);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_ok());
    }

    #[test]
    fn ping() {
        let mut d = [42; 128];

        let frame = Frame::Ping { mtu_probe: None };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 1);
        // On V3 it should be 0x01 << 2
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_V1 {
            assert_eq!(&d[..wire_len], [0x01_u8]);
        }

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_ok());
    }

    #[test]
    fn ack() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let frame = Frame::ACK {
            ack_delay: 874_656_534,
            ranges,
            ecn_counts: None,
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_ok());
    }

    #[test]
    fn ack_ecn() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let ecn_counts = Some(EcnCounts {
            ect0_count: 100,
            ect1_count: 200,
            ecn_ce_count: 300,
        });

        let frame = Frame::ACK {
            ack_delay: 874_656_534,
            ranges,
            ecn_counts,
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 23);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_ok());
    }

    #[test]
    fn reset_stream() {
        let mut d = [42; 128];

        let frame = Frame::ResetStream {
            stream_id: 123_213,
            error_code: 21_123_767,
            final_size: 21_123_767,
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 13);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn stop_sending() {
        let mut d = [42; 128];

        let frame = Frame::StopSending {
            stream_id: 123_213,
            error_code: 15_352,
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn crypto() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Crypto {
            data: <RangeBuf>::from(&data, 1230976, false),
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 19);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_ok());
    }

    #[test]
    fn new_token() {
        let mut d = [42; 128];

        let frame = Frame::NewToken {
            token: Vec::from("this is a token"),
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn stream() {
        let mut d = [42; 128];
        let _d2 = [42; 128];
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let framev3 = Frame::StreamV3 {
            stream_id: 32,
            metadata: stream::RecvBufInfo::from(1230976, 12, true),
        };
        let frame = Frame::Stream {
            stream_id: 32,
            data: <RangeBuf>::from(&data, 1230976, true),
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 20);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
            assert_eq!(
                Frame::from_bytes(
                    &mut b,
                    packet::Type::Short,
                    crate::PROTOCOL_VERSION
                ),
                Ok(framev3)
            );
        } else {
            assert_eq!(
                Frame::from_bytes(
                    &mut b,
                    packet::Type::Short,
                    crate::PROTOCOL_VERSION
                ),
                Ok(frame)
            );
        }

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn stream_too_big() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: <RangeBuf>::from(&data, MAX_STREAM_SIZE - 11, true),
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 24);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Err(Error::InvalidFrame)
        );
    }

    #[test]
    fn max_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxData { max: 128_318_273 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn max_stream_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamData {
            stream_id: 12_321,
            max: 128_318_273,
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn max_streams_bidi() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsBidi { max: 128_318_273 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };
        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn max_streams_uni() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsUni { max: 128_318_273 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::DataBlocked { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn stream_data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::StreamDataBlocked {
            stream_id: 12_321,
            limit: 128_318_273,
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn streams_blocked_bidi() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedBidi { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn streams_blocked_uni() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedUni { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn new_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::NewConnectionId {
            seq_num: 123_213,
            retire_prior_to: 122_211,
            conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            reset_token: [0x42; 16],
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 41);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn retire_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::RetireConnectionId { seq_num: 123_213 };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn path_challenge() {
        let mut d = [42; 128];

        let frame = Frame::PathChallenge {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn path_response() {
        let mut d = [42; 128];

        let frame = Frame::PathResponse {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn connection_close() {
        let mut d = [42; 128];

        let frame = Frame::ConnectionClose {
            error_code: 0xbeef,
            frame_type: 523_423,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 22);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_ok());
    }

    #[test]
    fn application_close() {
        let mut d = [42; 128];

        let frame = Frame::ApplicationClose {
            error_code: 0xbeef,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 18);
        let mut b = octets_rev::Octets::with_slice(&d);

        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }

        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn handshake_done() {
        let mut d = [42; 128];

        let frame = Frame::HandshakeDone;

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 1);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }

        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame)
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());
    }

    #[test]
    fn datagram() {
        let mut d = [42; 128];

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Datagram { data: data.clone() };

        let wire_len = {
            let mut b = octets_rev::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b, crate::PROTOCOL_VERSION).unwrap()
        };

        assert_eq!(wire_len, 15);

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert_eq!(
            Frame::from_bytes(
                &mut b,
                packet::Type::Short,
                crate::PROTOCOL_VERSION
            ),
            Ok(frame.clone())
        );

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Initial,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::ZeroRTT,
            crate::PROTOCOL_VERSION
        )
        .is_ok());

        let mut b = octets_rev::Octets::with_slice(&d);
        if crate::PROTOCOL_VERSION == crate::PROTOCOL_VERSION_VREVERSO {
            b.skip(wire_len).expect("skip issue");
        }
        assert!(Frame::from_bytes(
            &mut b,
            packet::Type::Handshake,
            crate::PROTOCOL_VERSION
        )
        .is_err());

        let frame_data = match &frame {
            Frame::Datagram { data } => data.clone(),

            _ => unreachable!(),
        };

        assert_eq!(frame_data, data);
    }
}