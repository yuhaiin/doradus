//! The UDP envelope carried in QUIC DATAGRAM frames.
//!
//! A datagram starts with a QUIC varint tag. The tag is
//! `(association_id << 1) | fragmented`, so association IDs stay compact for
//! the common case while still allowing a 30-bit ID space:
//!
//! ```text
//! single:     tag + payload
//! fragmented: tag + message_id:u32 + fragment_index:u16 + fragment_count:u16
//!             + fragment_payload
//! ```
//!
//! Fragmentation is deliberately best-effort. QUIC DATAGRAM does not
//! retransmit fragments; the reassembler emits a payload only after every
//! fragment arrives, and drops the partial message after its timeout or when
//! its bounded memory budget is exceeded.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAX_REASSEMBLED_PAYLOAD: usize = 128 * 1024;
pub const MAX_FRAGMENT_COUNT: usize = 1024;
pub const MAX_INCOMPLETE_BYTES_PER_ASSOCIATION: usize = 1024 * 1024;
pub const FRAGMENT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);
pub const FRAGMENT_HEADER_LEN: usize = 8;
pub const MAX_ASSOCIATION_ID: u32 = (1 << 29) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Single {
        association_id: u32,
        payload: &'a [u8],
    },
    Fragment {
        association_id: u32,
        message_id: u32,
        fragment_index: u16,
        fragment_count: u16,
        payload: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    InvalidAssociationId,
    InvalidFragmentCount,
    InvalidFragmentIndex,
    EmptyFragment,
    PayloadTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    InvalidAssociationId,
    DatagramTooSmall,
    PayloadTooLarge,
    TooManyFragments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedDatagrams<'a> {
    pub payload: &'a [u8],
    pub association_id: u32,
    pub message_id: u32,
    pub max_datagram_size: usize,
}

impl<'a> EncodedDatagrams<'a> {
    pub fn encode(self) -> Result<Vec<Vec<u8>>, EncodeError> {
        validate_association_id(self.association_id)?;
        if self.payload.len() > MAX_REASSEMBLED_PAYLOAD {
            return Err(EncodeError::PayloadTooLarge);
        }

        let tag = tag_value(self.association_id, false)?;
        let tag_len = varint_len(tag);
        if self.max_datagram_size < tag_len {
            return Err(EncodeError::DatagramTooSmall);
        }
        if self.payload.len() <= self.max_datagram_size - tag_len {
            let mut datagram = Vec::with_capacity(tag_len + self.payload.len());
            put_varint(tag, &mut datagram);
            datagram.extend_from_slice(self.payload);
            return Ok(vec![datagram]);
        }

        let fragment_tag = tag_value(self.association_id, true)?;
        let fragment_tag_len = varint_len(fragment_tag);
        let overhead = fragment_tag_len + FRAGMENT_HEADER_LEN;
        let chunk_size = self
            .max_datagram_size
            .checked_sub(overhead)
            .ok_or(EncodeError::DatagramTooSmall)?;
        if chunk_size == 0 {
            return Err(EncodeError::DatagramTooSmall);
        }
        let fragment_count = self.payload.len().div_ceil(chunk_size);
        if !(2..=MAX_FRAGMENT_COUNT).contains(&fragment_count) {
            return Err(EncodeError::TooManyFragments);
        }

        let mut datagrams = Vec::with_capacity(fragment_count);
        for (index, payload) in self.payload.chunks(chunk_size).enumerate() {
            let mut datagram = Vec::with_capacity(overhead + payload.len());
            put_varint(fragment_tag, &mut datagram);
            datagram.extend_from_slice(&self.message_id.to_be_bytes());
            datagram.extend_from_slice(&(index as u16).to_be_bytes());
            datagram.extend_from_slice(&(fragment_count as u16).to_be_bytes());
            datagram.extend_from_slice(payload);
            datagrams.push(datagram);
        }
        Ok(datagrams)
    }
}

pub fn encode_datagrams(
    association_id: u32,
    message_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>, EncodeError> {
    EncodedDatagrams {
        payload,
        association_id,
        message_id,
        max_datagram_size,
    }
    .encode()
}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, DecodeError> {
    let (tag, tag_len) = get_varint(bytes)?;
    let fragmented = tag & 1 != 0;
    let association_id = tag >> 1;
    validate_association_id(association_id).map_err(|_| DecodeError::InvalidAssociationId)?;
    if !fragmented {
        if bytes.len() - tag_len > MAX_REASSEMBLED_PAYLOAD {
            return Err(DecodeError::PayloadTooLarge);
        }
        return Ok(Frame::Single {
            association_id,
            payload: &bytes[tag_len..],
        });
    }

    let header_end = tag_len
        .checked_add(FRAGMENT_HEADER_LEN)
        .ok_or(DecodeError::Truncated)?;
    if bytes.len() < header_end {
        return Err(DecodeError::Truncated);
    }
    let message_id = u32::from_be_bytes(bytes[tag_len..tag_len + 4].try_into().unwrap());
    let fragment_index = u16::from_be_bytes(bytes[tag_len + 4..tag_len + 6].try_into().unwrap());
    let fragment_count = u16::from_be_bytes(bytes[tag_len + 6..header_end].try_into().unwrap());
    if fragment_count < 2 || usize::from(fragment_count) > MAX_FRAGMENT_COUNT {
        return Err(DecodeError::InvalidFragmentCount);
    }
    if fragment_index >= fragment_count {
        return Err(DecodeError::InvalidFragmentIndex);
    }
    if bytes.len() == header_end {
        return Err(DecodeError::EmptyFragment);
    }
    Ok(Frame::Fragment {
        association_id,
        message_id,
        fragment_index,
        fragment_count,
        payload: &bytes[header_end..],
    })
}

pub fn varint_len(value: u32) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => unreachable!("association tags are limited to QUIC's 30-bit varint"),
    }
}

fn tag_value(association_id: u32, fragmented: bool) -> Result<u32, EncodeError> {
    validate_association_id(association_id)?;
    Ok((association_id << 1) | u32::from(fragmented))
}

fn validate_association_id(association_id: u32) -> Result<(), EncodeError> {
    if association_id == 0 || association_id > MAX_ASSOCIATION_ID {
        return Err(EncodeError::InvalidAssociationId);
    }
    Ok(())
}

fn put_varint(value: u32, output: &mut Vec<u8>) {
    match varint_len(value) {
        1 => output.push(value as u8),
        2 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => output.extend_from_slice(&(value | 0xC000_0000).to_be_bytes()),
        _ => unreachable!(),
    }
}

fn get_varint(bytes: &[u8]) -> Result<(u32, usize), DecodeError> {
    let first = *bytes.first().ok_or(DecodeError::Truncated)?;
    match first >> 6 {
        0 => Ok((u32::from(first), 1)),
        1 => {
            if bytes.len() < 2 {
                return Err(DecodeError::Truncated);
            }
            Ok((u32::from(u16::from_be_bytes([first & 0x3f, bytes[1]])), 2))
        }
        3 => {
            if bytes.len() < 4 {
                return Err(DecodeError::Truncated);
            }
            Ok((
                u32::from_be_bytes([first & 0x3f, bytes[1], bytes[2], bytes[3]]),
                4,
            ))
        }
        _ => Err(DecodeError::InvalidAssociationId),
    }
}

#[derive(Debug)]
struct PartialMessage {
    created_at: Instant,
    fragment_count: u16,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
}

#[derive(Debug)]
pub struct FragmentReassembler {
    messages: HashMap<(u32, u32), PartialMessage>,
    incomplete_bytes: usize,
    timeout: Duration,
    max_incomplete_bytes: usize,
}

impl FragmentReassembler {
    pub fn new(timeout: Duration, max_incomplete_bytes: usize) -> Self {
        Self {
            messages: HashMap::new(),
            incomplete_bytes: 0,
            timeout,
            max_incomplete_bytes,
        }
    }

    pub fn push(&mut self, frame: Frame<'_>, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        match frame {
            Frame::Single { payload, .. } => {
                (payload.len() <= MAX_REASSEMBLED_PAYLOAD).then(|| payload.to_vec())
            }
            Frame::Fragment {
                association_id,
                message_id,
                fragment_index,
                fragment_count,
                payload,
            } => self.push_fragment(
                (association_id, message_id),
                fragment_index,
                fragment_count,
                payload,
                now,
            ),
        }
    }

    pub fn incomplete_bytes(&self) -> usize {
        self.incomplete_bytes
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn push_fragment(
        &mut self,
        key: (u32, u32),
        fragment_index: u16,
        fragment_count: u16,
        payload: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let fragment_count_usize = usize::from(fragment_count);
        let entry = self.messages.entry(key).or_insert_with(|| PartialMessage {
            created_at: now,
            fragment_count,
            fragments: vec![None; fragment_count_usize],
            received: 0,
        });
        if entry.fragment_count != fragment_count {
            self.remove(&key);
            return None;
        }
        if entry.fragments[usize::from(fragment_index)].is_some() {
            return None;
        }
        let next_size = self.incomplete_bytes.saturating_add(payload.len());
        if entry.received.saturating_add(payload.len()) > MAX_REASSEMBLED_PAYLOAD
            || next_size > self.max_incomplete_bytes
        {
            self.remove(&key);
            return None;
        }
        entry.fragments[usize::from(fragment_index)] = Some(payload.to_vec());
        entry.received += payload.len();
        self.incomplete_bytes += payload.len();
        if entry.received == 0 || entry.fragments.iter().any(Option::is_none) {
            return None;
        }

        let entry = self.messages.remove(&key).unwrap();
        self.incomplete_bytes -= entry.received;
        let mut output = Vec::with_capacity(entry.received);
        for fragment in entry.fragments.into_iter().flatten() {
            output.extend_from_slice(&fragment);
        }
        Some(output)
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let timeout = self.timeout;
        let expired: Vec<_> = self
            .messages
            .iter()
            .filter(|(_, message)| now.saturating_duration_since(message.created_at) >= timeout)
            .map(|(key, _)| *key)
            .collect();
        let count = expired.len();
        for key in expired {
            self.remove(&key);
        }
        count
    }

    fn remove(&mut self, key: &(u32, u32)) {
        if let Some(message) = self.messages.remove(key) {
            self.incomplete_bytes = self.incomplete_bytes.saturating_sub(message.received);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_frame_round_trips_with_compact_tag() {
        let datagrams = encode_datagrams(7, 1, b"hello", 1200).unwrap();
        assert_eq!(datagrams, vec![vec![14, b'h', b'e', b'l', b'l', b'o']]);
        assert_eq!(
            decode_frame(&datagrams[0]).unwrap(),
            Frame::Single {
                association_id: 7,
                payload: b"hello"
            }
        );
    }

    #[test]
    fn fragmented_frame_round_trips_and_reassembles_out_of_order() {
        let payload: Vec<u8> = (0..100).map(|value| value as u8).collect();
        let datagrams = encode_datagrams(70, 42, &payload, 40).unwrap();
        assert!(datagrams.len() > 2);
        assert!(datagrams.iter().all(|datagram| datagram.len() <= 40));
        let mut reassembler = FragmentReassembler::new(Duration::from_secs(2), 1024 * 1024);
        let now = Instant::now();
        let mut output = None;
        for datagram in datagrams.iter().rev() {
            output = reassembler.push(decode_frame(datagram).unwrap(), now);
            if output.is_some() {
                break;
            }
        }
        assert_eq!(output.as_deref(), Some(payload.as_slice()));
        assert_eq!(reassembler.incomplete_bytes(), 0);
    }

    #[test]
    fn duplicate_fragment_does_not_complete_or_double_count() {
        let datagrams = encode_datagrams(1, 5, &[9; 50], 30).unwrap();
        let mut reassembler = FragmentReassembler::new(Duration::from_secs(2), 1024);
        let now = Instant::now();
        let frame = decode_frame(&datagrams[0]).unwrap();
        assert!(reassembler.push(frame, now).is_none());
        assert!(reassembler.push(frame, now).is_none());
        assert_eq!(
            reassembler.incomplete_bytes(),
            datagrams[0].len() - 1 - FRAGMENT_HEADER_LEN
        );
    }

    #[test]
    fn timeout_discards_incomplete_message() {
        let datagrams = encode_datagrams(1, 5, &[9; 50], 30).unwrap();
        let mut reassembler = FragmentReassembler::new(Duration::from_secs(2), 1024);
        let started = Instant::now();
        assert!(
            reassembler
                .push(decode_frame(&datagrams[0]).unwrap(), started)
                .is_none()
        );
        assert_eq!(reassembler.expire(started + Duration::from_secs(2)), 1);
        assert_eq!(reassembler.len(), 0);
        assert_eq!(reassembler.incomplete_bytes(), 0);
    }

    #[test]
    fn invalid_frames_are_rejected_without_panicking() {
        assert_eq!(decode_frame(&[]), Err(DecodeError::Truncated));
        assert_eq!(decode_frame(&[0]), Err(DecodeError::InvalidAssociationId));
        assert_eq!(decode_frame(&[3, 0, 0, 0]), Err(DecodeError::Truncated));
        assert_eq!(
            decode_frame(&[3, 0, 0, 0, 0, 0, 1, 0, 0]),
            Err(DecodeError::InvalidFragmentCount)
        );
    }

    #[test]
    fn payload_limits_are_explicit() {
        assert_eq!(
            encode_datagrams(1, 1, &[0; MAX_REASSEMBLED_PAYLOAD + 1], 1200),
            Err(EncodeError::PayloadTooLarge)
        );
        assert_eq!(
            encode_datagrams(1, 1, &[0; 100], 8),
            Err(EncodeError::DatagramTooSmall)
        );
    }

    #[test]
    fn association_tags_use_quic_varint_boundaries() {
        for association_id in [1, 31, 32, 8_191, 8_192, MAX_ASSOCIATION_ID] {
            let datagram = encode_datagrams(association_id, 1, b"x", 1200)
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(
                decode_frame(&datagram).unwrap(),
                Frame::Single {
                    association_id,
                    payload: b"x"
                }
            );
            assert_eq!(varint_len(association_id << 1), datagram.len() - 1);
        }
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 4);
    }

    #[test]
    fn an_empty_payload_can_exactly_fill_the_tag() {
        let datagrams = encode_datagrams(32, 1, &[], 2).unwrap();
        assert_eq!(datagrams, vec![vec![0x40, 0x40]]);
        assert_eq!(
            decode_frame(&datagrams[0]).unwrap(),
            Frame::Single {
                association_id: 32,
                payload: &[]
            }
        );
    }

    #[test]
    fn even_an_empty_payload_needs_room_for_its_association_tag() {
        assert_eq!(
            encode_datagrams(32, 1, &[], 1),
            Err(EncodeError::DatagramTooSmall)
        );
    }

    #[test]
    fn oversized_and_empty_fragment_frames_are_rejected() {
        let mut oversized = vec![2];
        oversized.resize(1 + MAX_REASSEMBLED_PAYLOAD + 1, 0);
        assert_eq!(decode_frame(&oversized), Err(DecodeError::PayloadTooLarge));

        assert_eq!(
            decode_frame(&[3, 0, 0, 0, 1, 0, 0, 0, 2]),
            Err(DecodeError::EmptyFragment)
        );
    }

    #[test]
    fn incomplete_fragment_budget_discards_the_whole_message() {
        let datagrams = encode_datagrams(1, 5, &[9; 50], 30).unwrap();
        let mut reassembler = FragmentReassembler::new(Duration::from_secs(2), 10);
        assert!(
            reassembler
                .push(decode_frame(&datagrams[0]).unwrap(), Instant::now())
                .is_none()
        );
        assert_eq!(reassembler.len(), 0);
        assert_eq!(reassembler.incomplete_bytes(), 0);
    }
}
