use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Ipv6FragmentMetadata<'a> {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    fragment_offset: usize,
    more_fragments: bool,
    next_header: u8,
    previous_next_header_offset: usize,
    unfragmentable_prefix: &'a [u8],
    payload: &'a [u8],
}

pub(crate) fn parse_ipv6_fragment_metadata(
    bytes: &[u8],
) -> Result<Option<Ipv6FragmentMetadata<'_>>> {
    if bytes.is_empty() || bytes[0] >> 4 != 6 {
        return Ok(None);
    }
    if bytes.len() < 40 {
        return Err(Error::invalid("malformed IPv6 packet"));
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let packet_len = 40usize
        .checked_add(payload_len)
        .ok_or_else(|| Error::invalid("IPv6 packet length overflow"))?;
    if packet_len > bytes.len() {
        return Err(Error::invalid("malformed IPv6 packet length"));
    }
    let bytes = &bytes[..packet_len];
    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&bytes[8..24])
            .map_err(|_| Error::invalid("malformed IPv6 source address"))?,
    );
    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(&bytes[24..40])
            .map_err(|_| Error::invalid("malformed IPv6 destination address"))?,
    );
    let mut next_header = bytes[6];
    let mut previous_next_header_offset = 6usize;
    let mut offset = 40usize;

    // Hop-by-hop, routing and destination options are TLV extension headers
    // whose length is expressed in eight-octet units. AH uses four-octet
    // units. Stop at ESP/unknown headers rather than guessing offsets from
    // attacker-controlled bytes.
    for _ in 0..16 {
        match next_header {
            44 => {
                if offset + 8 > bytes.len() {
                    return Err(Error::invalid("truncated IPv6 fragment header"));
                }
                let raw_offset_and_flags =
                    u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                let fragment_offset = ((raw_offset_and_flags >> 3) as usize) * 8;
                let more_fragments = raw_offset_and_flags & 1 != 0;
                let fragment_payload = &bytes[offset + 8..];
                if more_fragments
                    && (fragment_payload.is_empty() || !fragment_payload.len().is_multiple_of(8))
                {
                    return Err(Error::invalid("invalid IPv6 fragment payload alignment"));
                }
                // RFC 8200 permits an atomic fragment, but it is not a
                // reassembly input. Passing it through preserves the raw
                // packet contract; smoltcp will decide whether the following
                // extension chain is supported.
                if fragment_offset == 0 && !more_fragments {
                    return Ok(None);
                }
                return Ok(Some(Ipv6FragmentMetadata {
                    source,
                    destination,
                    identification: u32::from_be_bytes([
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                        bytes[offset + 7],
                    ]),
                    fragment_offset,
                    more_fragments,
                    next_header: bytes[offset],
                    previous_next_header_offset,
                    unfragmentable_prefix: &bytes[..offset],
                    payload: fragment_payload,
                }));
            }
            0 | 43 | 60 => {
                if offset + 2 > bytes.len() {
                    return Err(Error::invalid("truncated IPv6 extension header"));
                }
                let header_len = (bytes[offset + 1] as usize + 1) * 8;
                if header_len < 8 || offset + header_len > bytes.len() {
                    return Err(Error::invalid("invalid IPv6 extension header length"));
                }
                previous_next_header_offset = offset;
                next_header = bytes[offset];
                offset += header_len;
            }
            51 => {
                if offset + 2 > bytes.len() {
                    return Err(Error::invalid("truncated IPv6 AH header"));
                }
                let header_len = (bytes[offset + 1] as usize + 2) * 4;
                if header_len < 12 || offset + header_len > bytes.len() {
                    return Err(Error::invalid("invalid IPv6 AH header length"));
                }
                previous_next_header_offset = offset;
                next_header = bytes[offset];
                offset += header_len;
            }
            _ => return Ok(None),
        }
    }
    Err(Error::invalid("IPv6 extension header chain is too long"))
}

pub(crate) fn ipv6_has_fragment_header(bytes: &[u8]) -> bool {
    parse_ipv6_fragment_metadata(bytes).ok().flatten().is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Ipv6FragmentKey {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    next_header: u8,
}

#[derive(Debug)]
pub(crate) struct Ipv6FragmentPiece {
    start: usize,
    end: usize,
    payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Ipv6FragmentAssembly {
    unfragmentable_prefix: Vec<u8>,
    previous_next_header_offset: usize,
    next_header: u8,
    pieces: Vec<Ipv6FragmentPiece>,
    received_bytes: usize,
    total_payload: Option<usize>,
    expires_at: StdInstant,
}

impl Ipv6FragmentAssembly {
    fn memory_bytes(&self) -> usize {
        self.unfragmentable_prefix
            .len()
            .saturating_add(self.received_bytes)
    }

    fn complete(&self) -> Option<usize> {
        let total = self.total_payload?;
        let mut pieces = self
            .pieces
            .iter()
            .map(|piece| (piece.start, piece.end))
            .collect::<Vec<_>>();
        pieces.sort_unstable_by_key(|(start, _)| *start);
        let mut covered = 0usize;
        for (start, end) in pieces {
            if start != covered {
                return None;
            }
            covered = end;
        }
        (covered == total).then_some(total)
    }

    fn finish(self, total_payload: usize) -> Option<Vec<u8>> {
        let payload_length = self
            .unfragmentable_prefix
            .len()
            .checked_sub(40)?
            .checked_add(total_payload)?;
        if payload_length > u16::MAX as usize {
            return None;
        }
        let mut packet = self.unfragmentable_prefix;
        packet[self.previous_next_header_offset] = self.next_header;
        packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        let payload_start = packet.len();
        packet.resize(payload_start + total_payload, 0);
        for piece in self.pieces {
            packet[payload_start + piece.start..payload_start + piece.end]
                .copy_from_slice(&piece.payload);
        }
        Some(packet)
    }
}

pub(crate) fn ipv6_unfragmentable_prefixes_match(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.get(..4) == right.get(..4) && left.get(6..) == right.get(6..)
}

#[derive(Debug, Default)]
pub struct Ipv6FragmentReassembler {
    pub(crate) assemblies: HashMap<Ipv6FragmentKey, Ipv6FragmentAssembly>,
    pub(crate) buffered_bytes: usize,
}

impl Ipv6FragmentReassembler {
    fn remove_assembly(&mut self, key: &Ipv6FragmentKey) -> Option<Ipv6FragmentAssembly> {
        let assembly = self.assemblies.remove(key)?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly.memory_bytes());
        Some(assembly)
    }

    /// Remove assemblies that have exceeded the bounded reassembly timeout.
    pub fn expire(&mut self, now: StdInstant) {
        let mut released = 0usize;
        self.assemblies.retain(|_, assembly| {
            if assembly.expires_at > now {
                true
            } else {
                released = released.saturating_add(assembly.memory_bytes());
                false
            }
        });
        self.buffered_bytes = self.buffered_bytes.saturating_sub(released);
    }

    /// Return the packet to enqueue, or `None` for an incomplete/invalid
    /// assembly. Invalid and resource-exhausted fragments are intentionally
    /// dropped without poisoning the TUN runtime.
    /// Add one IP packet to the reassembler.
    ///
    /// Non-fragmented packets are returned unchanged. A fragmented packet
    /// returns `None` until all pieces arrive; malformed, overlapping, or
    /// resource-exhausted assemblies are dropped and also return `None`.
    pub fn push(&mut self, packet: &[u8], now: StdInstant) -> Result<Option<Vec<u8>>> {
        self.push_borrowed(packet, now)
            .map(|packet| packet.map(Cow::into_owned))
    }

    /// Borrow non-fragmented packets instead of copying them into a second
    /// temporary `Vec`. Fragmented packets still produce an owned reassembly.
    pub fn push_borrowed<'a>(
        &mut self,
        packet: &'a [u8],
        now: StdInstant,
    ) -> Result<Option<Cow<'a, [u8]>>> {
        self.expire(now);
        let Some(metadata) = parse_ipv6_fragment_metadata(packet)? else {
            return Ok(Some(Cow::Borrowed(packet)));
        };
        let fragment_end = metadata
            .fragment_offset
            .checked_add(metadata.payload.len())
            .ok_or_else(|| Error::invalid("IPv6 fragment offset overflow"))?;
        if fragment_end > IPV6_FRAGMENT_MAX_PACKET
            || metadata.unfragmentable_prefix.len() > IPV6_FRAGMENT_MAX_PACKET
            || metadata
                .unfragmentable_prefix
                .len()
                .saturating_add(fragment_end)
                > IPV6_FRAGMENT_MAX_PACKET
        {
            return Ok(None);
        }
        let key = Ipv6FragmentKey {
            source: metadata.source,
            destination: metadata.destination,
            identification: metadata.identification,
            next_header: metadata.next_header,
        };
        if !self.assemblies.contains_key(&key) {
            if self.assemblies.len() >= IPV6_FRAGMENT_MAX_ENTRIES {
                return Ok(None);
            }
            let required = metadata
                .unfragmentable_prefix
                .len()
                .saturating_add(metadata.payload.len());
            if self.buffered_bytes.saturating_add(required) > IPV6_FRAGMENT_MAX_TOTAL_BYTES {
                return Ok(None);
            }
            self.assemblies.insert(
                key,
                Ipv6FragmentAssembly {
                    unfragmentable_prefix: metadata.unfragmentable_prefix.to_vec(),
                    previous_next_header_offset: metadata.previous_next_header_offset,
                    next_header: metadata.next_header,
                    pieces: Vec::new(),
                    received_bytes: 0,
                    total_payload: None,
                    expires_at: now + IPV6_FRAGMENT_TIMEOUT,
                },
            );
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_add(metadata.unfragmentable_prefix.len());
        }

        if self.buffered_bytes.saturating_add(metadata.payload.len())
            > IPV6_FRAGMENT_MAX_TOTAL_BYTES
        {
            self.remove_assembly(&key);
            return Ok(None);
        }

        let Some(assembly) = self.assemblies.get_mut(&key) else {
            return Ok(None);
        };
        if !ipv6_unfragmentable_prefixes_match(
            &assembly.unfragmentable_prefix,
            metadata.unfragmentable_prefix,
        ) || assembly.previous_next_header_offset != metadata.previous_next_header_offset
            || assembly.next_header != metadata.next_header
            || assembly.pieces.len() >= IPV6_FRAGMENT_MAX_FRAGMENTS
            || assembly
                .received_bytes
                .saturating_add(metadata.payload.len())
                > IPV6_FRAGMENT_MAX_PACKET
        {
            self.remove_assembly(&key);
            return Ok(None);
        }
        if assembly
            .pieces
            .iter()
            .any(|piece| metadata.fragment_offset < piece.end && fragment_end > piece.start)
        {
            // Overlap handling is deliberately fail-closed. Accepting either
            // first- or last-fragment bytes creates ambiguous security policy.
            self.remove_assembly(&key);
            return Ok(None);
        }
        if let Some(total) = assembly.total_payload
            && fragment_end > total
        {
            self.remove_assembly(&key);
            return Ok(None);
        }
        if !metadata.more_fragments {
            if let Some(total) = assembly.total_payload
                && total != fragment_end
            {
                self.remove_assembly(&key);
                return Ok(None);
            }
            assembly.total_payload = Some(fragment_end);
        }
        assembly.received_bytes += metadata.payload.len();
        assembly.pieces.push(Ipv6FragmentPiece {
            start: metadata.fragment_offset,
            end: fragment_end,
            payload: metadata.payload.to_vec(),
        });
        self.buffered_bytes = self.buffered_bytes.saturating_add(metadata.payload.len());
        let Some(total) = assembly.complete() else {
            return Ok(None);
        };
        let assembly = self.remove_assembly(&key).expect("assembly exists");
        Ok(assembly.finish(total).map(Cow::Owned))
    }
}
