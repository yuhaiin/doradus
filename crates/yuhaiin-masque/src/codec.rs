use bytes::Bytes;
use yuhaiin_core::{Error, ErrorKind, Result};

pub(crate) fn encode_datagram(flow_id: u64, packet: &[u8]) -> Result<Bytes> {
    let mut output = Vec::with_capacity(16 + packet.len());
    encode_varint(flow_id, &mut output)?;
    encode_varint(0, &mut output)?;
    output.extend_from_slice(packet);
    Ok(Bytes::from(output))
}

pub(crate) fn decode_datagram(bytes: &[u8]) -> Result<(u64, &[u8])> {
    let (flow_id, consumed) = decode_varint(bytes)?;
    let (context_id, context_len) = decode_varint(&bytes[consumed..])?;
    if context_id != 0 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("WARP MASQUE received unsupported context ID {context_id}"),
        ));
    }
    let payload_start = consumed + context_len;
    if payload_start > bytes.len() {
        return Err(Error::invalid("WARP MASQUE datagram has no payload"));
    }
    Ok((flow_id, &bytes[payload_start..]))
}

fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<()> {
    if value > ((1u64 << 62) - 1) {
        return Err(Error::invalid("WARP MASQUE varint is too large"));
    }
    if value < (1 << 6) {
        output.push(value as u8);
    } else if value < (1 << 14) {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&((value | 0xc000_0000_0000_0000).to_be_bytes()));
    }
    Ok(())
}

fn decode_varint(input: &[u8]) -> Result<(u64, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| Error::invalid("WARP MASQUE datagram is missing a flow ID"))?;
    let length = 1usize << (first >> 6);
    if input.len() < length {
        return Err(Error::invalid(
            "WARP MASQUE datagram has a truncated varint",
        ));
    }
    let mut value = match length {
        1 => u64::from(first),
        2 => u64::from(u16::from_be_bytes([input[0], input[1]])),
        4 => u64::from(u32::from_be_bytes(input[..4].try_into().unwrap())),
        8 => u64::from_be_bytes(input[..8].try_into().unwrap()),
        _ => unreachable!(),
    };
    value &= (1u64 << (length * 8 - 2)) - 1;
    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_flow_datagram() {
        let encoded = encode_datagram(4, b"packet").unwrap();
        let (flow_id, payload) = decode_datagram(&encoded).unwrap();
        assert_eq!(flow_id, 4);
        assert_eq!(payload, b"packet");
    }

    #[test]
    fn rejects_non_zero_context() {
        assert!(decode_datagram(&[4, 1, 1]).is_err());
    }
}
