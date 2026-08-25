//! VMess v2 TCP client and wire codec.

#[path = "vmess_body.rs"]
mod body;
#[path = "vmess_codec.rs"]
mod codec;
#[path = "vmess_stream.rs"]
mod stream;

pub use body::{read_body_frame, write_body_frame};
pub use codec::{
    Request, Security, command_key, decode_request, decode_response_header, encode_legacy_request,
    encode_legacy_response_header, encode_request, encode_response_header, read_request,
};
pub use stream::VmessProxy;

// Test-only access to stable wire constants and crypto helpers.
#[cfg(test)]
pub(crate) use body::{chacha_key, response_key_for};
#[cfg(test)]
pub(crate) use codec::{
    CMD_TCP, CMD_UDP, MAX_ALTER_ID, VERSION, VMESS_HEADER_PAYLOAD_KEY, aes_cfb_xor, alter_id_users,
    fnv1a, kdf, legacy_auth_id, legacy_timestamp_iv,
};
#[cfg(test)]
pub(crate) use stream::{VmessDatagram, VmessDatagramReader, VmessDatagramWriter};

#[cfg(test)]
#[path = "vmess_tests.rs"]
mod tests;
