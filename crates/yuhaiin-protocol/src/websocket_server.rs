//! WebSocket server-side handshake adapter.
//!
//! Runtime code decides which listener and route should receive the upgraded
//! stream. This module owns only the WebSocket handshake and Go-compatible
//! `early_data` negotiation.

use base64::Engine as _;
use yuhaiin_core::{Error, ErrorKind, Result};

use crate::websocket::WebSocketIo;

#[allow(clippy::result_large_err)]
pub async fn accept_stream<S>(stream: S) -> Result<(WebSocketIo<S>, Vec<u8>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut early_data = Vec::new();
    let websocket = tokio_tungstenite::accept_hdr_async(
        stream,
        |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
         mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            let wants_early_data = request
                .headers()
                .get("early_data")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("base64"));
            if !wants_early_data {
                return Ok(response);
            }
            let Some(key) = request.headers().get("Sec-WebSocket-Key") else {
                return Ok(response);
            };
            let Ok(decoded) =
                base64::engine::general_purpose::STANDARD_NO_PAD.decode(key.as_bytes())
            else {
                return Ok(response);
            };
            if decoded.len() > 2048 {
                return Ok(response);
            }
            early_data = decoded;
            response.headers_mut().insert(
                "early_data",
                tokio_tungstenite::tungstenite::http::HeaderValue::from_static("true"),
            );
            Ok(response)
        },
    )
    .await
    .map_err(|error| Error::new(ErrorKind::Protocol, format!("WebSocket handshake: {error}")))?;
    Ok((WebSocketIo::new(websocket), early_data))
}
