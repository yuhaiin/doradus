//! Shared process-level fixtures for runtime integration tests.
//!
//! The fixtures deliberately use loopback sockets and a cache-owned state
//! directory. `DORADUS_INTEGRATION_DIR` can point at a persistent directory
//! when a developer or Podman job wants to inspect/reuse the SQLite state.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Cursor};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use doradus_chain::{YuubinsyaH2Server, YuubinsyaServerProxy};
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, FlowContext, Result};
use doradus_protocol::proxy::DirectAsyncProxy;
use doradus_protocol::yuubinsya::derive_salt;
use doradus_store::ConfigStore;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

use p256_tls_auto::ecdsa::{DerSignature, SigningKey};
use p256_tls_auto::elliptic_curve::rand_core::OsRng;
use p256_tls_auto::pkcs8::EncodePrivateKey;
use p256_tls_auto::{PublicKey, SecretKey};

pub const YUUBINSYA_PASSWORD: &str = "runtime-integration-yuubinsya";
const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

mod client;
mod fixtures;
mod inbound_config;
mod network;
mod outbound_config;
mod process;

pub use client::*;
pub use fixtures::*;
#[allow(unused_imports)]
pub use inbound_config::*;
pub use network::*;
#[allow(unused_imports)]
pub use outbound_config::*;
pub use process::*;
