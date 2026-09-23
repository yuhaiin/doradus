use super::*;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use doradus_core::dns::{DnsResponse, encode_response};
use doradus_core::dns_resolver::SystemAsyncIpResolver;
use doradus_runtime::{RuntimeBuilder, RuntimeController};
use doradus_store::ConfigStore;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tower::ServiceExt;

async fn read_s3_test_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await.unwrap();
        assert!(length > 0);
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await.unwrap();
        assert!(length > 0);
        bytes.extend_from_slice(&chunk[..length]);
    }
    bytes
}

async fn state() -> ApiState {
    let store = ConfigStore::open_memory().await.unwrap();
    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(SystemAsyncIpResolver),
    ))
    .await
    .unwrap();
    ApiState::new(controller)
}

#[path = "api_tests/backup.rs"]
mod backup;
#[path = "api_tests/contracts.rs"]
mod contracts;
#[path = "api_tests/foundations.rs"]
mod foundations;
#[path = "api_tests/management.rs"]
mod management;
#[path = "api_tests/nodes_inbounds.rs"]
mod nodes_inbounds;
#[path = "api_tests/routes.rs"]
mod routes;
#[path = "api_tests/web.rs"]
mod web;
