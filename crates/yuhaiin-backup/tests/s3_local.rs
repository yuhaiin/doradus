use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use yuhaiin_backup::{S3Client, S3Config};

async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await.unwrap();
        assert!(length > 0, "local S3 server received an incomplete request");
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await.unwrap();
        assert!(length > 0, "local S3 server received a truncated body");
        bytes.extend_from_slice(&chunk[..length]);
    }
    bytes
}

#[tokio::test]
async fn put_and_get_use_s3_sigv4_against_a_local_compatible_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let recorded = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        for response_body in [Vec::new(), b"restored-state".to_vec()] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            recorded.lock().unwrap().push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&response_body).await.unwrap();
        }
    });

    let client = S3Client::new(S3Config {
        enabled: true,
        access_key: "access".to_owned(),
        secret_key: "secret".to_owned(),
        bucket: "bucket".to_owned(),
        region: "us-east-1".to_owned(),
        endpoint_url: endpoint,
        use_path_style: true,
        storage_class: "STANDARD".to_owned(),
    })
    .unwrap();
    client
        .put("instance-state.db", b"state-bytes")
        .await
        .unwrap();
    assert_eq!(
        client.get("instance-state.db").await.unwrap(),
        b"restored-state"
    );
    server.await.unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let put = String::from_utf8_lossy(&requests[0]);
    assert!(put.starts_with("PUT /bucket/instance-state.db HTTP/1.1\r\n"));
    assert!(put.contains("authorization: AWS4-HMAC-SHA256"));
    assert!(put.contains("x-amz-content-sha256:"));
    assert!(put.contains("x-amz-storage-class: STANDARD"));
    assert!(put.ends_with("\r\n\r\nstate-bytes"));
    let get = String::from_utf8_lossy(&requests[1]);
    assert!(get.starts_with("GET /bucket/instance-state.db HTTP/1.1\r\n"));
    assert!(get.contains("authorization: AWS4-HMAC-SHA256"));
}
