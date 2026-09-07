use super::*;

pub(super) async fn http_connect_with_auth(
    address: SocketAddr,
    authority: &str,
    token: Option<&str>,
) -> std::io::Result<(TcpStream, String)> {
    let mut stream = connect_loopback(address).await;
    let authorization = token
        .map(|token| format!("Proxy-Authorization: Basic {token}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n")
                .as_bytes(),
        )
        .await?;
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = match stream.read(&mut buffer).await {
            Ok(length) => length,
            Err(_) => break,
        };
        if length == 0 {
            break;
        }
        headers.extend_from_slice(&buffer[..length]);
    }
    Ok((stream, String::from_utf8_lossy(&headers).into_owned()))
}

pub(super) async fn socks5_auth_probe(
    address: SocketAddr,
    username: &str,
    password: &str,
) -> std::io::Result<[u8; 2]> {
    let mut stream = connect_loopback(address).await;
    stream.write_all(&[5, 1, 2]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 2] {
        return Ok(method);
    }
    let username = username.as_bytes();
    let password = password.as_bytes();
    let mut request = vec![1, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    let _ = stream.shutdown().await;
    Ok(reply)
}

pub(super) async fn connect_socks5_with_auth(
    address: SocketAddr,
    username: &str,
    password: &str,
    host: &str,
    port: u16,
) -> TcpStream {
    let mut stream = connect_loopback(address).await;
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let username = username.as_bytes();
    let password = password.as_bytes();
    let mut auth = vec![1, username.len() as u8];
    auth.extend_from_slice(username);
    auth.push(password.len() as u8);
    auth.extend_from_slice(password);
    stream.write_all(&auth).await.unwrap();
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [1, 0]);
    let host = host.as_bytes();
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    read_socks5_reply(&mut stream).await;
    stream
}

pub(super) async fn read_socks5_reply(stream: &mut TcpStream) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[..3], [5, 0, 0]);
    let address_length = match header[3] {
        1 => 4,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.unwrap();
            usize::from(length[0])
        }
        4 => 16,
        atyp => panic!("unexpected SOCKS5 reply address type {atyp}"),
    };
    let mut address_and_port = vec![0u8; address_length + 2];
    stream.read_exact(&mut address_and_port).await.unwrap();
}
