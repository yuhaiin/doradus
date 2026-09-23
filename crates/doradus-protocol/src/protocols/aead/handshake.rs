//! P-256/Ed25519 handshake and key derivation for the Go AEAD transport.

use super::stream::{AeadStream, DirectionCipher};
use super::*;

fn io_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

pub(super) async fn handshake_client(
    mut stream: BoxAsyncStream,
    password: &[u8],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    let signing_key = signing_key(&password_salt(password))?;
    let (secret, public_key) = generate_keypair();
    let mut client_header = [0u8; HEADER_SIZE];
    fill_random(&mut client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE]);
    let (client_time, encrypted_client_time) = timestamp_pair(
        password,
        &client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE],
    )?;
    client_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE]
        .copy_from_slice(&encrypted_client_time);
    client_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..].copy_from_slice(public_key.as_slice());
    sign_header(&mut client_header, &signing_key);
    stream.write_all(&client_header).await.map_err(io_error)?;

    let client_salt = client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].to_vec();
    let mut server_header = [0u8; HEADER_SIZE];
    stream
        .read_exact(&mut server_header)
        .await
        .map_err(io_error)?;
    server_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].copy_from_slice(&client_salt);
    verify_header(&server_header, &signing_key)?;
    let server_public =
        PublicKey::from_sec1_bytes(&server_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..])
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD server public key"))?;
    if server_public.to_encoded_point(false).as_bytes() == public_key.as_slice() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "AEAD handshake replayed the public key",
        ));
    }
    let server_time = decrypt_timestamp(
        password,
        &client_salt,
        &server_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE],
    )?;
    validate_timestamp(&server_time)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), server_public.as_affine());
    let read = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &client_time,
    )?;
    let write = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &server_time,
    )?;
    Ok(Box::new(AeadStream::new(stream, read, write)) as BoxAsyncStream)
}

pub(super) async fn handshake_server(
    mut stream: BoxAsyncStream,
    passwords: &[Vec<u8>],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    let mut client_header = [0u8; HEADER_SIZE];
    stream
        .read_exact(&mut client_header)
        .await
        .map_err(io_error)?;
    let client_salt = client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].to_vec();
    let encrypted_client_time =
        &client_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE];
    let Some((password, client_time, signing_key)) = passwords.iter().find_map(|password| {
        let signing_key = signing_key(&password_salt(password)).ok()?;
        verify_header(&client_header, &signing_key).ok()?;
        let client_time = decrypt_timestamp(password, &client_salt, encrypted_client_time).ok()?;
        validate_timestamp(&client_time).ok()?;
        Some((password.as_slice(), client_time, signing_key))
    }) else {
        return Err(Error::new(
            ErrorKind::Protocol,
            "AEAD handshake credentials are invalid",
        ));
    };
    let client_public =
        PublicKey::from_sec1_bytes(&client_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..])
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD client public key"))?;

    let (secret, public_key) = generate_keypair();
    let (server_time, encrypted_server_time) = timestamp_pair(password, &client_salt)?;
    let mut server_header = [0u8; HEADER_SIZE];
    server_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].copy_from_slice(&client_salt);
    server_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE]
        .copy_from_slice(&encrypted_server_time);
    server_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..].copy_from_slice(public_key.as_slice());
    sign_header(&mut server_header, &signing_key);
    // Go randomizes this field after signing.  The client replaces it with
    // the original client salt before signature verification.
    fill_random(&mut server_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE]);
    stream.write_all(&server_header).await.map_err(io_error)?;

    let shared = diffie_hellman(secret.to_nonzero_scalar(), client_public.as_affine());
    // Go's server NewConn swaps its read/write arguments: it reads with the
    // cipher derived from the server timestamp and writes with the client one.
    let read = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &server_time,
    )?;
    let write = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &client_time,
    )?;
    Ok(Box::new(AeadStream::new(stream, read, write)) as BoxAsyncStream)
}

fn generate_keypair() -> (SecretKey, Vec<u8>) {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    (secret, public)
}

fn signing_key(password_hash: &[u8; HASH_SIZE]) -> Result<SigningKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; HASH_SIZE]), password_hash);
    let mut seed = [0u8; 32];
    hkdf.expand(b"ed25519-signature", &mut seed)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD Ed25519 key derivation failed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign_header(header: &mut [u8; HEADER_SIZE], key: &SigningKey) {
    let signature = key.sign(&header[SIGNATURE_SIZE..]);
    header[..SIGNATURE_SIZE].copy_from_slice(&signature.to_bytes());
}

fn verify_header(header: &[u8; HEADER_SIZE], key: &SigningKey) -> Result<()> {
    let verifying: VerifyingKey = key.verifying_key();
    let signature = Signature::from_bytes(header[..SIGNATURE_SIZE].try_into().unwrap());
    verifying
        .verify(&header[SIGNATURE_SIZE..], &signature)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD handshake signature mismatch"))
}

fn timestamp_pair(password: &[u8], salt: &[u8]) -> Result<([u8; TIME_SIZE], [u8; TIME_SIZE])> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Protocol, "system clock is before Unix epoch"))?
        .as_secs();
    let plain = now.to_be_bytes();
    let mut encrypted = plain;
    crypt_timestamp(password, salt, &mut encrypted)?;
    Ok((plain, encrypted))
}

fn decrypt_timestamp(password: &[u8], salt: &[u8], encrypted: &[u8]) -> Result<[u8; TIME_SIZE]> {
    if encrypted.len() != TIME_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid AEAD timestamp length",
        ));
    }
    let mut plain = [0u8; TIME_SIZE];
    plain.copy_from_slice(encrypted);
    crypt_timestamp(password, salt, &mut plain)?;
    Ok(plain)
}

fn crypt_timestamp(password: &[u8], salt: &[u8], data: &mut [u8; TIME_SIZE]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), password);
    let mut key_nonce = [0u8; 44];
    hkdf.expand(b"time", &mut key_nonce)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD timestamp key derivation failed"))?;
    let mut cipher = ChaCha20::new_from_slices(&key_nonce[..32], &key_nonce[32..])
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD timestamp cipher"))?;
    cipher.apply_keystream(data);
    Ok(())
}

fn validate_timestamp(timestamp: &[u8; TIME_SIZE]) -> Result<()> {
    let timestamp = u64::from_be_bytes(*timestamp);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Protocol, "system clock is before Unix epoch"))?
        .as_secs();
    if now.abs_diff(timestamp) > 30 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "AEAD handshake timestamp expired",
        ));
    }
    Ok(())
}

pub(super) fn derive_cipher(
    method: CryptoMethod,
    shared: &[u8],
    salt: &[u8],
    timestamp: &[u8],
) -> Result<DirectionCipher> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut info = Vec::with_capacity(method.name().len() + timestamp.len());
    info.extend_from_slice(method.name());
    info.extend_from_slice(timestamp);
    let mut key_nonce = vec![0u8; 32 + method.nonce_size()];
    hkdf.expand(&info, &mut key_nonce)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD stream key derivation failed"))?;
    Ok(DirectionCipher {
        method,
        key: key_nonce[..32].to_vec(),
        nonce: key_nonce[32..].to_vec(),
    })
}
