//! Go user repository tests.

use super::*;

fn basic_password(password: &str) -> GoCredential {
    GoCredential {
        kind: "basic".to_owned(),
        basic: Some(GoBasicCredential {
            username: None,
            password: Some(password.to_owned()),
            allow_any_username: true,
            allow_any_password: false,
        }),
        uuid: None,
        token: None,
    }
}

#[test]
fn credential_validation_and_view_follow_go_contract() {
    let credential = basic_password("secret");
    credential.validate().unwrap();
    let view = credential.view();
    assert_eq!(view.kind, "basic");
    assert_eq!(view.password, "secret");
    assert!(view.has_secret);
    assert!(!view.has_username);

    let invalid = GoCredential {
        kind: "uuid".to_owned(),
        basic: Some(GoBasicCredential {
            username: None,
            password: Some("secret".to_owned()),
            allow_any_username: false,
            allow_any_password: false,
        }),
        uuid: None,
        token: None,
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn generated_user_ids_are_canonical_uuid_values() {
    let id = generate_user_id();
    assert!(is_uuid(&id));
    assert_eq!(id.as_bytes()[14], b'4');
}

#[test]
fn central_credentials_fill_supported_outbound_protocol_shapes() {
    let basic = GoUserRecord {
        id: "basic-user".to_owned(),
        name: String::new(),
        enabled: true,
        origin: "manual".to_owned(),
        usage: "outbound".to_owned(),
        credential: GoCredential {
            kind: "basic".to_owned(),
            basic: Some(GoBasicCredential {
                username: Some("u".to_owned()),
                password: Some("p".to_owned()),
                allow_any_username: false,
                allow_any_password: false,
            }),
            uuid: None,
            token: None,
        },
        updated_at: 0,
    };
    let uuid = GoUserRecord {
        id: "uuid-user".to_owned(),
        credential: GoCredential {
            kind: "uuid".to_owned(),
            basic: None,
            uuid: Some(GoUuidCredential {
                uuid: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            }),
            token: None,
        },
        ..basic.clone()
    };
    let token = GoUserRecord {
        id: "token-user".to_owned(),
        credential: GoCredential {
            kind: "token".to_owned(),
            basic: None,
            uuid: None,
            token: Some(GoTokenCredential {
                token: "token".to_owned(),
            }),
        },
        ..basic.clone()
    };
    let users = HashMap::from([
        (basic.id.clone(), basic),
        (uuid.id.clone(), uuid),
        (token.id.clone(), token),
    ]);

    let mut http = serde_json::json!({
        "chain": [{ "type": "http", "http": {
            "userId": "basic-user", "user": "old", "password": "old"
        }}]
    });
    inject_go_user_credentials(&mut http, None, &users).unwrap();
    assert_eq!(http["chain"][0]["http"]["user"], "u");
    assert_eq!(http["chain"][0]["http"]["password"], "p");

    let mut vmess = serde_json::json!({
        "chain": [{ "type": "vmess", "vmess": {
            "userId": "uuid-user", "id": "old"
        }}]
    });
    inject_go_user_credentials(&mut vmess, None, &users).unwrap();
    assert_eq!(
        vmess["chain"][0]["vmess"]["id"],
        "123e4567-e89b-42d3-a456-426614174000"
    );

    let mut tailscale = serde_json::json!({
        "type": "tailscale", "userId": "token-user", "token": "old"
    });
    inject_go_user_credentials(&mut tailscale, None, &users).unwrap();
    assert_eq!(tailscale["token"], "token");

    let mut yuubinsya = serde_json::json!({
        "type": "yuubinsya", "userId": "basic-user", "password": "old"
    });
    inject_go_user_credentials(&mut yuubinsya, None, &users).unwrap();
    assert_eq!(yuubinsya["password"], "p");

    let mut ssr = serde_json::json!({
        "chain": [{ "type": "shadowsocksr", "shadowsocksr": {
            "userId": "basic-user", "protocol": "auth_aes128_sha1", "password": "old"
        }}]
    });
    inject_go_user_credentials(&mut ssr, None, &users).unwrap();
    assert_eq!(ssr["chain"][0]["shadowsocksr"]["password"], "p");

    let mut missing = serde_json::json!({
        "type": "http", "userId": "missing-user"
    });
    assert_eq!(
        inject_go_user_credentials(&mut missing, None, &users)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );

    let mut disabled = users["basic-user"].clone();
    disabled.enabled = false;
    let disabled_users = HashMap::from([(disabled.id.clone(), disabled)]);
    let mut disabled_payload = serde_json::json!({
        "type": "http", "userId": "basic-user"
    });
    assert_eq!(
        inject_go_user_credentials(&mut disabled_payload, None, &disabled_users)
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
}
