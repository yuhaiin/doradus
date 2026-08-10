//! Central inbound authentication for Go schema-v6 users.
//!
//! Authentication is an immutable snapshot. Listener restart/reload creates
//! a new snapshot, while accepted connections only perform bounded in-memory
//! comparisons and never touch SQLite.

use std::sync::Arc;

use yuhaiin_store::{GoBasicCredential, GoUserRecord};

#[derive(Debug, Clone)]
pub(crate) struct InboundAuth {
    users: Arc<[InboundBasicUser]>,
}

#[derive(Debug, Clone)]
struct InboundBasicUser {
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
    allow_any_username: bool,
    allow_any_password: bool,
}

impl InboundAuth {
    pub(crate) fn from_users(mut users: Vec<GoUserRecord>) -> Self {
        users.sort_by(|left, right| left.id.cmp(&right.id));
        let users = users
            .into_iter()
            .filter(|user| user.enabled && matches!(user.usage.as_str(), "inbound" | "both"))
            .filter_map(|user| {
                let basic = user.credential.basic.as_ref()?;
                Some(InboundBasicUser::from(basic))
            })
            .collect::<Vec<_>>()
            .into();
        Self { users }
    }

    pub(crate) fn has_basic_users(&self) -> bool {
        self.users.iter().any(InboundBasicUser::is_active)
    }

    /// Password-hash protocols such as Yuubinsya and Trojan cannot represent
    /// an arbitrary password. They must fail closed when an active inbound
    /// user uses `allowAnyPassword`, rather than silently falling back to an
    /// empty or zero hash.
    pub(crate) fn has_unrepresentable_password(&self) -> bool {
        self.users
            .iter()
            .filter(|user| user.is_active())
            .any(|user| user.allow_any_password)
    }

    pub(crate) fn authenticate_basic(&self, username: &[u8], password: &[u8]) -> bool {
        self.users.iter().any(|user| {
            matches_field(username, user.username.as_deref(), user.allow_any_username)
                && matches_field(password, user.password.as_deref(), user.allow_any_password)
        })
    }

    /// Return concrete passwords usable by password-hash based protocols.
    /// Wildcard passwords are omitted because those protocols need a concrete
    /// key and cannot represent an arbitrary password safely.
    pub(crate) fn inbound_passwords(&self) -> Vec<Vec<u8>> {
        self.users
            .iter()
            .filter(|user| user.password.is_some())
            .filter_map(|user| user.password.clone())
            .collect()
    }
}

impl InboundBasicUser {
    fn is_active(&self) -> bool {
        (self.username.is_some() || self.allow_any_username)
            && (self.password.is_some() || self.allow_any_password)
    }
}

impl From<&GoBasicCredential> for InboundBasicUser {
    fn from(credential: &GoBasicCredential) -> Self {
        Self {
            username: credential
                .username
                .as_deref()
                .map(str::as_bytes)
                .map(Vec::from),
            password: credential
                .password
                .as_deref()
                .map(str::as_bytes)
                .map(Vec::from),
            allow_any_username: credential.allow_any_username,
            allow_any_password: credential.allow_any_password,
        }
    }
}

fn matches_field(actual: &[u8], expected: Option<&[u8]>, allow_any: bool) -> bool {
    allow_any || expected.is_some_and(|expected| constant_time_eq(actual, expected))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or_default())
            ^ usize::from(right.get(index).copied().unwrap_or_default());
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_store::GoCredential;

    fn user(
        id: &str,
        enabled: bool,
        usage: &str,
        username: Option<&str>,
        password: Option<&str>,
        allow_any_username: bool,
        allow_any_password: bool,
    ) -> GoUserRecord {
        GoUserRecord {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled,
            origin: "manual".to_owned(),
            usage: usage.to_owned(),
            credential: GoCredential {
                kind: "basic".to_owned(),
                basic: Some(GoBasicCredential {
                    username: username.map(str::to_owned),
                    password: password.map(str::to_owned),
                    allow_any_username,
                    allow_any_password,
                }),
                uuid: None,
                token: None,
            },
            updated_at: 0,
        }
    }

    #[test]
    fn only_enabled_inbound_basic_users_are_authenticators() {
        let auth = InboundAuth::from_users(vec![
            user(
                "outbound",
                true,
                "outbound",
                Some("u"),
                Some("p"),
                false,
                false,
            ),
            user(
                "disabled",
                false,
                "inbound",
                Some("u"),
                Some("p"),
                false,
                false,
            ),
            user("valid", true, "both", Some("u"), Some("p"), false, false),
        ]);
        assert!(auth.has_basic_users());
        assert!(auth.authenticate_basic(b"u", b"p"));
        assert!(!auth.authenticate_basic(b"u", b"wrong"));
        assert_eq!(auth.inbound_passwords(), vec![b"p".to_vec()]);
    }

    #[test]
    fn wildcard_fields_follow_central_auth_contract() {
        let auth = InboundAuth::from_users(vec![user(
            "wildcard",
            true,
            "inbound",
            None,
            Some("p"),
            true,
            false,
        )]);
        assert!(auth.has_basic_users());
        assert!(auth.authenticate_basic(b"any-user", b"p"));
        assert!(!auth.authenticate_basic(b"any-user", b"wrong"));
        assert_eq!(auth.inbound_passwords(), vec![b"p".to_vec()]);
    }

    #[test]
    fn wildcard_password_is_not_used_as_a_hash_key() {
        let auth = InboundAuth::from_users(vec![user(
            "wildcard-password",
            true,
            "inbound",
            Some("u"),
            None,
            false,
            true,
        )]);
        assert!(auth.has_basic_users());
        assert!(auth.authenticate_basic(b"u", b"anything"));
        assert!(auth.inbound_passwords().is_empty());
        assert!(auth.has_unrepresentable_password());
    }

    #[test]
    fn concrete_passwords_are_representable_by_hash_protocols() {
        let auth = InboundAuth::from_users(vec![user(
            "concrete",
            true,
            "inbound",
            Some("u"),
            Some("p"),
            false,
            false,
        )]);
        assert!(!auth.has_unrepresentable_password());
    }

    #[test]
    fn constant_time_compare_keeps_length_in_result() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"same-plus"));
        assert!(!constant_time_eq(b"same", b"different"));
    }
}
