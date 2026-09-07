use std::fmt;

use serde::Deserialize;

/// Configuration for one OpenVPN outbound.
///
/// `profile` is standard inline `.ovpn` content. Username/password are only
/// required when the profile is not autologin-capable.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnConfig {
    #[serde(alias = "config", alias = "content", alias = "ovpn")]
    pub profile: String,
    #[serde(default, alias = "user")]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl fmt::Debug for OpenVpnConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenVpnConfig")
            .field("profile", &"***")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_profile_and_password() {
        let config = OpenVpnConfig {
            profile: "<key>private</key>".to_owned(),
            username: Some("alice".to_owned()),
            password: Some("secret".to_owned()),
        };

        let output = format!("{config:?}");
        assert!(output.contains("alice"));
        assert!(!output.contains("private"));
        assert!(!output.contains("secret"));
    }
}
