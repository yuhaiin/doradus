use super::*;

pub fn default_route_config() -> Value {
    json!({"directResolver":"", "proxyResolver":"", "resolveLocally":false, "udpProxyFqdnStrategy":"default"})
}

pub fn default_settings() -> Value {
    // This is the HTTP contract default from Go's SettingsStore.Load. It is
    // deliberately separate from RuntimeSettings::default: the runtime uses
    // conservative operational defaults, while the Go management contract
    // returns zero values for unset scalar settings (except pprof).
    json!({
        "ipv6": false,
        "useDefaultInterface": false,
        "netInterface": "",
        "pprof": true,
        "systemProxy": {"http": false, "socks5": false},
        "logcat": {
            "level": "verbose",
            "save": false,
            "ignoreTimeoutError": false,
            "ignoreDnsError": false
        },
        "advanced": {
            "udpBufferSize": 0,
            "relayBufferSize": 0,
            "udpRingbufferSize": 0,
            "happyEyeballsSemaphore": 0
        },
        "backup": {
            "instanceName": "",
            "interval": 0,
            "lastBackupHash": ""
        }
    })
}

pub fn canonical_settings_value(value: &Value) -> Value {
    let mut result = default_settings();
    for (path, predicate) in [
        ("/ipv6", Value::is_boolean as fn(&Value) -> bool),
        ("/useDefaultInterface", Value::is_boolean),
        ("/netInterface", Value::is_string),
        ("/pprof", Value::is_boolean),
        ("/systemProxy/http", Value::is_boolean),
        ("/systemProxy/socks5", Value::is_boolean),
        ("/logcat/level", Value::is_string),
        ("/logcat/save", Value::is_boolean),
        ("/logcat/ignoreTimeoutError", Value::is_boolean),
        ("/logcat/ignoreDnsError", Value::is_boolean),
        ("/advanced/udpBufferSize", Value::is_number),
        ("/advanced/relayBufferSize", Value::is_number),
        ("/advanced/udpRingbufferSize", Value::is_number),
        ("/advanced/happyEyeballsSemaphore", Value::is_number),
    ] {
        if let (Some(source), Some(destination)) = (value.pointer(path), result.pointer_mut(path))
            && predicate(source)
        {
            *destination = source.clone();
        }
    }
    result
}

pub fn settings_value_from_go_kv(values: &[GoSettingsKvRecord]) -> Value {
    let mut result = default_settings();
    for record in values {
        let Ok(value) = serde_json::from_str::<Value>(&record.value_json) else {
            continue;
        };
        let path = match (record.section.as_str(), record.key.as_str()) {
            ("general", "ipv6") => "/ipv6",
            ("general", "use_default_interface") => "/useDefaultInterface",
            ("general", "net_interface") => "/netInterface",
            ("general", "pprof") => "/pprof",
            ("system_proxy", "http") => "/systemProxy/http",
            ("system_proxy", "socks5") => "/systemProxy/socks5",
            ("logcat", "save") => "/logcat/save",
            ("logcat", "ignore_dns_error") => "/logcat/ignoreDnsError",
            ("logcat", "ignore_timeout_error") => "/logcat/ignoreTimeoutError",
            ("advanced", "udp_buffer_size") => "/advanced/udpBufferSize",
            ("advanced", "relay_buffer_size") => "/advanced/relayBufferSize",
            ("advanced", "udp_ringbuffer_size") => "/advanced/udpRingbufferSize",
            ("advanced", "happyeyeballs_semaphore") => "/advanced/happyEyeballsSemaphore",
            ("logcat", "level") => {
                if let Some(destination) = result.pointer_mut("/logcat/level") {
                    *destination = Value::String(log_level_from_json(&value));
                }
                continue;
            }
            _ => continue,
        };
        let accepts = if path == "/netInterface" {
            value.is_string()
        } else if path.starts_with("/advanced/") {
            value.is_number()
        } else {
            value.is_boolean()
        };
        if accepts && let Some(destination) = result.pointer_mut(path) {
            *destination = value;
        }
    }
    result
}

pub fn settings_kv_from_contract(value: &Value) -> Vec<GoSettingsKvRecord> {
    let entries = [
        ("general", "ipv6", "/ipv6"),
        ("general", "use_default_interface", "/useDefaultInterface"),
        ("general", "net_interface", "/netInterface"),
        ("general", "pprof", "/pprof"),
        ("system_proxy", "http", "/systemProxy/http"),
        ("system_proxy", "socks5", "/systemProxy/socks5"),
        ("logcat", "save", "/logcat/save"),
        ("logcat", "ignore_dns_error", "/logcat/ignoreDnsError"),
        (
            "logcat",
            "ignore_timeout_error",
            "/logcat/ignoreTimeoutError",
        ),
        ("advanced", "udp_buffer_size", "/advanced/udpBufferSize"),
        ("advanced", "relay_buffer_size", "/advanced/relayBufferSize"),
        (
            "advanced",
            "udp_ringbuffer_size",
            "/advanced/udpRingbufferSize",
        ),
        (
            "advanced",
            "happyeyeballs_semaphore",
            "/advanced/happyEyeballsSemaphore",
        ),
    ];
    let mut result = entries
        .into_iter()
        .filter_map(|(section, key, path)| {
            let value = value.pointer(path)?;
            Some(GoSettingsKvRecord {
                section: section.to_owned(),
                key: key.to_owned(),
                value_json: serde_json::to_string(value).ok()?,
            })
        })
        .collect::<Vec<_>>();
    let level = value
        .pointer("/logcat/level")
        .and_then(Value::as_str)
        .map(log_level_code)
        .unwrap_or(0);
    result.push(GoSettingsKvRecord {
        section: "logcat".to_owned(),
        key: "level".to_owned(),
        value_json: level.to_string(),
    });
    result
}

pub fn log_level_code(level: &str) -> i64 {
    match level {
        "verbose" => 0,
        "debug" => 1,
        "info" => 2,
        "warning" => 3,
        "error" => 4,
        "fatal" => 5,
        _ => 2,
    }
}

pub fn log_level_from_json(value: &Value) -> String {
    let code = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .unwrap_or(0);
    match code {
        0 => "verbose",
        1 => "debug",
        2 => "info",
        3 => "warning",
        4 => "error",
        5 => "fatal",
        _ => "info",
    }
    .to_owned()
}

pub fn default_route_list_config() -> Value {
    json!({"refreshInterval":"0","lastRefreshTime":"0","error":"","hostIndexDisk":false,"maxMindDbGeoIp":{"downloadUrl":"","error":""}})
}

/// Go's route-extra contract expresses refresh intervals in minutes. Zero
/// disables the timer; malformed or overflowing legacy values are treated as
/// disabled until the user saves a valid configuration.
pub fn route_list_refresh_duration(value: &Value) -> Option<Duration> {
    let minutes = match value.get("refreshInterval") {
        Some(Value::String(value)) => value.parse::<u64>().ok(),
        Some(Value::Number(value)) => value.as_u64(),
        _ => None,
    };
    let minutes = minutes.filter(|minutes| *minutes != 0)?;
    Some(Duration::from_secs(minutes.checked_mul(60)?))
}

pub fn default_fakedns() -> Value {
    json!({
        "enabled": false,
        "ipv4Range": "10.2.0.1/24",
        "ipv6Range": "fc00::/64",
        "whitelist": [
            "*.msftncsi.com",
            "*.msftconnecttest.com",
            "ping.archlinux.org",
            "mask.icloud.com",
            "mask-h2.icloud.com",
            "mask.apple-dns.net"
        ],
        "skipCheckList": []
    })
}

pub fn default_tun_config() -> Value {
    json!({"enabled":false,"name":"yuhaiin0","mtu":1500,"queueCapacity":256,"channelCapacity":256,"directId":"","proxyId":"","bypassId":"","dropId":""})
}
