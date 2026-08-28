//! Legacy FakeIP import and export.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpEntry {
    pub domain: DomainName,
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyFakeIpSnapshot {
    pub entries: Vec<LegacyFakeIpEntry>,
    pub next: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpV6Entry {
    pub domain: DomainName,
    pub address: Ipv6Addr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyFakeIpV6Snapshot {
    pub entries: Vec<LegacyFakeIpV6Entry>,
    pub next: Option<Ipv6Addr>,
}

/// Versioned export envelope used by the Go Pebble/bbolt migration helper.
///
/// The Rust runtime intentionally does not open Pebble files. The Go side
/// exports one mapping or cursor per NDJSON line, while this type validates
/// the stable interchange contract before handing the snapshot to the
/// transactional importer below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpExport {
    pub version: u32,
    pub family: u8,
    pub prefix: String,
    pub snapshot: LegacyFakeIpSnapshot,
}

/// IPv6 counterpart to [`LegacyFakeIpExport`].  It uses the same versioned
/// NDJSON wire contract but never shares the IPv4 importer or cursor key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpV6Export {
    pub version: u32,
    pub family: u8,
    pub prefix: String,
    pub snapshot: LegacyFakeIpV6Snapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyFakeIpExportLine {
    version: u32,
    family: u8,
    prefix: String,
    kind: String,
    domain: Option<String>,
    address: Option<String>,
    next: Option<String>,
}

impl LegacyFakeIpExport {
    /// Parse the version-1 NDJSON export contract.
    ///
    /// Every non-empty line repeats the version/family/prefix metadata so a
    /// concatenated or partially replaced export cannot silently mix pools.
    /// Unknown fields, record kinds, duplicate cursors, malformed domains and
    /// malformed addresses fail closed before any SQLite write occurs.
    pub fn parse_ndjson(input: &str) -> Result<Self> {
        let parsed = parse_legacy_fakeip_ndjson(input, 4)?;
        let entries = parsed
            .entries
            .into_iter()
            .map(|(domain, address)| match address {
                IpAddr::V4(address) => LegacyFakeIpEntry { domain, address },
                IpAddr::V6(_) => unreachable!("family-checked legacy export"),
            })
            .collect();
        Ok(Self {
            version: parsed.version,
            family: parsed.family,
            prefix: parsed.prefix,
            snapshot: LegacyFakeIpSnapshot {
                entries,
                next: parsed.next.map(|address| match address {
                    IpAddr::V4(address) => address,
                    IpAddr::V6(_) => unreachable!("family-checked legacy cursor"),
                }),
            },
        })
    }
}

impl LegacyFakeIpV6Export {
    pub fn parse_ndjson(input: &str) -> Result<Self> {
        let parsed = parse_legacy_fakeip_ndjson(input, 6)?;
        let entries = parsed
            .entries
            .into_iter()
            .map(|(domain, address)| match address {
                IpAddr::V6(address) => LegacyFakeIpV6Entry { domain, address },
                IpAddr::V4(_) => unreachable!("family-checked legacy export"),
            })
            .collect();
        Ok(Self {
            version: parsed.version,
            family: parsed.family,
            prefix: parsed.prefix,
            snapshot: LegacyFakeIpV6Snapshot {
                entries,
                next: parsed.next.map(|address| match address {
                    IpAddr::V6(address) => address,
                    IpAddr::V4(_) => unreachable!("family-checked legacy cursor"),
                }),
            },
        })
    }
}

struct ParsedLegacyFakeIpExport {
    version: u32,
    family: u8,
    prefix: String,
    entries: Vec<(DomainName, IpAddr)>,
    next: Option<IpAddr>,
}

fn parse_legacy_fakeip_ndjson(
    input: &str,
    expected_family: u8,
) -> Result<ParsedLegacyFakeIpExport> {
    let mut version = None;
    let mut family = None;
    let mut prefix = None;
    let mut entries = Vec::new();
    let mut next = None;

    for (line_index, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let record: LegacyFakeIpExportLine = serde_json::from_str(line).map_err(|error| {
            Error::invalid(format!(
                "invalid FakeIP legacy NDJSON line {}: {error}",
                line_index + 1
            ))
        })?;
        if record.version != 1 {
            return Err(Error::invalid(format!(
                "unsupported FakeIP legacy export version {}",
                record.version
            )));
        }
        if record.family != expected_family {
            return Err(Error::invalid(format!(
                "version-1 FakeIP legacy NDJSON family {} does not match expected family {}",
                record.family, expected_family
            )));
        }
        validate_legacy_export_prefix(&record.prefix, expected_family)?;

        if let Some(expected) = version {
            if expected != record.version {
                return Err(Error::invalid("FakeIP legacy export mixes versions"));
            }
        } else {
            version = Some(record.version);
        }
        if let Some(expected) = family {
            if expected != record.family {
                return Err(Error::invalid(
                    "FakeIP legacy export mixes address families",
                ));
            }
        } else {
            family = Some(record.family);
        }
        if let Some(expected) = prefix.as_deref() {
            if expected != record.prefix {
                return Err(Error::invalid("FakeIP legacy export mixes pool prefixes"));
            }
        } else {
            prefix = Some(record.prefix.clone());
        }

        match record.kind.as_str() {
            "entry" => {
                let domain = DomainName::new(
                    record
                        .domain
                        .as_deref()
                        .ok_or_else(|| Error::invalid("FakeIP entry record is missing domain"))?,
                )?;
                let address = record
                    .address
                    .ok_or_else(|| Error::invalid("FakeIP entry record is missing address"))?
                    .parse::<IpAddr>()
                    .map_err(|error| Error::invalid(format!("invalid FakeIP address: {error}")))?;
                if address.is_ipv4() != (expected_family == 4) {
                    return Err(Error::invalid(
                        "FakeIP entry address family does not match export",
                    ));
                }
                if record.next.is_some() {
                    return Err(Error::invalid(
                        "FakeIP entry record must not contain a cursor",
                    ));
                }
                entries.push((domain, address));
            }
            "cursor" => {
                if record.domain.is_some() || record.address.is_some() {
                    return Err(Error::invalid(
                        "FakeIP cursor record must not contain an entry",
                    ));
                }
                if next.is_some() {
                    return Err(Error::invalid(
                        "FakeIP legacy export contains duplicate cursors",
                    ));
                }
                let cursor = record
                    .next
                    .ok_or_else(|| Error::invalid("FakeIP cursor record is missing next"))?
                    .parse::<IpAddr>()
                    .map_err(|error| Error::invalid(format!("invalid FakeIP cursor: {error}")))?;
                if cursor.is_ipv4() != (expected_family == 4) {
                    return Err(Error::invalid("FakeIP cursor family does not match export"));
                }
                next = Some(cursor);
            }
            kind => {
                return Err(Error::invalid(format!(
                    "unsupported FakeIP legacy record kind {kind:?}"
                )));
            }
        }
    }

    let Some(version) = version else {
        return Err(Error::invalid("FakeIP legacy NDJSON export is empty"));
    };
    Ok(ParsedLegacyFakeIpExport {
        version,
        family: family.expect("version is set together with family"),
        prefix: prefix.expect("version is set together with prefix"),
        entries,
        next,
    })
}

fn validate_legacy_export_prefix(prefix: &str, expected_family: u8) -> Result<()> {
    let Some((address, bits)) = prefix.rsplit_once('/') else {
        return Err(Error::invalid("FakeIP legacy export prefix is missing '/'"));
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|error| Error::invalid(format!("invalid FakeIP legacy prefix: {error}")))?;
    if address.is_ipv4() != (expected_family == 4) {
        return Err(Error::invalid(
            "FakeIP legacy export prefix family does not match record family",
        ));
    }
    let bits = bits
        .parse::<u8>()
        .map_err(|error| Error::invalid(format!("invalid FakeIP legacy prefix length: {error}")))?;
    let max_bits = if address.is_ipv4() { 32 } else { 128 };
    if bits > max_bits {
        return Err(Error::invalid(
            "FakeIP legacy export prefix length is out of range",
        ));
    }
    Ok(())
}
