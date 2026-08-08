//! Allocation-conscious routing indexes for domain names and IP prefixes.

use std::collections::BTreeMap;
use std::net::IpAddr;

use yuhaiin_core::{DomainName, Endpoint, Error, Result};

pub mod router;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DomainNode<T> {
    value: Option<T>,
    children: BTreeMap<String, DomainNode<T>>,
}
impl<T> Default for DomainNode<T> {
    fn default() -> Self {
        Self {
            value: None,
            children: BTreeMap::new(),
        }
    }
}

/// A reversed-label domain trie.
///
/// `*.example.com` is stored as a literal wildcard label and matches exactly
/// one label. A normal parent rule continues to match subdomains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainTrie<T> {
    root: DomainNode<T>,
}

impl<T> Default for DomainTrie<T> {
    fn default() -> Self {
        Self {
            root: DomainNode::default(),
        }
    }
}

impl<T> DomainTrie<T> {
    pub fn new() -> Self {
        Self {
            root: DomainNode::default(),
        }
    }

    pub fn insert(&mut self, domain: &str, value: T) -> Result<Option<T>> {
        let labels = pattern_labels(domain)?;
        let mut node = &mut self.root;
        for label in labels.iter().rev() {
            node = node.children.entry(label.clone()).or_default();
        }
        Ok(node.value.replace(value))
    }

    pub fn remove(&mut self, domain: &str) -> Result<Option<T>> {
        let labels = pattern_labels(domain)?;
        remove_domain(&mut self.root, &mut labels.iter().rev().map(String::as_str))
    }

    pub fn search(&self, domain: &str) -> Result<Option<&T>> {
        let domain = DomainName::try_from(domain)?;
        let labels: Vec<&str> = domain.labels().rev().collect();
        Ok(search_domain(&self.root, &labels, 0, None))
    }
}

fn pattern_labels(pattern: &str) -> Result<Vec<String>> {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() {
        return Err(Error::invalid("domain must contain at least one label"));
    }
    let mut labels = Vec::new();
    for label in pattern.split('.') {
        if label == "*" {
            labels.push(label.to_owned());
        } else {
            DomainName::new(label)?;
            labels.push(label.to_owned());
        }
    }
    if pattern.len() > 253 {
        return Err(Error::invalid("domain must contain at most 253 bytes"));
    }
    Ok(labels)
}

fn remove_domain<'a, I, T>(node: &mut DomainNode<T>, labels: &mut I) -> Result<Option<T>>
where
    T: 'a,
    I: Iterator<Item = &'a str>,
{
    let Some(label) = labels.next() else {
        return Ok(node.value.take());
    };
    let Some(child) = node.children.get_mut(label) else {
        return Ok(None);
    };
    let result = remove_domain(child, labels)?;
    if child.value.is_none() && child.children.is_empty() {
        node.children.remove(label);
    }
    Ok(result)
}

fn search_domain<'a, T>(
    node: &'a DomainNode<T>,
    labels: &[&str],
    depth: usize,
    best: Option<&'a T>,
) -> Option<&'a T> {
    let best = node.value.as_ref().or(best);
    if depth == labels.len() {
        return best;
    }

    let exact = node.children.get(labels[depth]);
    let wildcard = node.children.get("*");
    let exact_result = exact.and_then(|child| search_domain(child, labels, depth + 1, best));
    let wildcard_result = (depth + 1 == labels.len())
        .then(|| wildcard)
        .flatten()
        .and_then(|child| search_domain(child, labels, depth + 1, best));
    exact_result.or(wildcard_result).or(best)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CidrNode<T> {
    value: Option<T>,
    zero: Option<Box<CidrNode<T>>>,
    one: Option<Box<CidrNode<T>>>,
}

impl<T> Default for CidrNode<T> {
    fn default() -> Self {
        Self {
            value: None,
            zero: None,
            one: None,
        }
    }
}

/// Longest-prefix-match trie supporting IPv4 and IPv6 independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrTrie<T> {
    v4: CidrNode<T>,
    v6: CidrNode<T>,
}

impl<T> Default for CidrTrie<T> {
    fn default() -> Self {
        Self {
            v4: CidrNode::default(),
            v6: CidrNode::default(),
        }
    }
}

impl<T> CidrTrie<T> {
    pub fn new() -> Self {
        Self {
            v4: CidrNode::default(),
            v6: CidrNode::default(),
        }
    }

    pub fn insert(&mut self, network: IpAddr, prefix_len: u8, value: T) -> Result<Option<T>> {
        let (root, max_bits) = match network {
            IpAddr::V4(_) => (&mut self.v4, 32),
            IpAddr::V6(_) => (&mut self.v6, 128),
        };
        if prefix_len > max_bits {
            return Err(Error::invalid("CIDR prefix length exceeds address width"));
        }
        let mut node = root;
        for bit in address_bits(network).take(prefix_len as usize) {
            node = if bit {
                node.one.get_or_insert_with(Default::default)
            } else {
                node.zero.get_or_insert_with(Default::default)
            };
        }
        Ok(node.value.replace(value))
    }

    pub fn remove(&mut self, network: IpAddr, prefix_len: u8) -> Result<Option<T>> {
        let (root, max_bits) = match network {
            IpAddr::V4(_) => (&mut self.v4, 32),
            IpAddr::V6(_) => (&mut self.v6, 128),
        };
        if prefix_len > max_bits {
            return Err(Error::invalid("CIDR prefix length exceeds address width"));
        }
        remove_cidr(root, &mut address_bits(network).take(prefix_len as usize))
    }

    pub fn search(&self, address: IpAddr) -> Option<&T> {
        let root = match address {
            IpAddr::V4(_) => &self.v4,
            IpAddr::V6(_) => &self.v6,
        };
        let mut node = root;
        let mut best = node.value.as_ref();
        for bit in address_bits(address) {
            let next = if bit {
                node.one.as_deref()
            } else {
                node.zero.as_deref()
            };
            let Some(next) = next else { break };
            node = next;
            if node.value.is_some() {
                best = node.value.as_ref();
            }
        }
        best
    }
}

fn remove_cidr<T, I>(node: &mut CidrNode<T>, bits: &mut I) -> Result<Option<T>>
where
    I: Iterator<Item = bool>,
{
    let Some(bit) = bits.next() else {
        return Ok(node.value.take());
    };
    let child = if bit { &mut node.one } else { &mut node.zero };
    let Some(child_node) = child.as_mut() else {
        return Ok(None);
    };
    let result = remove_cidr(child_node, bits)?;
    if child_node.value.is_none() && child_node.zero.is_none() && child_node.one.is_none() {
        *child = None;
    }
    Ok(result)
}

fn address_bits(address: IpAddr) -> impl Iterator<Item = bool> {
    let (bytes, width) = match address {
        IpAddr::V4(value) => (value.octets().to_vec(), 32),
        IpAddr::V6(value) => (value.octets().to_vec(), 128),
    };
    (0..width).map(move |index| {
        let byte = bytes[index / 8];
        byte & (1 << (7 - index % 8)) != 0
    })
}

/// Combined lookup used by the router's rule compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedTrie<T> {
    pub domains: DomainTrie<T>,
    pub cidrs: CidrTrie<T>,
}

impl<T> Default for CombinedTrie<T> {
    fn default() -> Self {
        Self {
            domains: DomainTrie::default(),
            cidrs: CidrTrie::default(),
        }
    }
}

impl<T> CombinedTrie<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, pattern: &str, value: T) -> Result<Option<T>> {
        if let Some((address, prefix)) = pattern.split_once('/') {
            let address = address
                .parse::<IpAddr>()
                .map_err(|_| Error::invalid("invalid CIDR address"))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| Error::invalid("invalid CIDR prefix length"))?;
            self.cidrs.insert(address, prefix, value)
        } else {
            self.domains.insert(pattern, value)
        }
    }

    pub fn search(&self, endpoint: &Endpoint) -> Option<&T> {
        match endpoint {
            Endpoint::Ip { addr, .. } => self.cidrs.search(addr.ip()),
            Endpoint::Domain { host, .. } => self.domains.search(host.as_str()).ok().flatten(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use yuhaiin_core::{DomainName, Network};

    #[test]
    fn domain_lookup_supports_parent_and_one_label_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", "parent").unwrap();
        trie.insert("*.api.example.com", "wildcard").unwrap();
        assert_eq!(trie.search("example.com").unwrap(), Some(&"parent"));
        assert_eq!(trie.search("www.example.com").unwrap(), Some(&"parent"));
        assert_eq!(
            trie.search("edge.api.example.com").unwrap(),
            Some(&"wildcard")
        );
        assert_eq!(
            trie.search("a.edge.api.example.com").unwrap(),
            Some(&"parent")
        );
        assert_eq!(trie.search("other.net").unwrap(), None);
    }

    #[test]
    fn domain_remove_prunes_only_empty_branches() {
        let mut trie = DomainTrie::new();
        trie.insert("a.example.com", 1).unwrap();
        trie.insert("b.example.com", 2).unwrap();
        assert_eq!(trie.remove("a.example.com").unwrap(), Some(1));
        assert_eq!(trie.search("b.example.com").unwrap(), Some(&2));
        assert_eq!(trie.search("a.example.com").unwrap(), None);
    }

    #[test]
    fn randomized_domain_lookup_matches_parent_and_wildcard_model() {
        let mut trie = DomainTrie::new();
        let mut model = BTreeMap::new();
        let mut state = 0xbb67_ae85_u32;

        for value in 0..192usize {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let base = format!("r{}.example.com", state % 16);
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let pattern = match state % 3 {
                0 => base,
                1 => format!("*.{base}"),
                _ => format!("x.{base}"),
            };
            trie.insert(&pattern, value).unwrap();
            model.insert(pattern, value);
        }

        for _ in 0..2048 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let base = format!("r{}.example.com", state % 16);
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let query = match state % 5 {
                0 => base.clone(),
                1 => format!("edge.{base}"),
                2 => format!("x.{base}"),
                3 => format!("deep.edge.{base}"),
                _ => format!("other{}.invalid", state % 32),
            };
            let expected = model
                .iter()
                .filter(|(pattern, _)| {
                    if let Some(base) = pattern.strip_prefix("*.") {
                        query.strip_suffix(base).is_some_and(|prefix| {
                            prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
                        })
                    } else {
                        query == **pattern
                            || query
                                .strip_suffix(pattern.as_str())
                                .is_some_and(|prefix| prefix.ends_with('.'))
                    }
                })
                .max_by_key(|(pattern, _)| {
                    let base = pattern.strip_prefix("*.").unwrap_or(pattern);
                    (
                        base.split('.').count(),
                        usize::from(pattern.starts_with("*.")),
                    )
                })
                .map(|(_, value)| *value);
            assert_eq!(trie.search(&query).unwrap().copied(), expected);
        }
    }

    #[test]
    fn cidr_lookup_is_longest_prefix_match() {
        let mut trie = CidrTrie::new();
        trie.insert("0.0.0.0".parse().unwrap(), 0, "default")
            .unwrap();
        trie.insert("10.0.0.0".parse().unwrap(), 8, "private")
            .unwrap();
        trie.insert("10.1.0.0".parse().unwrap(), 16, "more-specific")
            .unwrap();
        assert_eq!(
            trie.search("10.1.2.3".parse().unwrap()),
            Some(&"more-specific")
        );
        assert_eq!(trie.search("10.9.2.3".parse().unwrap()), Some(&"private"));
        assert_eq!(trie.search("8.8.8.8".parse().unwrap()), Some(&"default"));
    }

    #[test]
    fn cidr_lookup_supports_ipv6_and_remove() {
        let mut trie = CidrTrie::new();
        let network: IpAddr = "2001:db8::".parse().unwrap();
        trie.insert(network, 32, "doc").unwrap();
        assert_eq!(trie.search("2001:db8:1::1".parse().unwrap()), Some(&"doc"));
        assert_eq!(trie.remove(network, 32).unwrap(), Some("doc"));
        assert_eq!(trie.search("2001:db8:1::1".parse().unwrap()), None);
    }

    #[test]
    fn randomized_ipv4_lpm_matches_a_naive_prefix_model() {
        let mut trie = CidrTrie::new();
        let mut model = BTreeMap::new();
        let mut state = 0x6a09_e667_u32;

        for value in 0..256usize {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let network = state;
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let prefix = (state % 33) as u8;
            trie.insert(IpAddr::V4(Ipv4Addr::from(network)), prefix, value)
                .unwrap();
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            model.insert((network & mask, prefix), value);
        }

        for _ in 0..2048 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let address = state;
            let expected = model
                .iter()
                .filter(|((network, prefix), _)| {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - u32::from(*prefix))
                    };
                    (address & mask) == (*network & mask)
                })
                .max_by_key(|((_, prefix), _)| *prefix)
                .map(|(_, value)| value);
            assert_eq!(trie.search(IpAddr::V4(Ipv4Addr::from(address))), expected);
        }
    }

    #[test]
    fn randomized_ipv6_lpm_matches_a_naive_prefix_model() {
        let mut trie = CidrTrie::new();
        let mut model = BTreeMap::new();
        let mut state = 0x3c6e_f372_u32;
        let mut next_u32 = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        for value in 0..256usize {
            let network = (u128::from(next_u32()) << 96)
                | (u128::from(next_u32()) << 64)
                | (u128::from(next_u32()) << 32)
                | u128::from(next_u32());
            let prefix = (next_u32() % 129) as u8;
            trie.insert(IpAddr::V6(network.into()), prefix, value)
                .unwrap();
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            model.insert((network & mask, prefix), value);
        }

        for _ in 0..2048 {
            let address = (u128::from(next_u32()) << 96)
                | (u128::from(next_u32()) << 64)
                | (u128::from(next_u32()) << 32)
                | u128::from(next_u32());
            let expected = model
                .iter()
                .filter(|((network, prefix), _)| {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - u32::from(*prefix))
                    };
                    (address & mask) == (*network & mask)
                })
                .max_by_key(|((_, prefix), _)| *prefix)
                .map(|(_, value)| value);
            assert_eq!(trie.search(IpAddr::V6(address.into())), expected);
        }
    }

    #[test]
    fn combined_lookup_uses_endpoint_kind() {
        let mut trie = CombinedTrie::new();
        trie.insert("example.com", "domain").unwrap();
        trie.insert("192.0.2.0/24", "cidr").unwrap();
        let domain = Endpoint::domain(
            Network::Tcp,
            DomainName::new("www.example.com").unwrap(),
            443,
        );
        let ip = Endpoint::ip(Network::Tcp, SocketAddr::from(([192, 0, 2, 1], 443)));
        assert_eq!(trie.search(&domain), Some(&"domain"));
        assert_eq!(trie.search(&ip), Some(&"cidr"));
    }
}
