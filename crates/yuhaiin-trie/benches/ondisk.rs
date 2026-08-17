use std::hint::black_box;
use std::time::Instant;

use yuhaiin_core::{DomainName, Endpoint, Network};
use yuhaiin_trie::HostTrie;

const DOMAIN_COUNT: usize = 100_000;
const QUERY_COUNT: usize = 1_000_000;

fn endpoint(domain: String) -> Endpoint {
    Endpoint::domain(Network::Tcp, DomainName::new(&domain).unwrap(), 443)
}

fn main() {
    let hwm_before = proc_status_kib("VmHWM");
    let build_start = Instant::now();
    let trie = HostTrie::from_patterns((0..DOMAIN_COUNT).map(benchmark_domain)).unwrap();
    let build_millis = build_start.elapsed().as_secs_f64() * 1_000.0;
    let hwm_after = proc_status_kib("VmHWM");

    let hits = (0..1024)
        .map(|index| endpoint(benchmark_domain(index)))
        .collect::<Vec<_>>();
    let misses = (0..1024)
        .map(|index| endpoint(format!("missing-{index}.example.net")))
        .collect::<Vec<_>>();

    let hit_start = Instant::now();
    let mut hit_count = 0;
    for query in 0..QUERY_COUNT {
        hit_count += usize::from(black_box(trie.search(&hits[query % hits.len()])).is_some());
    }
    let hit_nanos = hit_start.elapsed().as_secs_f64() * 1_000_000_000.0 / QUERY_COUNT as f64;

    let miss_start = Instant::now();
    let mut miss_count = 0;
    for query in 0..QUERY_COUNT {
        miss_count += usize::from(black_box(trie.search(&misses[query % misses.len()])).is_some());
    }
    let miss_nanos = miss_start.elapsed().as_secs_f64() * 1_000_000_000.0 / QUERY_COUNT as f64;

    println!("rust_ondisk_build_ms={build_millis:.3}");
    println!(
        "rust_ondisk_build_vm_hwm_delta_kib={}",
        hwm_after.saturating_sub(hwm_before)
    );
    println!("rust_ondisk_search_hit_ns={hit_nanos:.3} matches={hit_count}");
    println!("rust_ondisk_search_miss_ns={miss_nanos:.3} matches={miss_count}");
}

fn benchmark_domain(index: usize) -> String {
    format!(
        "com.sub1-{}.sub2-{}.sub3-{}",
        index % 1000,
        (index / 1000) % 1000,
        index / 1_000_000
    )
}

fn proc_status_kib(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == field)
                .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
        })
        .unwrap_or_default()
}
