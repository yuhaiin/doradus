//! Flow lifetime, NAT state, and process ownership cache for the TUN proxy runtime.

use super::*;
use doradus_core::process::ProcessInfo;

pub(super) struct NatBinding {
    pub(super) table: NatTable,
    pub(super) idle_timeout: Duration,
}

#[derive(Default)]
pub(super) struct FlowTracker {
    nat: Option<NatBinding>,
    flows: HashSet<TunFlowKey>,
    process_cache: HashMap<UdpSourceKey, Option<ProcessInfo>>,
    process_cache_refs: HashMap<UdpSourceKey, usize>,
}

impl FlowTracker {
    pub(super) fn with_nat(&mut self, table: NatTable, idle_timeout: Duration) {
        self.nat = Some(NatBinding {
            table,
            idle_timeout,
        });
    }

    pub(super) fn nat(&self) -> Option<&NatBinding> {
        self.nat.as_ref()
    }

    pub(super) fn contains(&self, flow: &TunFlowKey) -> bool {
        self.flows.contains(flow)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &TunFlowKey> {
        self.flows.iter()
    }

    pub(super) fn cached_process(&self, source: &UdpSourceKey) -> Option<&Option<ProcessInfo>> {
        self.process_cache.get(source)
    }

    pub(super) fn cache_process(&mut self, source: UdpSourceKey, process: Option<ProcessInfo>) {
        self.process_cache.insert(source, process);
    }

    pub(super) fn clear_process_cache(&mut self) {
        self.process_cache.clear();
    }

    pub(super) fn track(&mut self, flow: TunFlowKey) -> Result<bool> {
        if let Some(nat) = &self.nat {
            let key = nat_key(flow);
            if nat.table.touch(&key)?.is_none() {
                nat.table.insert(key, flow.source, nat.idle_timeout)?;
            }
        }
        let inserted = self.flows.insert(flow);
        if inserted {
            let source = udp_source_key(flow);
            *self.process_cache_refs.entry(source).or_default() += 1;
        }
        Ok(inserted)
    }

    pub(super) fn touch(&self, flow: TunFlowKey) -> Result<()> {
        let Some(nat) = &self.nat else {
            return Ok(());
        };
        let _ = nat.table.touch(&nat_key(flow))?;
        Ok(())
    }

    pub(super) fn untrack(&mut self, flow: &TunFlowKey) -> Result<bool> {
        if !self.flows.remove(flow) {
            return Ok(false);
        }
        self.release_process_cache(*flow);
        if let Some(nat) = &self.nat {
            let _ = nat.table.remove(&nat_key(*flow))?;
        }
        Ok(true)
    }

    pub(super) fn drain(&mut self) -> Vec<TunFlowKey> {
        let flows = self.flows.drain().collect::<Vec<_>>();
        for flow in &flows {
            self.release_process_cache(*flow);
            if let Some(nat) = &self.nat {
                let _ = nat.table.remove(&nat_key(*flow));
            }
        }
        flows
    }

    fn release_process_cache(&mut self, flow: TunFlowKey) {
        let source = udp_source_key(flow);
        let Some(references) = self.process_cache_refs.get_mut(&source) else {
            return;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            self.process_cache_refs.remove(&source);
            self.process_cache.remove(&source);
        }
    }
}
