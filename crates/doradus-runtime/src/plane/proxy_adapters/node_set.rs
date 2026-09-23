use super::*;

/// Go route tags resolve to a node set. Keep the set at the common async
/// proxy boundary so TCP, UDP and stateful protocol chains share the same
/// retry behavior. A failed member is tried before the set reports the
/// connection failure to the inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::plane) enum NodeSelectionStrategy {
    Random,
    RoundRobin,
}

pub struct NodeSetProxy {
    members: Vec<Arc<dyn AsyncProxy>>,
    cursor: AtomicUsize,
    strategy: NodeSelectionStrategy,
    random_offset: usize,
}

impl NodeSetProxy {
    pub(in crate::plane) fn new(
        members: Vec<Arc<dyn AsyncProxy>>,
        strategy: NodeSelectionStrategy,
    ) -> Result<Self> {
        if members.is_empty() {
            return Err(Error::invalid("node tag has no usable members"));
        }
        let random_offset = match strategy {
            NodeSelectionStrategy::Random => {
                let mut rng = rand::rng();
                rand::RngExt::random_range(&mut rng, 0..members.len())
            }
            NodeSelectionStrategy::RoundRobin => 0,
        };
        Ok(Self {
            members,
            cursor: AtomicUsize::new(0),
            strategy,
            random_offset,
        })
    }

    fn ordered_members(&self) -> Vec<Arc<dyn AsyncProxy>> {
        let length = self.members.len();
        let ticket = self.cursor.fetch_add(1, Ordering::Relaxed);
        // Random strategy chooses a random initial offset, then cycles through
        // every member. This preserves per-member load spread for any group
        // size while avoiding a per-flow random-number call.
        let start = Self::starting_index(ticket, length, self.strategy, self.random_offset);
        (0..length)
            .map(|offset| Arc::clone(&self.members[(start + offset) % length]))
            .collect()
    }

    fn starting_index(
        ticket: usize,
        length: usize,
        strategy: NodeSelectionStrategy,
        random_offset: usize,
    ) -> usize {
        match strategy {
            NodeSelectionStrategy::RoundRobin => ticket % length,
            NodeSelectionStrategy::Random => (ticket % length + random_offset) % length,
        }
    }
}

impl AsyncProxy for NodeSetProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let members = self.ordered_members();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for member in members {
                match member.connect(&context).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("node tag proxy failed")))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let members = self.ordered_members();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for member in members {
                match member.open_datagram(&context).await {
                    Ok(datagram) => return Ok(datagram),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("node tag datagram failed")))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let members = self.ordered_members();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for member in members {
                match member.ping(&context).await {
                    Ok(duration) => return Ok(duration),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("node tag ping failed")))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut last_error = None;
            for member in &self.members {
                if let Err(error) = member.close().await {
                    last_error = Some(error);
                }
            }
            last_error.map_or(Ok(()), Err)
        })
    }
}

#[derive(Debug, Clone)]
pub struct NodeTagDefinition {
    pub(in crate::plane) kind: String,
    pub(in crate::plane) targets: Vec<String>,
    pub(in crate::plane) strategy: NodeSelectionStrategy,
}

pub fn parse_node_tag(record: &doradus_store::GoNodeTagRecord) -> Result<NodeTagDefinition> {
    let value: serde_json::Value =
        serde_json::from_slice(&record.members_json).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid node tag {:?} JSON: {error}", record.name),
            )
        })?;
    let object = value.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("node tag {:?} must be a JSON object", record.name),
        )
    })?;
    let kind = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|kind| !kind.trim().is_empty())
        .unwrap_or("node")
        .to_ascii_lowercase();
    if kind != "node" && kind != "mirror" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unknown node tag {:?} type {kind:?}", record.name),
        ));
    }
    let targets = match object.get("hash") {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            vec![value.trim().to_owned()]
        }
        Some(_) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("node tag {:?} hash must be a string or array", record.name),
            ));
        }
        None => Vec::new(),
    };
    let strategy = object
        .get("strategy")
        .or_else(|| object.get("mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    Ok(NodeTagDefinition {
        kind,
        targets,
        strategy: if strategy.eq_ignore_ascii_case("round_robin")
            || strategy.eq_ignore_ascii_case("round-robin")
            || strategy.eq_ignore_ascii_case("roundrobin")
        {
            NodeSelectionStrategy::RoundRobin
        } else {
            NodeSelectionStrategy::Random
        },
    })
}

pub fn resolve_node_tag_targets(
    tag: &str,
    definitions: &BTreeMap<String, NodeTagDefinition>,
    visiting: &mut BTreeSet<String>,
) -> Vec<String> {
    let Some(definition) = definitions.get(tag) else {
        return Vec::new();
    };
    if !visiting.insert(tag.to_owned()) {
        return Vec::new();
    }
    let targets = if definition.kind == "mirror" {
        definition
            .targets
            .first()
            .map(|target| resolve_node_tag_targets(target, definitions, visiting))
            .unwrap_or_default()
    } else {
        definition.targets.clone()
    };
    visiting.remove(tag);
    targets
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn node_set_starting_index_visits_every_member_for_any_group_size() {
        for length in 1..=32 {
            for offset in 0..length {
                let starts = (0..length)
                    .map(|ticket| {
                        NodeSetProxy::starting_index(
                            ticket,
                            length,
                            NodeSelectionStrategy::Random,
                            offset,
                        )
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(starts.len(), length, "length={length}, offset={offset}");
            }
        }
    }

    #[test]
    fn node_set_round_robin_starts_at_the_first_member() {
        for length in 1..=32 {
            let starts = (0..length)
                .map(|ticket| {
                    NodeSetProxy::starting_index(
                        ticket,
                        length,
                        NodeSelectionStrategy::RoundRobin,
                        length - 1,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(starts, (0..length).collect::<Vec<_>>());
        }
    }
}
