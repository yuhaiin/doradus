use super::*;
pub async fn route_config_get_value(state: &ApiState) -> ApiResult {
    let value = state.controller.store().repository().list_go_route_settings().await?.into_iter().next().map(|record| json!({
        "directResolver": record.direct_resolver,
        "proxyResolver": record.proxy_resolver,
        "resolveLocally": record.resolve_locally,
        "udpProxyFqdnStrategy": match record.udp_proxy_fqdn { 1 => "resolve", 2 => "skip_resolve", _ => "default" },
    })).unwrap_or_else(default_route_config);
    Ok(Json(value))
}

pub async fn route_config_put_value(state: &ApiState, value: Value) -> ApiResult {
    let record = GoRouteSettingsRecord {
        // Go's route_settings compatibility table is a single-row table with
        // CHECK (id = 1). Keep the API mutation on that canonical row so a
        // Go snapshot can be edited and later reopened by either runtime.
        id: 1,
        direct_resolver: string_or_any(&value, &["directResolver", "direct_resolver"]),
        proxy_resolver: string_or_any(&value, &["proxyResolver", "proxy_resolver"]),
        resolve_locally: bool_or_any(&value, &["resolveLocally", "resolve_locally"], false),
        udp_proxy_fqdn: match string_or_any(&value, &["udpProxyFqdnStrategy", "udp_proxy_fqdn"])
            .as_str()
        {
            "resolve" => 1,
            "skip_resolve" | "skipResolve" => 2,
            _ => 0,
        },
    };
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_route_settings(&record).await
        })
        .await?;
    Ok(Json(returned))
}

pub async fn route_lists_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    let values = records
        .into_iter()
        .map(route_list_item_json)
        .collect::<Vec<_>>();
    Ok(Json(page_with_filter(
        values,
        input,
        route_list_matches_query,
    )))
}

pub async fn get_route_list_value(state: &ApiState, id: String) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_lists()
        .await?;
    records
        .into_iter()
        .find(|record| record.name == id)
        .map(|record| Json(route_list_detail_json(record)))
        .ok_or_else(|| ApiError::not_found("route list not found"))
}

pub async fn save_route_list_value(
    state: &ApiState,
    mut value: Value,
    name: Option<String>,
) -> ApiResult {
    let request_name = name.unwrap_or(required_string(&value, "name")?);
    set_string(&mut value, "name", request_name.clone());
    let name = request_name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::bad("route list name is empty"));
    }
    let persisted_value = normalize_route_list_value(&value, &name);
    let source = persisted_value
        .get("source")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let record = GoRouteListRecord {
        name: name.clone(),
        list_type: string_or(&persisted_value, "type", "host"),
        source_type: string_or(&source, "type", "local"),
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&persisted_value)?,
    };
    let activation = serde_json::to_vec(&pending_route_list_activation())?;
    let returned = value.clone();
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.repository().put_go_route_list(&record).await?;
            store
                .put_config(ROUTE_LIST_ACTIVATION_KEY, &activation)
                .await
        })
        .await?;
    Ok(Json(returned))
}

pub async fn delete_route_list_value(state: &ApiState, id: String) -> ApiResult {
    let activation = serde_json::to_vec(&pending_route_list_activation())?;
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            if store.repository().delete_go_route_list(&id).await? {
                store
                    .put_config(ROUTE_LIST_ACTIVATION_KEY, &activation)
                    .await
            } else {
                Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::NotFound,
                    "route list not found",
                ))
            }
        })
        .await;
    result.map(|_| empty_json()).map_err(|error| {
        if error.to_string().contains("not found") {
            ApiError::not_found(error.to_string())
        } else {
            error.into()
        }
    })
}

pub async fn route_rules_get_value(state: &ApiState, input: &Value) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    let values = records
        .into_iter()
        .map(route_rule_item_json)
        .collect::<Vec<_>>();
    Ok(Json(page_with_filter(
        values,
        input,
        route_rule_matches_query,
    )))
}

pub async fn get_route_rule_value(state: &ApiState, name: String, _index: usize) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    records
        .into_iter()
        .find(|record| record.name == name)
        .map(|record| Json(route_rule_detail_json(record)))
        .ok_or_else(|| ApiError::not_found("route rule not found"))
}

pub async fn save_route_rule_value(
    state: &ApiState,
    mut value: Value,
    index: Option<usize>,
) -> ApiResult {
    let request_name = required_string(&value, "name")?;
    let name = request_name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::bad("route rule name is empty"));
    }
    let current = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    let existing = current.iter().find(|record| record.name == name);
    let replace_legacy_id = existing.is_some_and(|record| record.id != name);
    let priority = existing.map(|record| record.priority).unwrap_or_else(|| {
        let requested = index.map(|value| value as i64).unwrap_or_default();
        if requested > 0 {
            requested
        } else {
            current
                .iter()
                .map(|record| record.priority)
                .max()
                .unwrap_or_default()
                .saturating_add(1)
        }
    });
    set_string(&mut value, "name", request_name);
    let returned = value.clone();
    let mut persisted_value = normalize_route_rule_value(&value, &name);
    let (match_type, pattern) = route_match(&persisted_value);
    if !pattern.is_empty()
        && let Some(object) = persisted_value.as_object_mut()
    {
        let mut matcher = Map::new();
        matcher.insert(
            if match_type == "cidr" {
                "cidr"
            } else {
                "domain"
            }
            .to_owned(),
            Value::String(pattern),
        );
        object
            .entry("match".to_owned())
            .or_insert_with(|| Value::Object(matcher));
    }
    let record = GoRouteRuleRecord {
        // Go's v2 store uses the public rule name as the compatibility row
        // id.  The URL index is only a legacy routing parameter; making it
        // part of the id creates duplicate rules on every PUT.
        id: name.clone(),
        name: name.clone(),
        priority,
        disabled: bool_or(&persisted_value, "disabled", false),
        action_mode: string_or(&persisted_value, "mode", "direct"),
        match_type,
        tag: match string_or(&persisted_value, "tag", "default").as_str() {
            "" => "default".to_owned(),
            tag => tag.to_owned(),
        },
        updated_at: unix_seconds(),
        data_json: serde_json::to_vec(&persisted_value)?,
    };
    let activation = serde_json::to_vec(&pending_route_rule_activation())?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            if replace_legacy_id {
                store
                    .repository()
                    .delete_go_route_rule_by_name(&record.name)
                    .await?;
            }
            store.repository().put_go_route_rule(&record).await?;
            store.put_config(ROUTE_ACTIVATION_KEY, &activation).await
        })
        .await?;
    Ok(Json(returned))
}

pub async fn delete_route_rule_value(state: &ApiState, name: String, _index: usize) -> ApiResult {
    let records = state
        .controller
        .store()
        .repository()
        .list_go_route_rules()
        .await?;
    if !records.iter().any(|record| record.name == name) {
        return Err(ApiError::not_found("route rule not found"));
    }
    let activation = serde_json::to_vec(&pending_route_rule_activation())?;
    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .delete_go_route_rule_by_name(&name)
                .await?;
            store.put_config(ROUTE_ACTIVATION_KEY, &activation).await
        })
        .await;
    result.map(|_| empty_json()).map_err(Into::into)
}

pub async fn route_rules_priority_value(state: &ApiState, value: &Value) -> ApiResult {
    let source = value
        .get("source")
        .ok_or_else(|| ApiError::bad("source is required"))?;
    let target = value
        .get("target")
        .ok_or_else(|| ApiError::bad("target is required"))?;
    let source_name = required_string(source, "name")?;
    let target_name = required_string(target, "name")?;
    let operate = string_or(value, "operate", "exchange");
    if !matches!(
        operate.as_str(),
        "" | "exchange" | "insert_before" | "insert_after"
    ) {
        return Err(ApiError::bad(format!(
            "unknown priority operate {operate:?}"
        )));
    }
    let activation = serde_json::to_vec(&pending_route_rule_activation())?;

    let result = state
        .controller
        .mutate_and_reload(move |store| async move {
            store
                .repository()
                .change_go_route_rule_priority(&source_name, &target_name, &operate)
                .await?;
            store.put_config(ROUTE_ACTIVATION_KEY, &activation).await
        })
        .await;
    result
        .map(|_| empty_json())
        .map_err(|error| match error.kind {
            yuhaiin_core::ErrorKind::NotFound => ApiError::not_found(error.to_string()),
            yuhaiin_core::ErrorKind::InvalidInput => ApiError::bad(error.to_string()),
            _ => error.into(),
        })
}

pub async fn route_rules_test_value(state: &ApiState, value: &Value) -> ApiResult {
    let input = required_string(value, "host")?;
    let (host, port) = split_rule_test_target(&input)?;
    let destination = match host.parse() {
        Ok(address) => Endpoint::ip(Network::Tcp, std::net::SocketAddr::new(address, port)),
        Err(_) => Endpoint::domain(
            Network::Tcp,
            DomainName::new(&host).map_err(|error| ApiError::bad(error.to_string()))?,
            port,
        ),
    };
    let mut context = FlowContext::new(destination);
    let snapshot = state.controller.handle().load();
    let decision = snapshot.apply_route(&mut context);
    let mode = match decision.mode {
        yuhaiin_core::RouteMode::Direct => "direct",
        yuhaiin_core::RouteMode::Proxy => "proxy",
        yuhaiin_core::RouteMode::Bypass => "bypass",
        yuhaiin_core::RouteMode::Block => "drop",
    };
    let selected_rule_name = snapshot.router.selected_rule_name(&context);
    let selected = selected_rule_name.as_deref().and_then(|name| {
        snapshot
            .route_rules
            .iter()
            .find(|record| record.name == name)
            .map(|record| raw_json(&record.data_json, json!({})))
    });
    let tag = context.tag.clone().unwrap_or_else(|| {
        selected
            .as_ref()
            .map(|value| string_or(value, "tag", ""))
            .unwrap_or_default()
    });
    let resolver = selected
        .as_ref()
        .map(|value| string_or(value, "resolver", ""))
        .unwrap_or_default();
    let match_result = context
        .match_history
        .iter()
        .map(|entry| {
            json!({
                "ruleName": entry.rule_name,
                "history": entry
                    .history
                    .iter()
                    .map(|result| {
                        json!({
                            "listName": result.list_name,
                            "matched": result.matched,
                        })
                    })
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let ips = match &context.destination {
        Endpoint::Ip { addr, .. } => vec![addr.ip().to_string()],
        Endpoint::Domain { host, .. } => {
            let mut resolved = Vec::new();
            if let Ok(resolver) = snapshot.dns_resolver_for_route_mode(decision.mode)
                && let Ok(addresses) = resolver.resolve(host, ResolveStrategy::Default).await
            {
                resolved.extend(addresses.v4.into_iter().map(|address| address.to_string()));
                resolved.extend(addresses.v6.into_iter().map(|address| address.to_string()));
            }
            resolved
        }
    };
    json_value(json!({
        "mode": mode,
        "tag": tag,
        "resolver": resolver,
        "afterAddr": endpoint_authority(&context.destination),
        "lists": context.lists,
        "ips": ips,
        "matchResult": match_result,
    }))
}

pub fn endpoint_authority(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ip { addr, .. } => addr.to_string(),
        Endpoint::Domain { host, port, .. } if *port == 0 => host.to_string(),
        Endpoint::Domain { host, port, .. } => format!("{host}:{port}"),
    }
}

pub fn split_rule_test_target(value: &str) -> std::result::Result<(String, u16), ApiError> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| ApiError::bad("host has an invalid IPv6 authority"))?;
        let port = suffix
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|error| ApiError::bad(format!("host port: {error}")))?
            .unwrap_or(0);
        return Ok((host.to_owned(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Ok((host.to_owned(), port));
    }
    Ok((value.to_owned(), 0))
}

pub async fn route_rules_block_history_value(state: &ApiState) -> ApiResult {
    json_value(state.controller.monitor().block_history_value())
}

pub async fn route_apply_value(state: &ApiState) -> ApiResult {
    let applied_at = unix_millis();
    let activation = json!({
        "hostIndexRefreshAt": 0,
        "ruleApplyAt": 0,
        "lastApplyAt": applied_at,
    });
    let bytes = serde_json::to_vec(&activation)?;
    let list_bytes = serde_json::to_vec(&json!({"hostIndexRefreshAt": 0}))?;
    state
        .controller
        .mutate_and_reload(move |store| async move {
            store.put_config(ROUTE_ACTIVATION_KEY, &bytes).await?;
            store
                .put_config(ROUTE_LIST_ACTIVATION_KEY, &list_bytes)
                .await
        })
        .await?;
    state
        .controller
        .monitor()
        .logs()
        .info(format!("route rules applied at {applied_at}"));
    empty()
}

pub async fn route_activation_value(state: &ApiState) -> ApiResult {
    let rule_value = state
        .controller
        .store()
        .get_config(ROUTE_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0, "ruleApplyAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0, "ruleApplyAt": 0}));
    let list_value = state
        .controller
        .store()
        .get_config(ROUTE_LIST_ACTIVATION_KEY)
        .await?
        .map(|bytes| raw_json(&bytes, json!({"hostIndexRefreshAt": 0})))
        .unwrap_or_else(|| json!({"hostIndexRefreshAt": 0}));
    let value = json!({
        "hostIndexRefreshAt": effective_activation_at(&list_value, "hostIndexRefreshAt"),
        "ruleApplyAt": effective_activation_at(&rule_value, "ruleApplyAt"),
    });
    json_value(value)
}

pub fn effective_activation_at(value: &Value, field: &str) -> i64 {
    value
        .get(field)
        .and_then(Value::as_i64)
        .filter(|at| *at > unix_millis())
        .unwrap_or(0)
}

pub fn pending_route_list_activation() -> Value {
    json!({"hostIndexRefreshAt": unix_millis() + 60_000})
}

pub fn pending_route_rule_activation() -> Value {
    json!({"hostIndexRefreshAt": 0, "ruleApplyAt": unix_millis() + 60_000})
}

pub async fn hosts_get_value(state: &ApiState) -> ApiResult {
    if let Some(value) = state
        .controller
        .store()
        .get_config("resolver.hosts")
        .await?
    {
        return Ok(Json(raw_json(&value, json!({"hosts": {}}))));
    }
    let mut hosts = Map::new();
    for record in state
        .controller
        .store()
        .repository()
        .list_go_dns_hosts()
        .await?
    {
        hosts.insert(record.host, Value::String(record.target));
    }
    Ok(Json(json!({"hosts": hosts})))
}

pub async fn hosts_put_value(state: &ApiState, value: Value) -> ApiResult {
    let value = if value.get("hosts").is_some() {
        value
    } else {
        json!({"hosts": value})
    };
    write_config_json(state, "resolver.hosts", value).await
}

pub async fn fakedns_get_value(state: &ApiState) -> ApiResult {
    if let Some(value) = state
        .controller
        .store()
        .get_config("resolver.fakedns")
        .await?
    {
        return Ok(Json(raw_json(&value, default_fakedns())));
    }
    let repository = state.controller.store().repository();
    let settings = repository.list_go_dns_settings().await?;
    let lists = repository.list_go_dns_fakedns_lists().await?;
    let mut value = settings
        .into_iter()
        .next()
        .map(|record| {
            json!({
                "enabled": record.fakedns_enabled,
                "ipv4Range": record.fakedns_ipv4_range,
                "ipv6Range": record.fakedns_ipv6_range,
                "whitelist": [],
                "skipCheckList": [],
            })
        })
        .unwrap_or_else(default_fakedns);
    let mut whitelist = Vec::new();
    let mut skip_check_list = Vec::new();
    for list in lists {
        match list.kind.as_str() {
            "whitelist" => whitelist.push(Value::String(list.value)),
            "skip_check" => skip_check_list.push(Value::String(list.value)),
            _ => {}
        }
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::internal("fake DNS settings must be an object"))?;
    object.insert("whitelist".to_owned(), Value::Array(whitelist));
    object.insert("skipCheckList".to_owned(), Value::Array(skip_check_list));
    Ok(Json(value))
}

pub async fn fakedns_put_value(state: &ApiState, value: Value) -> ApiResult {
    write_config_json(state, "resolver.fakedns", value).await
}

pub async fn resolver_server_get_value(state: &ApiState) -> ApiResult {
    if let Some(value) = state
        .controller
        .store()
        .get_config("resolver.server")
        .await?
    {
        return Ok(Json(raw_json(&value, json!({"server": ""}))));
    }
    let server = state
        .controller
        .store()
        .repository()
        .list_go_dns_settings()
        .await?
        .into_iter()
        .next()
        .map(|r| r.server)
        .unwrap_or_default();
    Ok(Json(json!({"server": server})))
}

pub async fn resolver_server_put_value(state: &ApiState, value: Value) -> ApiResult {
    let server = string_or(&value, "server", "");
    let config = json!({"server": server});
    let bytes = serde_json::to_vec(&config)?;
    state
        .controller
        .mutate_and_reload_dns(move |store| async move {
            store.put_config("resolver.server", &bytes).await?;
            store.repository().put_go_dns_server(&server).await
        })
        .await?;
    Ok(Json(config))
}
