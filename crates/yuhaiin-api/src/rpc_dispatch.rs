use super::*;
#[derive(Debug, Clone, Copy)]
enum RpcOperation {
    Info,
    UpdateCheck,
    UpdateApply,
    UpdateStatus,
    SettingsGet,
    SettingsPut,
    BackupConfigGet,
    BackupConfigPut,
    BackupRun,
    BackupRestore,
    ToolsInterfaces,
    ToolsLicenses,
    ToolsLogs,
    ToolsLogsV2,
    NodesGet,
    NodesPost,
    NodesSelected,
    NodesActive,
    NodeGet,
    NodePut,
    NodeDelete,
    NodeUse,
    NodeClose,
    NodeLatency,
    InboundsConfigGet,
    InboundsConfigPut,
    InboundsGet,
    InboundsPost,
    InboundGet,
    InboundPut,
    InboundDelete,
    ResolversGet,
    ResolversPost,
    ResolverGet,
    ResolverPut,
    ResolverDelete,
    ResolverHostsGet,
    ResolverHostsPut,
    ResolverFakednsGet,
    ResolverFakednsPut,
    ResolverServerGet,
    ResolverServerPut,
    SubscriptionsGet,
    SubscriptionsPut,
    SubscriptionsDelete,
    SubscriptionsDeletePreview,
    SubscriptionsUpdate,
    Publishes,
    PublishPut,
    PublishDelete,
    PublishResolve,
    UsersGet,
    UsersPost,
    UserGet,
    UserPut,
    UserDelete,
    Connections,
    ConnectionsTotal,
    ConnectionsTraffic,
    ConnectionsTelemetry,
    ConnectionsClose,
    ConnectionsFailedHistory,
    ConnectionsHistory,
    TunConfigGet,
    TunConfigPut,
    RouteConfigGet,
    RouteConfigPut,
    RouteListsGet,
    RouteListsPost,
    RouteListGet,
    RouteListPut,
    RouteListDelete,
    RouteListsConfigGet,
    RouteListsConfigPut,
    RouteListsRefresh,
    RouteListsActivation,
    RouteRulesGet,
    RouteRulesPost,
    RouteRuleGet,
    RouteRulePut,
    RouteRuleDelete,
    RouteRulesPriority,
    RouteRulesTest,
    RouteRulesBlockHistory,
    RouteApply,
    RouteActivation,
    RouteTagsGet,
    RouteTagPut,
    RouteTagDelete,
}

impl RpcOperation {
    fn parse(name: &str) -> Result<Self, ApiError> {
        Ok(match name {
            "info" => Self::Info,
            "update.check" => Self::UpdateCheck,
            "update.apply" => Self::UpdateApply,
            "update.status" => Self::UpdateStatus,
            "settings.get" => Self::SettingsGet,
            "settings.put" => Self::SettingsPut,
            "backup.config.get" => Self::BackupConfigGet,
            "backup.config.put" => Self::BackupConfigPut,
            "backup.run" => Self::BackupRun,
            "backup.restore" => Self::BackupRestore,
            "tools.interfaces" => Self::ToolsInterfaces,
            "tools.licenses" => Self::ToolsLicenses,
            "tools.logs" => Self::ToolsLogs,
            "tools.logs.v2" => Self::ToolsLogsV2,
            "nodes.get" => Self::NodesGet,
            "nodes.post" => Self::NodesPost,
            "nodes.selected" => Self::NodesSelected,
            "nodes.active" => Self::NodesActive,
            "node.get" => Self::NodeGet,
            "node.put" => Self::NodePut,
            "node.delete" => Self::NodeDelete,
            "node.use" => Self::NodeUse,
            "node.close" => Self::NodeClose,
            "node.latency" => Self::NodeLatency,
            "inbounds.config.get" => Self::InboundsConfigGet,
            "inbounds.config.put" => Self::InboundsConfigPut,
            "inbounds.get" => Self::InboundsGet,
            "inbounds.post" => Self::InboundsPost,
            "inbound.get" => Self::InboundGet,
            "inbound.put" => Self::InboundPut,
            "inbound.delete" => Self::InboundDelete,
            "resolvers.get" => Self::ResolversGet,
            "resolvers.post" => Self::ResolversPost,
            "resolver.get" => Self::ResolverGet,
            "resolver.put" => Self::ResolverPut,
            "resolver.delete" => Self::ResolverDelete,
            "resolver.hosts.get" => Self::ResolverHostsGet,
            "resolver.hosts.put" => Self::ResolverHostsPut,
            "resolver.fakedns.get" => Self::ResolverFakednsGet,
            "resolver.fakedns.put" => Self::ResolverFakednsPut,
            "resolver.server.get" => Self::ResolverServerGet,
            "resolver.server.put" => Self::ResolverServerPut,
            "subscriptions.get" => Self::SubscriptionsGet,
            "subscriptions.put" => Self::SubscriptionsPut,
            "subscriptions.delete" => Self::SubscriptionsDelete,
            "subscriptions.delete_preview" => Self::SubscriptionsDeletePreview,
            "subscriptions.update" => Self::SubscriptionsUpdate,
            "publishes" => Self::Publishes,
            "publish.put" => Self::PublishPut,
            "publish.delete" => Self::PublishDelete,
            "publish.resolve" => Self::PublishResolve,
            "users.get" => Self::UsersGet,
            "users.post" => Self::UsersPost,
            "user.get" => Self::UserGet,
            "user.put" => Self::UserPut,
            "user.delete" => Self::UserDelete,
            "connections" => Self::Connections,
            "connections.total" => Self::ConnectionsTotal,
            "connections.traffic" => Self::ConnectionsTraffic,
            "connections.telemetry" => Self::ConnectionsTelemetry,
            "connections.close" => Self::ConnectionsClose,
            "connections.failed_history" => Self::ConnectionsFailedHistory,
            "connections.history" => Self::ConnectionsHistory,
            "tun.config.get" => Self::TunConfigGet,
            "tun.config.put" => Self::TunConfigPut,
            "route.config.get" => Self::RouteConfigGet,
            "route.config.put" => Self::RouteConfigPut,
            "route.lists.get" => Self::RouteListsGet,
            "route.lists.post" => Self::RouteListsPost,
            "route.list.get" => Self::RouteListGet,
            "route.list.put" => Self::RouteListPut,
            "route.list.delete" => Self::RouteListDelete,
            "route.lists.config.get" => Self::RouteListsConfigGet,
            "route.lists.config.put" => Self::RouteListsConfigPut,
            "route.lists.refresh" => Self::RouteListsRefresh,
            "route.lists.activation" => Self::RouteListsActivation,
            "route.rules.get" => Self::RouteRulesGet,
            "route.rules.post" => Self::RouteRulesPost,
            "route.rule.get" => Self::RouteRuleGet,
            "route.rule.put" => Self::RouteRulePut,
            "route.rule.delete" => Self::RouteRuleDelete,
            "route.rules.priority" => Self::RouteRulesPriority,
            "route.rules.test" => Self::RouteRulesTest,
            "route.rules.block_history" => Self::RouteRulesBlockHistory,
            "route.apply" => Self::RouteApply,
            "route.activation" => Self::RouteActivation,
            "route.tags.get" => Self::RouteTagsGet,
            "route.tag.put" => Self::RouteTagPut,
            "route.tag.delete" => Self::RouteTagDelete,
            _ => {
                return Err(ApiError::not_found(format!(
                    "unknown RPC operation {name:?}"
                )));
            }
        })
    }
}

pub(super) async fn dispatch(
    State(state): State<ApiState>,
    Path(operation): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    let body = if body.is_object() {
        body
    } else {
        return Err(ApiError::bad("request must be a JSON object"));
    };
    let operation = RpcOperation::parse(&operation)?;
    match operation {
        RpcOperation::Info => info_value(&state),
        RpcOperation::UpdateCheck => update_check_value(&state, &body).await,
        RpcOperation::UpdateApply => update_apply_value(&state, &body).await,
        RpcOperation::UpdateStatus => update_status_value(&state).await,
        RpcOperation::SettingsGet => settings_get_value(&state).await,
        RpcOperation::SettingsPut => write_config_json(&state, "settings", body).await,
        RpcOperation::BackupConfigGet => backup_config_get_value(&state).await,
        RpcOperation::BackupConfigPut => backup_config_put_value(&state, body).await,
        RpcOperation::BackupRun => run_backup_value(&state).await,
        RpcOperation::BackupRestore => restore_backup_value(&state, &body).await,
        RpcOperation::ToolsInterfaces => tools_interfaces_value(),
        RpcOperation::ToolsLicenses => tools_licenses_value(),
        RpcOperation::ToolsLogs | RpcOperation::ToolsLogsV2 => json_value(log_batch_value(
            state.controller.monitor().logs().snapshot(),
        )),
        RpcOperation::NodesGet => nodes_get_value(&state, &body).await,
        RpcOperation::NodesPost => save_node_value(&state, body, None).await,
        RpcOperation::NodesSelected => selected_nodes_value(&state).await,
        RpcOperation::NodesActive => active_nodes_value(&state).await,
        // Go decodes these endpoints into typed request structs. A missing or
        // null string field therefore becomes the zero value and reaches the
        // store lookup, which returns 404; it is not rejected as a 400 here.
        RpcOperation::NodeGet => get_node_value(&state, go_request_string(&body, "id")?).await,
        RpcOperation::NodePut => save_node_value(&state, body, None).await,
        RpcOperation::NodeDelete => delete_node_value(&state, required_string(&body, "id")?).await,
        RpcOperation::NodeUse => select_node_value(&state, required_string(&body, "id")?).await,
        RpcOperation::NodeClose => node_close_value(&state, required_string(&body, "id")?).await,
        RpcOperation::NodeLatency => node_latency_value(&state, &body).await,
        RpcOperation::InboundsConfigGet => inbounds_config_get_value(&state).await,
        RpcOperation::InboundsConfigPut => inbounds_config_put_value(&state, body).await,
        RpcOperation::InboundsGet => inbounds_get_value(&state, &body).await,
        RpcOperation::InboundsPost => save_inbound_value(&state, body, None).await,
        RpcOperation::InboundGet => {
            get_inbound_value(&state, go_request_string(&body, "id")?).await
        }
        RpcOperation::InboundPut => save_inbound_value(&state, body, None).await,
        RpcOperation::InboundDelete => {
            delete_inbound_value(&state, required_string(&body, "id")?).await
        }
        RpcOperation::ResolversGet => resolvers_get_value(&state, &body).await,
        RpcOperation::ResolversPost => save_resolver_value(&state, body, None).await,
        RpcOperation::ResolverGet => {
            get_resolver_value(&state, go_request_string(&body, "id")?).await
        }
        RpcOperation::ResolverPut => save_resolver_value(&state, body, None).await,
        RpcOperation::ResolverDelete => {
            delete_resolver_value(&state, required_string(&body, "id")?).await
        }
        RpcOperation::ResolverHostsGet => hosts_get_value(&state).await,
        RpcOperation::ResolverHostsPut => hosts_put_value(&state, body).await,
        RpcOperation::ResolverFakednsGet => fakedns_get_value(&state).await,
        RpcOperation::ResolverFakednsPut => fakedns_put_value(&state, body).await,
        RpcOperation::ResolverServerGet => resolver_server_get_value(&state).await,
        RpcOperation::ResolverServerPut => resolver_server_put_value(&state, body).await,
        RpcOperation::SubscriptionsGet => subscriptions_get_value(&state).await,
        RpcOperation::SubscriptionsPut => subscriptions_put_value(&state, body).await,
        RpcOperation::SubscriptionsDelete => subscriptions_delete_value(&state, &body).await,
        RpcOperation::SubscriptionsDeletePreview => {
            subscriptions_delete_preview_value(&state, &body).await
        }
        RpcOperation::SubscriptionsUpdate => subscriptions_update_value(&state, &body).await,
        RpcOperation::Publishes => publishes_get_value(&state).await,
        RpcOperation::PublishPut => publish_put_value(&state, body).await,
        RpcOperation::PublishDelete => {
            publish_delete_value(&state, required_string(&body, "name")?).await
        }
        RpcOperation::PublishResolve => publish_resolve_value(&state, &body).await,
        RpcOperation::UsersGet => users_get_value(&state, &body).await,
        RpcOperation::UsersPost => user_save_value(&state, body, None).await,
        RpcOperation::UserGet => user_get_value(&state, go_request_string(&body, "id")?).await,
        RpcOperation::UserPut => {
            user_save_value(&state, body.clone(), Some(required_string(&body, "id")?)).await
        }
        RpcOperation::UserDelete => user_delete_value(&state, required_string(&body, "id")?).await,
        RpcOperation::Connections => json_value(state.controller.monitor().connections_value()),
        RpcOperation::ConnectionsTotal => json_value(state.controller.monitor().total_flow_value()),
        RpcOperation::ConnectionsTraffic => {
            let interval = string_or(&body, "interval", "hour");
            let (from, to) = required_stats_range(
                body.get("from").and_then(Value::as_str),
                body.get("to").and_then(Value::as_str),
            )?;
            json_value(
                state
                    .controller
                    .monitor()
                    .traffic_value_range(&interval, from, to),
            )
        }
        RpcOperation::ConnectionsTelemetry => {
            let (from, to) = required_stats_range(
                body.get("from").and_then(Value::as_str),
                body.get("to").and_then(Value::as_str),
            )?;
            let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(8);
            if !(1..=50).contains(&limit) {
                return Err(ApiError::bad("limit must be between 1 and 50"));
            }
            json_value(
                state
                    .controller
                    .monitor()
                    .telemetry_value_range(from, to, limit as usize),
            )
        }
        RpcOperation::ConnectionsClose => close_connections_value(&state, body).await,
        RpcOperation::ConnectionsFailedHistory => {
            json_value(state.controller.monitor().failed_history_value())
        }
        RpcOperation::ConnectionsHistory => {
            json_value(state.controller.monitor().all_history_value())
        }
        RpcOperation::TunConfigGet => {
            read_config_json(&state, "tun.runtime", default_tun_config()).await
        }
        RpcOperation::TunConfigPut => write_config_json(&state, "tun.runtime", body).await,
        RpcOperation::RouteConfigGet => route_config_get_value(&state).await,
        RpcOperation::RouteConfigPut => route_config_put_value(&state, body).await,
        RpcOperation::RouteListsGet => route_lists_get_value(&state, &body).await,
        RpcOperation::RouteListsPost => save_route_list_value(&state, body, None).await,
        RpcOperation::RouteListGet => {
            get_route_list_value(&state, go_request_string(&body, "id")?).await
        }
        RpcOperation::RouteListPut => save_route_list_value(&state, body, None).await,
        RpcOperation::RouteListDelete => {
            delete_route_list_value(&state, required_string(&body, "id")?).await
        }
        RpcOperation::RouteListsConfigGet => route_lists_config_get_value(&state).await,
        RpcOperation::RouteListsConfigPut => route_lists_config_put_value(&state, body).await,
        RpcOperation::RouteListsRefresh => route_lists_refresh_value(&state).await,
        RpcOperation::RouteListsActivation => route_lists_activation_value(&state).await,
        RpcOperation::RouteRulesGet => route_rules_get_value(&state, &body).await,
        RpcOperation::RouteRulesPost => save_route_rule_value(&state, body, None).await,
        RpcOperation::RouteRuleGet => {
            get_route_rule_value(
                &state,
                go_request_string(&body, "name")?,
                go_request_number(&body, "index")?,
            )
            .await
        }
        RpcOperation::RouteRulePut => {
            let index = number(&body, "index")?;
            save_route_rule_value(&state, body, Some(index)).await
        }
        RpcOperation::RouteRuleDelete => {
            delete_route_rule_value(
                &state,
                required_string(&body, "name")?,
                number(&body, "index")?,
            )
            .await
        }
        RpcOperation::RouteRulesPriority => route_rules_priority_value(&state, &body).await,
        RpcOperation::RouteRulesTest => route_rules_test_value(&state, &body).await,
        RpcOperation::RouteRulesBlockHistory => route_rules_block_history_value(&state).await,
        RpcOperation::RouteApply => route_apply_value(&state).await,
        RpcOperation::RouteActivation => route_activation_value(&state).await,
        RpcOperation::RouteTagsGet => tags_get_value(&state, &body).await,
        RpcOperation::RouteTagPut => tag_put_value(&state, body).await,
        RpcOperation::RouteTagDelete => {
            tag_delete_value(&state, required_string(&body, "tag")?).await
        }
    }
}
