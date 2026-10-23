//! PostgreSQL access for providers, keys, routes and cooldowns.
//!
//! Pure data layer: no business-semantics parsing, only keeping row structures consistent with the schema.
//! The model is key-centric: providers hold no credential, every credential is a named key row,
//! cooldown identity is (key, model) with NULL meaning the whole key, and routes are named key
//! subsets exposed as client model ids.

mod gateway_key;
mod key;
mod price;
mod provider;
mod quota;
mod request;
mod rest;
mod route;
mod usage;

pub use gateway_key::{
    GatewayKeyInfo, GatewayKeyRow, create_gateway_key, gateway_key_info, list_gateway_keys,
    seed_gateway_key, set_gateway_key_enabled, touch_gateway_key,
};
pub use key::{
    ActiveWindow, AvailabilityRule, EnabledKeyModels, KeyModels, LimitedKeyRow, ProviderKeyRow,
    ProviderKeyView, RouteEntry, RouteRow, RouteStrategy, RuleEffect, delete_provider_key,
    insert_provider_key, key_api_key, list_all_key_models, list_all_keys, list_enabled_key_models,
    list_keys_by_ids, list_limited_keys, list_provider_keys, reorder_keys, update_key_models,
    update_provider_key,
};
pub use price::{
    ModelPrice, ModelSuccessRow, PriceTier, get_price, last_model_success,
    served_models_for_pricing, upsert_catalog_price,
};
pub use provider::{
    ProviderInput, ProviderRow, default_auth_scheme, delete_provider, find_or_create_provider,
    get_provider, get_provider_by_name, insert_provider, list_providers, list_providers_by_ids,
    seed_from_config, set_provider_enabled, update_provider,
};
pub use quota::{
    QuotaHistoryPoint, list_quota_history, list_quota_snapshots, list_quota_snapshots_by_keys,
    quota_history_insert, quota_snapshot_upsert,
};
pub use request::{
    AttemptLog, RequestRow, insert_request_logs, list_recent_requests, request_row_anchor,
};
pub use rest::{
    ActiveRestRow, RestRow, active_rest_rows, clear_provider_rests, clear_rest,
    clear_rest_for_model, insert_rest, list_rests,
};
pub use route::{EffortsUpdate, delete_route, get_route, list_routes, put_route};
pub use usage::{
    CallerFilter, TrendRow, TrendSplit, UsageRow, UsageWindow, hourly_buckets, usage_by_day,
    usage_trend, usage_window,
};
