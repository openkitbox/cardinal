use hickory_resolver::{
    TokioResolver,
    config::{
        LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
        ServerOrderingStrategy,
    },
    net::{NetError, runtime::TokioRuntimeProvider},
};
use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

const CLOUDFLARE_DOH_NAME: &str = "cloudflare-dns.com";
const GOOGLE_DOH_NAME: &str = "dns.google";
const ALIDNS_DOH_NAME: &str = "dns.alidns.com";
const DNS_QUERY_PATH: &str = "/dns-query";

/// DNS resolution profile: which upstream nameservers a provider's host is
/// resolved through. The host ↔ profile pairing is hard-coded (see `ROUTES`)
/// — there is intentionally no configuration surface for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Preset {
    /// Everything not in `ROUTES`: Cloudflare/Google DoH with an AliDNS UDP/TCP
    /// fallback. This is the historical single-resolver behavior, unchanged.
    Default,
    /// Chinese vendors: AliDNS DoH with a DNSPod UDP/TCP fallback — CDN-local
    /// answers, no dependency on overseas DoH reachability.
    Domestic,
    /// Overseas vendors: pure Cloudflare/Google DoH with NO domestic fallback,
    /// so a polluted or CDN-suboptimal domestic answer can never win.
    Overseas,
}

impl Preset {
    /// Log label identifying which preset resolved a host.
    fn label(self) -> &'static str {
        match self {
            Preset::Default => "default",
            Preset::Domestic => "domestic",
            Preset::Overseas => "overseas",
        }
    }
}

/// Hard-coded host-suffix → preset pairing; first match wins. The key is the
/// provider base_url's HOST, never the provider name — the name is
/// user-chosen and unreliable (the wire endpoint is the factual identity).
const ROUTES: &[(&str, Preset)] = &[
    ("bigmodel.cn", Preset::Domestic),
    ("deepseek.com", Preset::Domestic),
    ("kimi.com", Preset::Domestic),
    ("googleapis.com", Preset::Overseas),
    ("opencode.ai", Preset::Overseas),
    ("commandcode.ai", Preset::Overseas),
];

/// Dot-boundary suffix match: `host == suffix` or `host` ends with
/// `.{suffix}`, so `notbigmodel.cn` does not match `bigmodel.cn`.
fn host_matches(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

/// The preset a host resolves through: a pure table lookup, first route wins.
/// IP literals and unknown names fall to the default preset (literals never
/// reach a nameserver anyway — `resolve_all` short-circuits them).
///
/// The caller MUST pass an already lowercased host: `host_matches` compares
/// bytes, so an uppercase byte would silently miss a route (a `reqwest::Url`
/// parse result satisfies this). A trailing dot is stripped first, matching
/// the FQDN handling in `resolve_all`.
fn preset_for_host(host: &str) -> Preset {
    let host = host.strip_suffix('.').unwrap_or(host);
    for (suffix, preset) in ROUTES {
        if host_matches(host, suffix) {
            return *preset;
        }
    }
    Preset::Default
}

/// The nameserver list for one preset: DoH first (encrypted, harder to
/// poison); plaintext UDP/TCP only where the preset wants a domestic
/// fallback.
fn name_servers(preset: Preset) -> Vec<NameServerConfig> {
    let doh = |octets: [u8; 4], tls_name: &str| {
        NameServerConfig::https(
            IpAddr::V4(Ipv4Addr::from(octets)),
            Arc::from(tls_name),
            Some(Arc::from(DNS_QUERY_PATH)),
        )
    };
    match preset {
        Preset::Default => vec![
            doh([1, 1, 1, 1], CLOUDFLARE_DOH_NAME),
            doh([8, 8, 8, 8], GOOGLE_DOH_NAME),
            NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))),
        ],
        Preset::Domestic => {
            vec![
                doh([223, 5, 5, 5], ALIDNS_DOH_NAME),
                NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29))),
            ]
        }
        Preset::Overseas => vec![
            doh([1, 1, 1, 1], CLOUDFLARE_DOH_NAME),
            doh([8, 8, 8, 8], GOOGLE_DOH_NAME),
        ],
    }
}

/// DNS resolver for one preset, used by both destination validation and reqwest.
#[derive(Clone)]
pub(crate) struct HickoryResolver {
    resolver: TokioResolver,
    preset: Preset,
}

impl HickoryResolver {
    /// Builds the resolver for one preset. Hosts-file answers are intentionally
    /// disabled because provider destinations must come from the configured
    /// public resolvers.
    fn build(preset: Preset) -> anyhow::Result<Arc<Self>> {
        let config = ResolverConfig::from_name_servers(name_servers(preset));
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_secs(2);
        options.attempts = 2;
        options.num_concurrent_reqs = 1;
        options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        options.ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
        options.use_hosts_file = ResolveHosts::Never;
        options.try_tcp_on_error = true;
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to build Hickory DNS resolver (preset {}): {error}",
                    preset.label()
                )
            })?;
        Ok(Arc::new(Self { resolver, preset }))
    }

    pub(crate) async fn resolve_all(&self, host: &str) -> Result<Vec<IpAddr>, NetError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let fqdn = if host.ends_with('.') {
            Cow::Borrowed(host)
        } else {
            Cow::Owned(format!("{host}."))
        };
        let preset = self.preset.label();
        let lookup = self
            .resolver
            .lookup_ip(fqdn.as_ref())
            .await
            .inspect_err(|error| {
                tracing::warn!(host, preset, error = %error, "upstream dns resolution failed");
            })?;
        let addresses: Vec<IpAddr> = lookup.iter().collect();
        tracing::debug!(host, preset, ?addresses, "upstream dns resolution result");
        Ok(addresses)
    }
}

impl reqwest::dns::Resolve for HickoryResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let addresses = resolver.resolve_all(name.as_str()).await?;
            let addrs: reqwest::dns::Addrs =
                Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// One resolver per preset, each with its own TTL cache so answers never leak
/// across profiles. All three are built eagerly: a broken resolver
/// configuration fails fast at startup instead of on the first request.
#[derive(Clone)]
pub(crate) struct Resolvers {
    default: Arc<HickoryResolver>,
    domestic: Arc<HickoryResolver>,
    overseas: Arc<HickoryResolver>,
}

impl Resolvers {
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self {
            default: HickoryResolver::build(Preset::Default)?,
            domestic: HickoryResolver::build(Preset::Domestic)?,
            overseas: HickoryResolver::build(Preset::Overseas)?,
        })
    }

    /// The resolver a host's lookups go through (see [`preset_for_host`]).
    pub(crate) fn for_host(&self, host: &str) -> &Arc<HickoryResolver> {
        match preset_for_host(host) {
            Preset::Default => &self.default,
            Preset::Domestic => &self.domestic,
            Preset::Overseas => &self.overseas,
        }
    }

    /// The default preset's resolver: reqwest clients whose destination is not
    /// host-specific (the startup configuration probe) resolve through it.
    pub(crate) fn default_resolver(&self) -> &Arc<HickoryResolver> {
        &self.default
    }
}
