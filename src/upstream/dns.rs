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
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

const CLOUDFLARE_DOH_NAME: &str = "cloudflare-dns.com";
const GOOGLE_DOH_NAME: &str = "dns.google";
const ALIDNS_DOH_NAME: &str = "dns.alidns.com";
const DOT_PUB_NAME: &str = "dot.pub";
const DNS_QUERY_PATH: &str = "/dns-query";

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Dns {
    #[default]
    Overseas,
    Domestic,
}

impl fmt::Display for Dns {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Overseas => "overseas",
            Self::Domestic => "domestic",
        })
    }
}

impl FromStr for Dns {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "overseas" => Ok(Self::Overseas),
            "domestic" => Ok(Self::Domestic),
            _ => Err(anyhow::anyhow!("unknown DNS region: {value}")),
        }
    }
}

fn name_servers(dns: Dns) -> Vec<NameServerConfig> {
    let doh = |octets: [u8; 4], tls_name: &str| {
        NameServerConfig::https(
            IpAddr::V4(Ipv4Addr::from(octets)),
            Arc::from(tls_name),
            Some(Arc::from(DNS_QUERY_PATH)),
        )
    };
    let dot = |octets: [u8; 4], tls_name: &str| {
        NameServerConfig::tls(IpAddr::V4(Ipv4Addr::from(octets)), Arc::from(tls_name))
    };
    match dns {
        Dns::Overseas => vec![
            doh([1, 1, 1, 1], CLOUDFLARE_DOH_NAME),
            doh([8, 8, 8, 8], GOOGLE_DOH_NAME),
            dot([1, 1, 1, 1], CLOUDFLARE_DOH_NAME),
            dot([8, 8, 8, 8], GOOGLE_DOH_NAME),
        ],
        Dns::Domestic => vec![
            doh([223, 5, 5, 5], ALIDNS_DOH_NAME),
            dot([1, 12, 12, 12], DOT_PUB_NAME),
            dot([223, 5, 5, 5], ALIDNS_DOH_NAME),
        ],
    }
}

#[derive(Clone)]
pub(crate) struct HickoryResolver {
    resolver: TokioResolver,
    dns: Dns,
}

impl HickoryResolver {
    fn build(dns: Dns) -> anyhow::Result<Arc<Self>> {
        let config = ResolverConfig::from_name_servers(name_servers(dns));
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
                anyhow::anyhow!("failed to build Hickory DNS resolver ({dns}): {error}")
            })?;
        Ok(Arc::new(Self { resolver, dns }))
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
        let dns = self.dns.to_string();
        let lookup = self
            .resolver
            .lookup_ip(fqdn.as_ref())
            .await
            .inspect_err(|error| {
                tracing::warn!(host, dns, error = %error, "upstream dns resolution failed");
            })?;
        let addresses: Vec<IpAddr> = lookup.iter().collect();
        tracing::debug!(host, dns, ?addresses, "upstream dns resolution result");
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

#[derive(Clone)]
pub(crate) struct Resolvers {
    overseas: Arc<HickoryResolver>,
    domestic: Arc<HickoryResolver>,
}

impl Resolvers {
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self {
            overseas: HickoryResolver::build(Dns::Overseas)?,
            domestic: HickoryResolver::build(Dns::Domestic)?,
        })
    }

    pub(crate) fn resolver(&self, dns: Dns) -> &Arc<HickoryResolver> {
        match dns {
            Dns::Overseas => &self.overseas,
            Dns::Domestic => &self.domestic,
        }
    }

    pub(crate) fn default_resolver(&self) -> &Arc<HickoryResolver> {
        self.resolver(Dns::Overseas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_defaults_to_overseas_and_round_trips() {
        assert_eq!(Dns::default(), Dns::Overseas);
        for dns in [Dns::Overseas, Dns::Domestic] {
            let encoded = serde_json::to_string(&dns).expect("serialize DNS");
            let decoded: Dns = serde_json::from_str(&encoded).expect("deserialize DNS");
            assert_eq!(decoded, dns);
            assert_eq!(dns.to_string().parse::<Dns>().expect("parse DNS"), dns);
        }
        assert!("unknown".parse::<Dns>().is_err());
    }

    #[test]
    fn resolver_profiles_use_only_encrypted_servers() {
        for dns in [Dns::Overseas, Dns::Domestic] {
            for server in name_servers(dns) {
                assert_eq!(server.connections.len(), 1);
                assert!(matches!(
                    server.connections[0].protocol,
                    hickory_resolver::config::ProtocolConfig::Https { .. }
                        | hickory_resolver::config::ProtocolConfig::Tls { .. }
                ));
                assert!(matches!(server.connections[0].port, 443 | 853));
            }
        }
    }
}
