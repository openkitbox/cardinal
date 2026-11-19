//! One transactional HTTP mail transport; never logs addresses or credentials.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::{Client, Url};
use serde::Serialize;

use crate::config::PortalMailConfig;

pub(crate) struct Mailer {
    client: Client,
    url: Url,
    token: secrecy::SecretString,
    from: String,
    origin: Url,
}

#[derive(Clone, Copy)]
pub(crate) enum MailKind {
    Registration,
    PasswordReset,
}

#[derive(Serialize)]
struct Message<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'static str,
    text: String,
}

impl Mailer {
    pub(crate) async fn new(config: &PortalMailConfig) -> Option<Self> {
        let (url, origin) = match validate(config) {
            Some(urls) => urls,
            None => {
                tracing::warn!("invalid portal mail configuration; delivery disabled");
                return None;
            }
        };
        let mut builder = Client::builder().redirect(reqwest::redirect::Policy::none());
        if url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| host.parse::<IpAddr>().is_err())
        {
            let host = url.host_str()?;
            let resolvers = match crate::upstream::dns::Resolvers::new() {
                Ok(resolvers) => resolvers,
                Err(_) => {
                    tracing::error!("portal mail DNS resolver could not be initialized");
                    return None;
                }
            };
            let addresses = match resolvers.default_resolver().resolve_all(host).await {
                Ok(addresses) if mail_destination_addresses_allowed(&addresses) => addresses,
                Ok(_) => {
                    tracing::warn!("portal mail host resolved to a disallowed address");
                    return None;
                }
                Err(_) => {
                    tracing::warn!("portal mail host could not be resolved; delivery disabled");
                    return None;
                }
            };
            let sockets: Vec<SocketAddr> = addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, 0))
                .collect();
            builder = builder.resolve_to_addrs(host, &sockets);
        }
        let client = builder
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| tracing::error!("portal mail transport could not be initialized"))
            .ok()?;
        Some(Self {
            client,
            url,
            token: config.token.clone().into(),
            from: config.from.clone(),
            origin,
        })
    }

    pub(crate) async fn send(&self, kind: MailKind, email: &str, fragment: &str) {
        use secrecy::ExposeSecret as _;

        let (path, subject) = match kind {
            MailKind::Registration => ("/register/verify", "Verify your Cardinal account"),
            MailKind::PasswordReset => ("/reset-password", "Reset your Cardinal password"),
        };
        let mut link = self.origin.clone();
        link.set_path(path);
        link.set_fragment(Some(&format!("token={fragment}")));
        let message = Message {
            from: &self.from,
            to: [email],
            subject,
            text: format!("Use this link to continue: {link}"),
        };
        let result = self
            .client
            .post(self.url.clone())
            .bearer_auth(self.token.expose_secret())
            .json(&message)
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => tracing::warn!(status = %response.status(), "portal mail rejected"),
            Err(error) => {
                tracing::warn!(timeout = error.is_timeout(), "portal mail request failed")
            }
        }
    }
}

fn validate(config: &PortalMailConfig) -> Option<(Url, Url)> {
    let url = Url::parse(&config.url).ok()?;
    let origin = Url::parse(&config.origin).ok()?;
    if !usable_url(&url)
        || !usable_url(&origin)
        || (origin.path() != "" && origin.path() != "/")
        || config.token.is_empty()
        || !config.token.bytes().all(|byte| byte.is_ascii_graphic())
        || config.from.trim().is_empty()
        || config.from.chars().any(char::is_control)
    {
        return None;
    }
    Some((url, origin))
}

fn usable_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }

    let host = host.trim_matches(['[', ']']);
    let allowed_scheme = match url.scheme() {
        "https" => host
            .parse::<IpAddr>()
            .map_or(true, crate::upstream::transport::is_global_unicast),
        // Plaintext is permitted only for local mail mocks and local development.
        "http" => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        _ => false,
    };

    // HTTPS DNS names are resolved once at startup, every answer must be globally
    // routable, and the client pins those answers. This prevents DNS rebinding
    // between requests while retaining the configured hostname for TLS/SNI.
    allowed_scheme
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn mail_destination_addresses_allowed(addresses: &[IpAddr]) -> bool {
    !addresses.is_empty()
        && addresses
            .iter()
            .copied()
            .all(crate::upstream::transport::is_global_unicast)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{mail_destination_addresses_allowed, usable_url};
    use reqwest::Url;

    #[test]
    fn rejects_empty_or_private_mail_dns_answers() {
        for addresses in [
            vec![],
            vec![IpAddr::from([10, 0, 0, 1])],
            vec![
                IpAddr::from([93, 184, 216, 34]),
                IpAddr::from([169, 254, 169, 254]),
            ],
            vec!["::ffff:169.254.169.254".parse().expect("test IPv6 address")],
            vec!["2001:db8::1".parse().expect("test IPv6 address")],
        ] {
            assert!(
                !mail_destination_addresses_allowed(&addresses),
                "DNS answers should be rejected: {addresses:?}"
            );
        }
    }

    #[test]
    fn accepts_public_mail_dns_answers() {
        let addresses = [
            IpAddr::from([93, 184, 216, 34]),
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse()
                .expect("test IPv6 address"),
        ];
        assert!(
            mail_destination_addresses_allowed(&addresses),
            "public DNS answers should be accepted: {addresses:?}"
        );
    }

    #[test]
    fn rejects_localhost_and_non_global_https_ip_literals() {
        for raw_url in [
            "https://localhost/mail",
            "https://127.0.0.1/mail",
            "https://10.0.0.1/mail",
            "https://169.254.1.1/mail",
            "https://0.0.0.0/mail",
            "https://224.0.0.1/mail",
            "https://100.64.0.1/mail",
            "https://192.0.0.9/mail",
            "https://192.0.2.1/mail",
            "https://198.18.0.1/mail",
            "https://198.51.100.1/mail",
            "https://203.0.113.1/mail",
            "https://[::1]/mail",
            "https://[::]/mail",
            "https://[ff02::1]/mail",
            "https://[2001:db8::1]/mail",
            "https://[2001:2::1]/mail",
            "https://[3fff::1]/mail",
        ] {
            let url = Url::parse(raw_url).expect("test URL should parse");
            assert!(!usable_url(&url), "URL should be rejected: {raw_url}");
        }
    }

    #[test]
    fn accepts_public_https_and_loopback_http_urls() {
        for raw_url in [
            "https://mail.example.com/send",
            "https://93.184.216.34/send",
            "http://127.0.0.1:8080/send",
            "http://[::1]:8080/send",
        ] {
            let url = Url::parse(raw_url).expect("test URL should parse");
            assert!(usable_url(&url), "URL should be accepted: {raw_url}");
        }
    }
}
