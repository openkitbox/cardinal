//! Portal challenge mail. HTTP and SMTP share one renderer so a link is byte
//! identical across transports; neither transport logs addresses or credentials.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use lettre::AsyncTransport;
use lettre::Message;
use lettre::Tokio1Executor;
use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use reqwest::{Client, Url};
use secrecy::SecretString;
use serde::Serialize;

use crate::config::PortalMailConfig;
use crate::store::PortalSettingsRow;

pub(crate) struct Mailer {
    transport: Transport,
    origin: Url,
    from: String,
}

enum Transport {
    Http {
        client: Client,
        url: Url,
        token: SecretString,
    },
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MailKind {
    Registration,
    PasswordReset,
}

/// The complete rendered message. Shared by both transports and by tests that
/// must prove the wire bodies stay identical.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ComposedMessage {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) subject: &'static str,
    pub(crate) text: String,
    pub(crate) link: String,
}

#[derive(Serialize)]
struct HttpMessage<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'static str,
    text: String,
}

impl Mailer {
    /// Select a transport from DB settings. Incomplete or invalid settings
    /// disable delivery instead of failing gateway startup or reload.
    pub(crate) async fn from_settings(settings: &PortalSettingsRow) -> Option<Self> {
        match settings.mail_transport.as_str() {
            "http" => {
                let config = PortalMailConfig {
                    url: settings.mail_url.clone(),
                    token: settings.mail_token.clone(),
                    from: settings.mail_from.clone(),
                    origin: settings.mail_origin.clone(),
                };
                Self::new_http(&config).await
            }
            "smtp" => Self::new_smtp(settings).await,
            other => {
                tracing::warn!(transport = other, "unsupported portal mail transport");
                None
            }
        }
    }

    async fn new_http(config: &PortalMailConfig) -> Option<Self> {
        let (url, origin) = match validate_http(config) {
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
            transport: Transport::Http {
                client,
                url,
                token: config.token.clone().into(),
            },
            origin,
            from: config.from.clone(),
        })
    }

    async fn new_smtp(settings: &PortalSettingsRow) -> Option<Self> {
        let origin = Url::parse(&settings.mail_origin).ok()?;
        let from = settings.smtp_from.trim();
        let host = settings.smtp_host.trim();
        let port = u16::try_from(settings.smtp_port)
            .ok()
            .filter(|port| *port > 0)?;
        if !usable_url(&origin)
            || (origin.path() != "" && origin.path() != "/")
            || host.is_empty()
            || host.eq_ignore_ascii_case("localhost")
            || host.chars().any(char::is_control)
            || from.is_empty()
            || from.chars().any(char::is_control)
            || from.parse::<Mailbox>().is_err()
            || settings.smtp_username.is_empty()
            || settings.smtp_password.is_empty()
            || settings.smtp_password.chars().any(char::is_control)
        {
            return None;
        }
        // Connect to a validated literal address: loopback is allowed only as
        // an explicit IP for the local E2E sink, every other address must be
        // global unicast. DNS names are resolved once and pinned, while TLS
        // parameters keep the configured hostname for SNI and certificate
        // verification, so there is no re-resolution/TOCTOU gap.
        let target = match host.parse::<IpAddr>() {
            Ok(address) if address.is_loopback() => address,
            Ok(address) if crate::upstream::transport::is_global_unicast(address) => address,
            Ok(_) => {
                tracing::warn!("portal SMTP host is not an allowed destination");
                return None;
            }
            Err(_) => {
                let resolvers = match crate::upstream::dns::Resolvers::new() {
                    Ok(resolvers) => resolvers,
                    Err(_) => {
                        tracing::error!("portal SMTP DNS resolver could not be initialized");
                        return None;
                    }
                };
                let addresses = match resolvers.default_resolver().resolve_all(host).await {
                    Ok(addresses) if mail_destination_addresses_allowed(&addresses) => addresses,
                    Ok(_) => {
                        tracing::warn!("portal SMTP host resolved to a disallowed address");
                        return None;
                    }
                    Err(_) => {
                        tracing::warn!("portal SMTP host could not be resolved; delivery disabled");
                        return None;
                    }
                };
                addresses[0]
            }
        };
        let tls = match settings.smtp_tls.as_str() {
            "none" => Tls::None,
            "starttls" => Tls::Required(TlsParameters::new(host.to_owned()).ok()?),
            "tls" => Tls::Wrapper(TlsParameters::new(host.to_owned()).ok()?),
            _ => return None,
        };
        let credentials = Credentials::new(
            settings.smtp_username.clone(),
            settings.smtp_password.clone(),
        );
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(target.to_string())
            .port(port)
            .timeout(Some(Duration::from_secs(10)))
            .credentials(credentials)
            .tls(tls)
            .build();
        Some(Self {
            transport: Transport::Smtp(transport),
            origin,
            from: from.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn compose(&self, kind: MailKind, email: &str, fragment: &str) -> ComposedMessage {
        render_message(kind, &self.origin, &self.from, email, fragment)
    }

    pub(crate) async fn send(&self, kind: MailKind, email: &str, fragment: &str) {
        use secrecy::ExposeSecret as _;

        let message = render_message(kind, &self.origin, &self.from, email, fragment);
        match &self.transport {
            Transport::Http { client, url, token } => {
                let body = HttpMessage {
                    from: &message.from,
                    to: [&message.to],
                    subject: message.subject,
                    text: message.text,
                };
                let result = client
                    .post(url.clone())
                    .bearer_auth(token.expose_secret())
                    .json(&body)
                    .send()
                    .await;
                match result {
                    Ok(response) if response.status().is_success() => {}
                    Ok(response) => {
                        tracing::warn!(status = %response.status(), "portal mail rejected")
                    }
                    Err(error) => {
                        tracing::warn!(timeout = error.is_timeout(), "portal mail request failed")
                    }
                }
            }
            Transport::Smtp(transport) => {
                let (Some(from), Some(to)) = (
                    message.from.parse::<Mailbox>().ok(),
                    message.to.parse::<Mailbox>().ok(),
                ) else {
                    tracing::warn!("portal mail address could not be parsed");
                    return;
                };
                let built = Message::builder()
                    .from(from)
                    .to(to)
                    .subject(message.subject)
                    .body(message.text);
                let Ok(built) = built else {
                    tracing::warn!("portal mail message could not be built");
                    return;
                };
                if transport.send(built).await.is_err() {
                    tracing::warn!("portal SMTP delivery failed");
                }
            }
        }
    }
}

/// One renderer for both transports: the link and every body byte are the
/// same, no matter which way the challenge is delivered.
fn render_message(
    kind: MailKind,
    origin: &Url,
    from: &str,
    email: &str,
    fragment: &str,
) -> ComposedMessage {
    let (path, subject) = match kind {
        MailKind::Registration => ("/register/verify", "Verify your Cardinal account"),
        MailKind::PasswordReset => ("/reset-password", "Reset your Cardinal password"),
    };
    let mut link = origin.clone();
    link.set_path(path);
    link.set_fragment(Some(&format!("token={fragment}")));
    ComposedMessage {
        from: from.to_owned(),
        to: email.to_owned(),
        subject,
        text: format!("Use this link to continue: {link}"),
        link: link.to_string(),
    }
}

fn validate_http(config: &PortalMailConfig) -> Option<(Url, Url)> {
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
    use std::time::Duration;

    use super::{MailKind, Mailer, mail_destination_addresses_allowed, usable_url};
    use crate::store::PortalSettingsRow;
    use jiff::Timestamp;
    use reqwest::Url;

    fn settings(transport: &str) -> PortalSettingsRow {
        PortalSettingsRow {
            mail_transport: transport.to_owned(),
            mail_url: "http://127.0.0.1:9/emails".to_owned(),
            mail_token: "mail-token".to_owned(),
            mail_from: "Cardinal <auth@example.com>".to_owned(),
            mail_origin: "https://portal.example.com".to_owned(),
            smtp_host: "127.0.0.1".to_owned(),
            smtp_port: 9,
            smtp_username: "smtp-user".to_owned(),
            smtp_password: "smtp-password".to_owned(),
            smtp_tls: "none".to_owned(),
            smtp_from: "Cardinal <auth@example.com>".to_owned(),
            updated_at: Timestamp::now(),
        }
    }

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

    #[tokio::test]
    async fn account_mail_transports_render_identical_links_and_bodies() {
        let http = Mailer::from_settings(&settings("http"))
            .await
            .expect("HTTP settings should build a mailer");
        let smtp = Mailer::from_settings(&settings("smtp"))
            .await
            .expect("SMTP settings should build a mailer");
        for (kind, path, subject) in [
            (
                MailKind::Registration,
                "/register/verify",
                "Verify your Cardinal account",
            ),
            (
                MailKind::PasswordReset,
                "/reset-password",
                "Reset your Cardinal password",
            ),
        ] {
            let fragment = "fragment-with-43-characters-aaaaaaaaaaaaaa";
            let via_http = http.compose(kind, "alice@example.com", fragment);
            let via_smtp = smtp.compose(kind, "alice@example.com", fragment);
            assert_eq!(via_http, via_smtp);
            assert_eq!(via_http.subject, subject);
            assert_eq!(
                via_http.link,
                format!("https://portal.example.com{path}#token={fragment}")
            );
            assert_eq!(
                via_http.text,
                format!("Use this link to continue: {}", via_http.link)
            );
        }
    }

    #[tokio::test]
    async fn account_mail_incomplete_settings_disable_delivery() {
        let mut config = settings("smtp");
        for bad in [
            PortalSettingsRow {
                smtp_host: String::new(),
                ..config.clone()
            },
            PortalSettingsRow {
                smtp_port: 0,
                ..config.clone()
            },
            PortalSettingsRow {
                smtp_tls: "implicit".to_owned(),
                ..config.clone()
            },
            PortalSettingsRow {
                smtp_password: String::new(),
                ..config.clone()
            },
            PortalSettingsRow {
                mail_origin: String::new(),
                ..config.clone()
            },
        ] {
            assert!(Mailer::from_settings(&bad).await.is_none());
        }
        config.mail_transport = "http".to_owned();
        config.mail_token.clear();
        assert!(Mailer::from_settings(&config).await.is_none());
        config.mail_transport = "carrier-pigeon".to_owned();
        assert!(Mailer::from_settings(&config).await.is_none());
    }

    #[tokio::test]
    async fn account_mail_rejects_private_and_link_local_smtp_hosts() {
        for host in ["10.0.0.1", "169.254.169.254", "localhost"] {
            let bad = PortalSettingsRow {
                smtp_host: host.to_owned(),
                ..settings("smtp")
            };
            assert!(
                Mailer::from_settings(&bad).await.is_none(),
                "SMTP host must be rejected: {host}"
            );
        }
        assert!(
            Mailer::from_settings(&settings("smtp")).await.is_some(),
            "literal loopback SMTP sink must still work"
        );
    }

    #[tokio::test]
    async fn account_mail_failed_transport_does_not_panic() {
        let mailer = Mailer::from_settings(&settings("smtp"))
            .await
            .expect("loopback SMTP settings should build a mailer");
        tokio::time::timeout(
            Duration::from_secs(5),
            mailer.send(MailKind::Registration, "alice@example.com", "fragment"),
        )
        .await
        .expect("SMTP delivery to a closed port must finish promptly");
    }
}
