//! Config tests for `[gateway.payments.xiaodou]`: fail-closed validation and
//! private-key redaction. The private key is injected only through the
//! `with_private_key` / `load_with_private_key` boundary; no test mutates
//! process-global environment variables.

use std::sync::atomic::{AtomicU64, Ordering};

use cardinal::config::Config;
use cardinal::xiaodou_pay::PlatformKeys;
use secrecy::ExposeSecret as _;

const TEST_PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDoeEGI39t6STg0
3hX697V2UDPBjSAf5Xin/KRVfmqvl75of5uK8Ygr98C9Q4yLMjQq706yE5MC8ckC
+BgIPuRyjt2CFsgk3hmLaxv7jpzodCiR4gw1Nbqr89NIr2jM1EZOjDKdlTbRaAGC
PO6DY2aOER5a55+9T70Fv0lEh1b100aTaQ5QKr0+Jy5sA+puscVvPB0O5MIzqJ3N
qvBNsz906Vz1rucZgk1WuCXPhcD/i62UZrVizjM3f4aTKo5ZKiLu7eqKYSXRD4Yg
rffDYBZZz9r7Zu8O/SAw39Jyc5i+IixdzW0raYi+Z22yEQK7oWHLiV9ZE7Sbgjhz
DgQ/h+9NAgMBAAECggEAN8LgtVw84RA/Ey9SRmi0djS2tW6MjhoU3vaS1I8GOChF
2/r/7EwTRbif2sYhKCJasRHF5qEbWlF0zemEmjW7xl7Ocy3TxEQiDHcctzJ2IKv8
L0Hxe7HvnN9Xhs/Ma5VfZ+fpHDN2erRf6EWFUK6/IsSoa1Wz000VIhPIF0//Y+dc
qJ+wmaDpmE3E8TSrw8x+hnyrqiFJDlHXhwdnnvMxT+BJx1+UPvDJcU+5tKQ7qPX2
qEXFMI46Ubg6rhJWA5LKDITVu4FRRRY50pN/6li+CgVFcQXmIL2fXN7k7pmZC2oR
cEhDafhjdoUlSHO+yluRKtnPpneFLtbxKVOy0UvuYQKBgQD7ZVMFt7enWm6h6GkC
/8fK2Ws6GuYivvcPqPnOCOEPyxnNBqHhvW3AF2PCrn/0fjhI0E/PDEkybKWCb2uW
cA+0Bp87OWy9f1fZarFUCYFxHiK6KUwhsNZW8S4/xNMuJYtubPcJtnOgsmDKeIUQ
KXmm6LH3on0o6h6K5B1lKFY7twKBgQDsujJIzVGNE2nnmK8lkbHKVUZ+ht6nBLxn
TkTDUlMHW1syAetZi2uSjf/qreOHw1np8NVpCTU5mGRNQRuH52WDX2a//Ix/JOjO
1MbLGww8tCGbcR8+3R0DcX0rzEQvG1bTZg/IIHourSwYpWbUgdTx49XNEQQNN8Vj
S2A0LgN1GwKBgQC76D6oNWxnAOdUyf1EKp/R9bV6VwTRz9+nquwdnvFq9qqwX1a8
/vR78n+00u39eCLl+h7NaieEM0V7O4E1j0mNjK2UfRXUhszJTECDyh8gyB+4+olX
XXC4x8mEDMC064dO4M++SMwgv3QtouwC6p1trtzndmMLJAP0WRHHvODH/QKBgQCY
PldAgutDs4yUqZlarAyPd7BShyKCf4U7WxbWFwfW32YTDzDw8b1JD5Hat+Jw2a3l
ykE1v/o/BEbdeFXgXWznxF8scZtZ2b7v5d/Dl62TDLXgZiwWHdYe9MnvdPsU4JxC
cI0Nw/VQN4b4gsdTO/xbZI+Hxr24UnnblgpVBJKsqQKBgQDzFgBYk96viYLGVZT0
4u7PfiesXgQ2L6pUZyj0HYh0qFUbzQOaQdRCajE9SLwa4lZ/N+s1U80EbyaKr7iO
c4pEqUJ/4e5NXgaaO8eWgd5WKnGnugUlOZQQwkdsorUagbAi6N/HAMTkiQ6vniLk
a1YBT8LPeUxHDv+cjGOAzKGcGA==
-----END PRIVATE KEY-----
"#;

// Published in 02-integration-guide.md §3.1.
const DOC_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw9Z3B6q8jsaNu3KmswGF
Kl/8Rc3dWV2yFCq61VIbuPVEQPI6S1S2gbFeWpXz6KzrdAJxTDyMqfSDnSStoesn
t6FCMjgc0SBflQOjxsM2ahNDJO4JmJGj7Mca/nFCMrvVTy4tLxFkxMUxOcXhn4LU
QPCvpoIc7Y10xHBrqVizrHwMWNPxteWsOG4ZQUbXDrYddsceTcZ3a46cBhBUyqas
lNkWwzjaw9KmrdcXWOjDT3YCyMAXkcjLBh/7gr+sb11P4PUCjeQl2F6dDASIjZmO
EXFRSQJtXSRlna+WHWgVSFtrWBdyq+Gf+5pwjXMk1PrSWIG56QKhCXKCylNz8Kwn
TQIDAQAB
-----END PUBLIC KEY-----"#;

const DOC_FINGERPRINT: &str = "c828f7e47c2eef5a958aa32009f5151bda43b585c979b40bf7c795b0b48d35f4";

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn config_toml() -> String {
    format!(
        r#"
listen = "127.0.0.1:0"
[payments.xiaodou]
base_url = "https://pay.example.com"
app_id = "xdop_1234567890abcdef"
merchant_kid = "xdop-key-2026-11"
channel = "ALIPAY_H5"
trade_scope = "CARD_VIRTUAL"
notify_url = "https://c1.iios.net/payments/webhook/xiaodou"
return_url = "https://c1.iios.net/topup/return"
usd_micros_per_cny_fen = 150000
time_expire_seconds = 1800
fee_bearer = "SELLER"

[payments.xiaodou.platform_keys.xdpk-2026-09]
pem = '''{DOC_PUBLIC_PEM}'''
fingerprint = "{DOC_FINGERPRINT}"
"#
    )
}

fn parse(raw: &str) -> Config {
    toml::from_str(raw).expect("parse config")
}

#[test]
fn xiaodou_xiaodou_config_binds_env_private_key_and_redacts_debug() {
    let config = parse(&config_toml())
        .payments
        .xiaodou
        .expect("xiaodou section")
        .with_private_key(Some(TEST_PRIVATE_PEM))
        .expect("valid config");

    let exposed = config
        .private_key()
        .expect("private key bound")
        .expose_secret();
    assert_eq!(exposed, TEST_PRIVATE_PEM);

    let debug = format!("{config:?}");
    assert!(
        !debug.contains("MIIEvwIBADANBgkq"),
        "private key leaked in Debug"
    );
    assert!(
        !debug.contains("BEGIN PRIVATE KEY"),
        "private key leaked in Debug"
    );
    assert!(
        debug.contains("REDACTED"),
        "SecretString must redact itself"
    );

    let keys: PlatformKeys = config.platform_keys().expect("platform keys");
    assert!(keys.contains("xdpk-2026-09"));
    assert!(!keys.contains(TEST_PRIVATE_PEM));
}

#[test]
fn xiaodou_missing_or_invalid_private_key_fails_closed() {
    let raw = config_toml();
    assert!(
        parse(&raw)
            .payments
            .xiaodou
            .expect("xiaodou section")
            .with_private_key(None)
            .is_err(),
        "missing private key must fail closed"
    );
    assert!(
        parse(&raw)
            .payments
            .xiaodou
            .expect("xiaodou section")
            .with_private_key(Some("not a PEM key"))
            .is_err(),
        "invalid private key must fail closed"
    );
}

#[test]
fn xiaodou_invalid_public_configuration_is_rejected() {
    let valid = config_toml();
    let cases = [
        valid.replace("channel = \"ALIPAY_H5\"", "channel = \"WECHAT_H5\""),
        valid.replace("fee_bearer = \"SELLER\"", "fee_bearer = \"BUYER\""),
        valid.replace(
            "usd_micros_per_cny_fen = 150000",
            "usd_micros_per_cny_fen = 0",
        ),
        valid.replace("time_expire_seconds = 1800", "time_expire_seconds = 299"),
        valid.replace("time_expire_seconds = 1800", "time_expire_seconds = 86401"),
        valid.replace(
            "base_url = \"https://pay.example.com\"",
            "base_url = \"http://pay.example.com\"",
        ),
        valid.replace(
            "notify_url = \"https://c1.iios.net/payments/webhook/xiaodou\"",
            "notify_url = \"https://c1.iios.net/payments/webhook/xiaodou?x=1\"",
        ),
        valid.replace(
            "notify_url = \"https://c1.iios.net/payments/webhook/xiaodou\"",
            "notify_url = \"https://c1.iios.net/\"",
        ),
        valid.replace("app_id = \"xdop_1234567890abcdef\"", "app_id = \"\""),
        valid.replace(
            DOC_FINGERPRINT,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        valid.replace("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", "broken"),
    ];
    for (index, raw) in cases.iter().enumerate() {
        let result = toml::from_str::<Config>(raw)
            .expect("TOML parses")
            .payments
            .xiaodou
            .expect("xiaodou section")
            .with_private_key(Some(TEST_PRIVATE_PEM));
        assert!(result.is_err(), "case {index} must fail closed");
    }
}

#[test]
fn xiaodou_absent_section_keeps_online_payments_disabled() {
    let config = parse("listen = \"127.0.0.1:0\"\n");
    assert!(config.payments.xiaodou.is_none());
    assert!(
        Config::default().payments.xiaodou.is_none(),
        "default config must not enable payments"
    );
}

#[test]
fn xiaodou_load_with_private_key_injects_key_without_touching_environment() {
    let unique = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "cardinal-xiaodou-config-{}-{unique}.toml",
        std::process::id()
    ));
    let raw = config_toml().replace("[payments.", "[gateway.payments.");
    std::fs::write(&path, format!("[gateway]\n{raw}")).expect("write config");
    let result = Config::load_with_private_key(&path, Some(TEST_PRIVATE_PEM));
    std::fs::remove_file(&path).expect("remove temp config");

    let config = result.expect("load config");
    let xiaodou = config.payments.xiaodou.expect("xiaodou section");
    assert_eq!(
        xiaodou.private_key().expect("injected key").expose_secret(),
        TEST_PRIVATE_PEM
    );
}
