//! Golden-vector tests for the Xiaodou protocol.
//!
//! The published Xiaodou docs define the three canonical-string layouts and
//! the platform public key/fingerprint, but the `examples/` directory holding
//! A1/A6 reference vectors is not part of the supplied docs. The signature
//! vectors below were generated locally with openssl from a throwaway
//! 2048-bit test key; they pin our RSA2 encoding against an independent
//! implementation, not against a published Xiaodou value.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cardinal::xiaodou_pay::{
    PlatformKeys, ProtocolError, RequestFields, ResponseFields, ResponseHeaders,
    ResponseVerification, SigningKey, VerifyError, WEBHOOK_SUCCESS_BODY, WebhookEventType,
    WebhookFields, WebhookHeaders, canonical_request, canonical_response, canonical_webhook,
    fingerprint_public_key_pem, generate_nonce, verify_response, verify_webhook,
};
use secrecy::SecretString;

const TEST_KID: &str = "xdpk-test";

// Throwaway test key generated with:
// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
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

const TEST_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6HhBiN/bekk4NN4V+ve1
dlAzwY0gH+V4p/ykVX5qr5e+aH+bivGIK/fAvUOMizI0Ku9OshOTAvHJAvgYCD7k
co7dghbIJN4Zi2sb+46c6HQokeIMNTW6q/PTSK9ozNRGTowynZU20WgBgjzug2Nm
jhEeWuefvU+9Bb9JRIdW9dNGk2kOUCq9PicubAPqbrHFbzwdDuTCM6idzarwTbM/
dOlc9a7nGYJNVrglz4XA/4utlGa1Ys4zN3+GkyqOWSoi7u3qimEl0Q+GIK33w2AW
Wc/a+2bvDv0gMN/ScnOYviIsXc1tK2mIvmdtshECu6Fhy4lfWRO0m4I4cw4EP4fv
TQIDAQAB
-----END PUBLIC KEY-----
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

const REQUEST_BODY: &[u8] = br#"{"amountFen":100}"#;
const RESPONSE_BODY: &[u8] =
    br#"{"requestId":"req_0123456789","outTradeNo":"XD20261120001","status":"SUCCEEDED"}"#;
const WEBHOOK_BODY: &[u8] =
    br#"{"eventId":"evt_0123456789","eventType":"PAYMENT_SUCCEEDED","grossAmountFen":100}"#;

const FULL_WEBHOOK_BODY: &[u8] = br#"{"eventId":"evt_0123456789","eventType":"PAYMENT_SUCCEEDED","appId":"xdop_1234567890abcdef","outTradeNo":"XD20261120001","outRefundNo":null,"eventAmountFen":100,"grossAmountFen":100,"feeBearer":"SELLER","merchantAmountFen":100,"feeAmountFen":0,"status":"SUCCEEDED","reason":"","occurredAt":1763664002,"stateVersion":0,"attach":"","feeProjection":{"ruleVersion":"v1"}}"#;

// openssl dgst -sha256 -sign <throwaway key> over each canonical string below.
const REQUEST_SIGNATURE: &str = "F5Hh9aWfX0H1gfluoOp+P7UakuztrcapiMTFqgKTSafZDhkOC4bKy4jdme0yH5ylOoYjK1degwC08s8Zvl6hehzQXhR/vLX9YVqUZLi+B5aXflRN3R1JxbdW6mDTjOboGVuE5nZsgu9MiADzQeSL5nUctf+RjUpOcFHTwJGa/58JwDp2fxdi82plXAqftcTWz76ULHsZRiQjhardgd9HTK+VNmhePZr83omYbmXiwYJud0utiMUgbOXS+1YGFEHTYFPJr112UYgjAfYzJNY+M5Vc1x1I6u1vSSJMYVU4e/KI/AbzwsFJGgDA7dqW1rVXUy9/lch240ld4VAB9UzrtA==";
const RESPONSE_SIGNATURE: &str = "NoWj+83jJ78jnHm1kbdPBoCcdTeS/eAF29AEjaaRx4hD75zjXeqaSX5tSUe4b4iPG3QvHZN9cXenuAMu4tbaN8FhrCi8hofQBFESPTm++hVnli9vETuRguC8jUxCykDo4syVAvIXI2umQkmNlnWKSlaXefdTiXoe2muLNVm5pR/e+nv26nknzDLPAfQNh+rX9ei3p+GSAC2EJjTHt75SzTwYupojVEEOwwbRa7xHeBi6OPhvBizva4ErG+TFVlanPJ8LmBQGdrh95YdgYSzKVAk/IfM/9Zm5TBYtkPuW1F5N5+7L7y5oNQX7ARVce8uwMi8j8BDZJp6mHPLjcLcNvw==";
const WEBHOOK_SIGNATURE: &str = "MmpoI62wMQ3l269FT4Yg34LIG5jup3aU3pdrgbXriPGorlFKmUAjjNvacQAOLzXo60rGMHRarFv36hIVItfaAT7knXh4ijA1+upEw9mKrrYPbWq4BcebA6k3yln03lyuhUl+b3cx1/utF8frjuGKggKfwrU9pafWNBSWYcNwgy9pxMn8FIT5vgtelR9RUjZWIVv5JHnY0MInwQc73ysTSlhj6XA++lULwlKHwRkeDhRWbwyjfeHpJ75r3xaT7CsBswH9xTngDJ+8KLCfoKY5HmB4jG0oQiyrTVWXeJ5taZoa7fAYbl0LgHt6IIm06nCsTvfRo1AmIWK6opblzvsx0w==";
const FULL_WEBHOOK_SIGNATURE: &str = "4hAfnSvnz6/qtDTjidObcLQIUCwaFm3sGyjQWK0XMx59ftbcQ3SFYrYsVCiusaTHp1USomaAPIp1IzGANg+yLDfne+0GRjntJmBWNY17z/IgJcKYKe59d822ZjKjouz0V3VbKkylb7+BOBtULb4MDH2JRUinGG4ti75FpN1+hZUnLx/gxqHIZvjaSRUvBpFUlxSnrDzia3R1xt7m5DhNyjcTBCBaG9qHVJ8nADqOWrPBnmQCZBzBBECaPPVMyYqWz7J0QDEKXZt7vpqU3ojhP/Al8mr8O5vN2AFcpR0SWNwhr8jDUExU+6RGzcs82fnWxk7EJ9Arhiy7mvi3kE0PSQ==";
const ROTATED_WEBHOOK_SIGNATURE: &str = "4gipT6jqZsP+W+llNyZWAIVWud8Lcrbg4NSJvLLg01qs/uTFLc2ADKD4cqxgDrEBHlmT0fH206m3Xp2QC/xDK9lRyRliFTnXDF+XluUo6sHQGHUleDmuOmwhLdogSXFU8N8itp/sR/769JFlYTR8IopJ2i79zoAztEVOZ+pv57gzTuhXSP5BdwtZNA0G1gDLbNqINalMVyWB3ImuYuhXCdmm9k57EuOknRf4vxcVizxRVEY2cDmnNs9L6eseOr8bMBtwNKNOIwFEHDG+w6DzWRcBA6Z0oCq4YNk/amKOl3CFVRCI9+MsJMpjhxZFS3tRj/lXRjZxtdp6PG+0m+PNKQ==";

fn test_keys() -> PlatformKeys {
    let fingerprint = fingerprint_of(TEST_PUBLIC_PEM);
    PlatformKeys::from_entries([(TEST_KID, TEST_PUBLIC_PEM, fingerprint.as_str())])
        .expect("test platform key")
}

fn response_input<'a>(headers: Option<ResponseHeaders<'a>>) -> ResponseVerification<'a> {
    ResponseVerification {
        status: 201,
        content_type: Some("application/json"),
        request_id: "req_0123456789",
        raw_body: RESPONSE_BODY,
        headers,
    }
}

fn fingerprint_of(pem: &str) -> String {
    fingerprint_public_key_pem(pem)
}

fn request_fields() -> RequestFields<'static> {
    RequestFields {
        method: "POST",
        path: "/api/open/v1/payments",
        query: "b=%E4%B8%AD&a=1&a=0",
        timestamp: "1763664000",
        nonce: "nonce1234567890ab",
        app_id: "xdop_1234567890abcdef",
        key_id: "test-key",
        request_id: "req_0123456789",
        content_type: Some("application/json; charset=utf-8"),
        raw_body: REQUEST_BODY,
    }
}

fn response_headers() -> ResponseHeaders<'static> {
    ResponseHeaders {
        sign: RESPONSE_SIGNATURE,
        key_id: TEST_KID,
        timestamp: "1763664001",
        nonce: "respnonce0123456",
    }
}

fn webhook_headers(signature: &'static str) -> WebhookHeaders<'static> {
    WebhookHeaders {
        sign: signature,
        key_id: TEST_KID,
        timestamp: "1763664002",
        nonce: "webhooknonce0123",
        event_id: "evt_0123456789",
        event_type: "PAYMENT_SUCCEEDED",
    }
}

#[test]
fn xiaodou_request_canonical_string_is_eleven_lines_with_rfc3986_query() {
    let canonical = canonical_request(&request_fields()).expect("canonical request");
    assert_eq!(
        canonical,
        concat!(
            "XD-Signature-v1\n",
            "POST\n",
            "/api/open/v1/payments\n",
            "a=1&a=0&b=%E4%B8%AD\n",
            "1763664000\n",
            "nonce1234567890ab\n",
            "xdop_1234567890abcdef\n",
            "test-key\n",
            "req_0123456789\n",
            "application/json\n",
            "fb41bcc04966867cd3afc24abc2ba01cf45a56dc53bf7bc1aeb2c4838365e361",
        )
    );
}

#[test]
fn xiaodou_request_canonical_string_keeps_empty_lines_for_empty_query_and_no_content_type() {
    let mut fields = request_fields();
    fields.query = "";
    fields.content_type = None;
    let canonical = canonical_request(&fields).expect("canonical request");
    let lines: Vec<&str> = canonical.split('\n').collect();
    assert_eq!(lines.len(), 11, "the spec requires exactly eleven lines");
    assert_eq!(lines[3], "", "empty query must still be its own line");
    assert_eq!(lines[9], "", "no content-type header must be an empty line");
}

#[test]
fn xiaodou_request_canonical_string_rejects_unsafe_paths() {
    for path in ["/api/../payments", "/api//payments", "/api\\payments"] {
        let mut fields = request_fields();
        fields.path = path;
        assert_eq!(
            canonical_request(&fields),
            Err(ProtocolError::InvalidPath),
            "path {path} must be rejected"
        );
    }
}

#[test]
fn xiaodou_published_platform_key_fingerprint_is_recomputed_exactly() {
    assert_eq!(fingerprint_of(DOC_PUBLIC_PEM), DOC_FINGERPRINT);
}

#[test]
fn xiaodou_request_signature_matches_independent_golden_value() {
    let canonical = canonical_request(&request_fields()).expect("canonical request");
    let secret = SecretString::from(TEST_PRIVATE_PEM.to_owned());
    let signer = SigningKey::from_secret(&secret).expect("test signing key");
    let signature = signer.sign(&canonical).expect("signature");
    assert_eq!(signature, REQUEST_SIGNATURE);
    assert_eq!(
        BASE64.decode(&signature).expect("base64 signature").len(),
        256,
        "RSA-2048 signature must be 256 bytes"
    );
}

#[test]
fn xiaodou_response_canonical_string_normalizes_content_type_and_verifies_golden_signature() {
    let fields = ResponseFields {
        status: 201,
        content_type: Some("Application/JSON; charset=utf-8"),
        request_id: "req_0123456789",
        timestamp: "1763664001",
        nonce: "respnonce0123456",
        key_id: TEST_KID,
        raw_body: RESPONSE_BODY,
    };
    let canonical = canonical_response(&fields).expect("canonical response");
    assert_eq!(
        canonical,
        concat!(
            "XD-Response-v1\n",
            "201\n",
            "application/json\n",
            "req_0123456789\n",
            "1763664001\n",
            "respnonce0123456\n",
            "xdpk-test\n",
            "73dbaeacd5046570d56ab5d9668300728f270c91feef06bb0a7ecbd0cccce8a7",
        )
    );
    let input = ResponseVerification {
        status: 201,
        content_type: Some("Application/JSON; charset=utf-8"),
        request_id: "req_0123456789",
        raw_body: RESPONSE_BODY,
        headers: Some(response_headers()),
    };
    verify_response(&input, &test_keys(), 1_763_664_100, 300).expect("golden response");
}

#[test]
fn xiaodou_response_verification_classifies_missing_headers_stale_time_and_unknown_kid() {
    let keys = test_keys();
    assert_eq!(
        verify_response(&response_input(None), &keys, 1_763_664_100, 300),
        Err(VerifyError::MissingHeaders {
            missing: vec![
                "X-XD-Response-Sign",
                "X-XD-Response-Key-Id",
                "X-XD-Response-Timestamp",
                "X-XD-Response-Nonce"
            ]
        })
    );

    let mut headers = response_headers();
    headers.nonce = "";
    assert_eq!(
        verify_response(&response_input(Some(headers)), &keys, 1_763_664_100, 300),
        Err(VerifyError::MissingHeaders {
            missing: vec!["X-XD-Response-Nonce"]
        })
    );

    let headers = response_headers();
    assert_eq!(
        verify_response(&response_input(Some(headers)), &keys, 1_763_664_500, 300),
        Err(VerifyError::TimestampOutsideWindow)
    );

    let mut headers = response_headers();
    headers.key_id = "xdpk-rotated-out";
    assert_eq!(
        verify_response(&response_input(Some(headers)), &keys, 1_763_664_100, 300),
        Err(VerifyError::UnknownKeyId)
    );

    let mut headers = response_headers();
    headers.timestamp = "not-a-timestamp";
    assert_eq!(
        verify_response(&response_input(Some(headers)), &keys, 1_763_664_100, 300),
        Err(VerifyError::InvalidHeader("X-XD-Response-Timestamp"))
    );

    let tampered =
        br#"{"requestId":"req_0123456789","outTradeNo":"XD20261120002","status":"SUCCEEDED"}"#;
    assert_eq!(
        verify_response(
            &ResponseVerification {
                status: 201,
                content_type: Some("application/json"),
                request_id: "req_0123456789",
                raw_body: tampered,
                headers: Some(response_headers()),
            },
            &keys,
            1_763_664_100,
            300
        ),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn xiaodou_webhook_canonical_string_is_seven_lines_over_raw_bytes() {
    let canonical = canonical_webhook(&WebhookFields {
        event_id: "evt_0123456789",
        event_type: "PAYMENT_SUCCEEDED",
        timestamp: "1763664002",
        nonce: "webhooknonce0123",
        key_id: TEST_KID,
        raw_body: WEBHOOK_BODY,
    })
    .expect("canonical webhook");
    assert_eq!(
        canonical,
        concat!(
            "XD-Webhook-v1\n",
            "evt_0123456789\n",
            "PAYMENT_SUCCEEDED\n",
            "1763664002\n",
            "webhooknonce0123\n",
            "xdpk-test\n",
            "b9d13a931b1b44b48bf2581b4515a63dff3ea47eee61f985bfb0aebce3e40405",
        )
    );
    test_keys()
        .verify(TEST_KID, &canonical, WEBHOOK_SIGNATURE)
        .expect("minimal webhook golden signature");
}

#[test]
fn xiaodou_webhook_golden_signature_verifies_over_raw_body_and_parses_typed_event() {
    let event = verify_webhook(
        FULL_WEBHOOK_BODY,
        webhook_headers(FULL_WEBHOOK_SIGNATURE),
        &test_keys(),
        1_763_664_100,
        300,
    )
    .expect("golden webhook");
    assert_eq!(event.event_id, "evt_0123456789");
    assert_eq!(event.event_type, WebhookEventType::PaymentSucceeded);
    assert_eq!(event.out_trade_no, "XD20261120001");
    assert_eq!(event.gross_amount_fen, 100);
    assert_eq!(event.event_amount_fen, 100);
    assert_eq!(event.fee_bearer, "SELLER");
    assert_eq!(
        event.state_version, 0,
        "stateVersion is not a freshness signal"
    );
    assert_eq!(event.nonce, "webhooknonce0123");
    assert_eq!(WEBHOOK_SUCCESS_BODY, b"success");
}

#[test]
fn xiaodou_webhook_verification_uses_received_bytes_not_reserialized_json() {
    let mut reordered = FULL_WEBHOOK_BODY.to_vec();
    reordered.push(b' ');
    assert_eq!(
        verify_webhook(
            &reordered,
            webhook_headers(FULL_WEBHOOK_SIGNATURE),
            &test_keys(),
            1_763_664_100,
            300
        ),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn xiaodou_webhook_verification_distinguishes_missing_headers_time_and_key_rotation() {
    let keys = test_keys();
    let verify = |headers, keys: &PlatformKeys, now| {
        verify_webhook(FULL_WEBHOOK_BODY, headers, keys, now, 300).map(|_| ())
    };
    assert_eq!(
        verify(webhook_headers(""), &keys, 1_763_664_100),
        Err(VerifyError::MissingHeaders {
            missing: vec!["X-XD-Webhook-Signature"]
        })
    );
    let mut headers = webhook_headers(FULL_WEBHOOK_SIGNATURE);
    headers.event_type = "";
    assert_eq!(
        verify(headers, &keys, 1_763_664_100),
        Err(VerifyError::MissingHeaders {
            missing: vec!["X-XD-Webhook-Event-Type"]
        })
    );
    assert_eq!(
        verify(
            webhook_headers(FULL_WEBHOOK_SIGNATURE),
            &keys,
            1_763_664_900
        ),
        Err(VerifyError::TimestampOutsideWindow)
    );
    let mut headers = webhook_headers(FULL_WEBHOOK_SIGNATURE);
    headers.nonce = "short";
    assert_eq!(
        verify(headers, &keys, 1_763_664_100),
        Err(VerifyError::InvalidHeader("X-XD-Webhook-Nonce"))
    );
    let mut headers = webhook_headers(FULL_WEBHOOK_SIGNATURE);
    headers.key_id = "xdpk-2027-01";
    assert_eq!(
        verify(headers, &keys, 1_763_664_100),
        Err(VerifyError::UnknownKeyId)
    );

    let fingerprint = fingerprint_of(TEST_PUBLIC_PEM);
    let rotated = PlatformKeys::from_entries([
        (TEST_KID, TEST_PUBLIC_PEM, fingerprint.as_str()),
        ("xdpk-2027-01", TEST_PUBLIC_PEM, fingerprint.as_str()),
    ])
    .expect("rotated keys");
    let mut headers = webhook_headers(ROTATED_WEBHOOK_SIGNATURE);
    headers.key_id = "xdpk-2027-01";
    verify(headers, &rotated, 1_763_664_100).expect("rotated kid verifies");
}

#[test]
fn xiaodou_generated_nonce_is_visible_ascii_within_documented_lengths() {
    let nonce = generate_nonce().expect("random nonce");
    assert!((16..=64).contains(&nonce.len()), "nonce length: {nonce}");
    assert!(
        nonce.bytes().all(|byte| (b'!'..=b'~').contains(&byte)),
        "nonce must be visible ASCII"
    );
}
