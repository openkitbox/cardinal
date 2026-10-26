#!/usr/bin/env python3
"""One-shot import of one Kiro account's OAuth bundle through the admin API.

The vendor export is not the credential shape cardinal stores, so this tool is
the one bridge between them — and it is a whitelist by construction. It reads
exactly ``accounts[i].credentials.{clientId,clientSecret,refreshToken,
accessToken,expiresAt,region}`` and ``accounts[i].profileArn``; the account's
password, email, csrfToken, machineId, nickname, usage and subscription are
never extracted, never sent, and never printed.

The export carries millisecond ``expiresAt`` and an account-level
``profileArn``; the stored bundle (``kiro::KiroOAuth``, migrations/0007) is
camelCase with a Unix-seconds expiry, and ``authRegion``/``apiRegion`` are the
credential's single region. The conversion happens here, with integer
division so no float rounding can land the token one second off.

Rows are written through the existing admin API only — there is no import
endpoint:

- ``GET /api/providers`` then ``POST /api/providers`` (absent) or
  ``PATCH /api/providers/{id}`` (present, and only when it already speaks
  ``protocol=kiro``; a foreign protocol is never converted). The PATCH is
  applied after the key write so a refused credential leaves it untouched.
- ``GET /api/providers/{id}/keys`` then ``POST .../keys`` (absent) or
  ``PATCH .../keys/{key_id}`` with the OAuth bundle (present). The server
  refuses an OAuth bundle on a static-credential key, so a same-label
  credential-kind conflict fails closed instead of overwriting a static key.

Both steps match by name/label, so importing the same export twice updates the
same two rows — one provider, one key — instead of duplicating them.

Two scope assumptions, both deliberate. A provider row holds exactly one
``base_url``, so an existing Kiro provider is re-pointed at the imported
account's region: accounts in different regions need distinct ``--provider``
names. And the export's single ``region`` is taken as both the SSO and the API
region, which is what the gateway's endpoint pinning expects.

Secret hygiene is a hard rule of this tool: the admin key comes from the
environment only (never argv, never a file), responses are never echoed (an
error carries the HTTP status and a fixed message, body withheld), and a
successful run prints only the provider and key ids. TLS certificate
verification stays on, redirects are refused (a redirect could carry the admin
bearer to another host), and environment proxies are bypassed for this
traffic.
"""

import argparse
import http.client
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# The AWS region grammar, mirrored from kiro_tokens::valid_region: the region is
# interpolated into a hostname, so anything but lowercase letters, digits and
# hyphens must be refused before it can introduce another host, port or path.
_REGION_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
# An epoch below this cannot be a millisecond expiry (10^12 ms is 2001-09-09;
# a Unix-seconds value from this century is ~1.7 * 10^9), so it is a malformed
# export rather than a value to divide.
_MIN_MILLISECOND_EPOCH = 10**12
_MILLISECONDS_PER_SECOND = 1000
# The bundle is stored as an i64 Unix-seconds expiry; reject an out-of-range
# value here rather than as an opaque HTTP 400 from the server.
_MAX_UNIX_SECONDS = 2**63 - 1
_REQUEST_TIMEOUT_SECONDS = 30
# Only these fields are read from the account's credentials object.
_CREDENTIAL_FIELDS = ("clientId", "clientSecret", "refreshToken", "accessToken", "region")


def fail(message):
    """Print one fixed, secret-free error and exit non-zero."""
    print(f"import-kiro-account: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def valid_region(region):
    """Whether `region` is a bare AWS region (same rule as the gateway)."""
    return 0 < len(region) <= 32 and set(region) <= _REGION_CHARACTERS


def is_loopback(hostname):
    """Whether `hostname` names this machine (plain http is allowed only there)."""
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def admin_base_url(raw):
    """Validate CARDINAL_ADMIN_URL: https, or plain http only on loopback."""
    base = raw.strip().rstrip("/")
    try:
        parts = urllib.parse.urlsplit(base)
    except ValueError:
        fail("CARDINAL_ADMIN_URL is not a valid URL")
    if parts.scheme not in ("https", "http"):
        fail("CARDINAL_ADMIN_URL must use https (http is allowed only for loopback)")
    if parts.username is not None or parts.password is not None:
        fail("CARDINAL_ADMIN_URL must not carry credentials")
    if parts.query or parts.fragment:
        fail("CARDINAL_ADMIN_URL must not carry a query or fragment")
    if not parts.hostname:
        fail("CARDINAL_ADMIN_URL has no host")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in base):
        fail("CARDINAL_ADMIN_URL must not contain whitespace or control characters")
    if parts.scheme == "http" and not is_loopback(parts.hostname):
        fail("CARDINAL_ADMIN_URL must use https unless the host is loopback")
    return base


def read_account_bundle(path, index):
    """Read one account and return (admin OAuth bundle, region).

    Only the whitelisted fields are ever read; everything else in the export
    stays untouched on disk.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as error:
        fail(f"cannot read --input ({error.strerror or error.__class__.__name__})")
    except (json.JSONDecodeError, UnicodeDecodeError):
        fail("--input is not a UTF-8 JSON document")

    accounts = document.get("accounts") if isinstance(document, dict) else None
    if not isinstance(accounts, list):
        fail("--input has no accounts array")
    if index < 0 or index >= len(accounts):
        fail(f"--account {index} is out of range (the export holds {len(accounts)} account(s))")
    account = accounts[index]
    if not isinstance(account, dict):
        fail(f"accounts[{index}] is not an object")

    credentials = account.get("credentials")
    if not isinstance(credentials, dict):
        fail(f"accounts[{index}].credentials is missing")
    values = {}
    for name in _CREDENTIAL_FIELDS:
        value = credentials.get(name)
        if not isinstance(value, str) or not value.strip():
            fail(f"accounts[{index}].credentials.{name} is missing or empty")
        values[name] = value.strip()

    expires_at = credentials.get("expiresAt")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int):
        fail(f"accounts[{index}].credentials.expiresAt is not an integer")
    if expires_at < _MIN_MILLISECOND_EPOCH or expires_at // _MILLISECONDS_PER_SECOND > _MAX_UNIX_SECONDS:
        fail(f"accounts[{index}].credentials.expiresAt is not a plausible millisecond epoch")

    region = values["region"]
    if not valid_region(region):
        fail(f"accounts[{index}].credentials.region is not an AWS region")

    profile_arn = account.get("profileArn")
    if not isinstance(profile_arn, str) or not profile_arn.strip():
        fail(f"accounts[{index}].profileArn is missing or empty")

    oauth = {
        "clientId": values["clientId"],
        "clientSecret": values["clientSecret"],
        "refreshToken": values["refreshToken"],
        "accessToken": values["accessToken"],
        "expiresAt": expires_at // _MILLISECONDS_PER_SECOND,
        "region": region,
        "authRegion": region,
        "apiRegion": region,
        "profileArn": profile_arn.strip(),
    }
    return oauth, region


class AdminError(Exception):
    """A failure that may be printed: a message plus the HTTP status, if any."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.message = message
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: following one would hand the admin bearer to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AdminApi:
    """Minimal admin client: bearer auth, JSON bodies, no response echo."""

    def __init__(self, base_url, admin_key):
        self._base_url = base_url
        self._admin_key = admin_key
        # Direct connections only: an environment proxy would see the bearer
        # (and on plain-http loopback, the whole request).
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect
        )

    def call(self, method, path, payload=None, expect=None):
        """Perform one request; return the decoded body (or raise AdminError)."""
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._base_url + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self._admin_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as error:
            error.close()
            raise AdminError(
                f"{method} {path} failed with HTTP {error.code} (response body withheld)",
                error.code,
            ) from None
        except (urllib.error.URLError, OSError) as error:
            reason = getattr(error, "reason", None) or error.__class__.__name__
            raise AdminError(
                f"{method} {path} failed: no HTTP response ({reason})"
            ) from None
        except (http.client.HTTPException, ValueError):
            # A malformed status line, a truncated response or an invalid URL
            # must never surface as a traceback: those exception messages can
            # carry peer-controlled bytes (or the request's own headers).
            raise AdminError(f"{method} {path} failed: invalid HTTP exchange") from None
        if expect is not None and status != expect:
            raise AdminError(
                f"{method} {path} returned HTTP {status} (expected {expect}); "
                "response body withheld",
                status,
            )
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise AdminError(
                f"{method} {path} returned an unreadable JSON body (body withheld)"
            ) from None


def match_existing(rows, field, value, what):
    """Return (id, row) for the single match, None when absent, else fail closed."""
    if not isinstance(rows, list):
        fail(f"the admin API returned an unexpected {what} list shape")
    matches = [row for row in rows if isinstance(row, dict) and row.get(field) == value]
    if not matches:
        return None
    if len(matches) > 1:
        fail(f"{len(matches)} {what}s are named {value!r}; refusing to guess which one to update")
    row_id = matches[0].get("id")
    if isinstance(row_id, bool) or not isinstance(row_id, int):
        fail(f"the matching {what} carries no usable id")
    return row_id, matches[0]


def created_id(document, what):
    """The `{"id": n}` body of a create endpoint."""
    value = document.get("id") if isinstance(document, dict) else None
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"the admin API did not return the created {what} id")
    return value


def ensure_provider(api, name, region):
    """Create the provider, or return the PATCH that aligns the existing one.

    The update is deferred so the caller can rotate the key first: a refused
    key write must not leave the provider already re-pointed at a new region.
    Returns (provider_id, action, pending_patch) where pending_patch is None
    for a freshly created provider.
    """
    spec = {
        "name": name,
        "protocol": "kiro",
        "base_url": f"https://runtime.{region}.kiro.dev",
        "auth_scheme": "bearer",
        "enabled": True,
    }
    providers = api.call("GET", "/api/providers", expect=200)
    existing = match_existing(providers, "name", name, "provider")
    if existing is None:
        created = api.call("POST", "/api/providers", spec, expect=201)
        return created_id(created, "provider"), "created", None
    provider_id, provider = existing
    if provider.get("protocol") != "kiro":
        fail(
            f"provider {name!r} already exists with a non-Kiro protocol; "
            "refusing to convert it to Kiro"
        )
    enabled = provider.get("enabled")
    if not isinstance(enabled, bool):
        fail(f"provider {name!r} has an unreadable enabled flag; refusing to rewrite it")
    # Never flip the operator's enable flag: an import refreshes a credential,
    # it does not change whether the provider is in service.
    spec["enabled"] = enabled
    return provider_id, "updated", (f"/api/providers/{provider_id}", spec)


def ensure_key(api, provider_id, label, oauth):
    """Create the key, or rotate the OAuth bundle of the existing same-label one."""
    keys = api.call("GET", f"/api/providers/{provider_id}/keys", expect=200)
    existing = match_existing(keys, "label", label, "key")
    if existing is None:
        created = api.call(
            "POST",
            f"/api/providers/{provider_id}/keys",
            {
                "label": label,
                "auth_kind": "kiro_oidc",
                # A Kiro OIDC row stores its credential in `oauth`; the
                # plaintext column is explicitly null (migrations/0007 CHECK).
                "api_key": None,
                "oauth": oauth,
            },
            expect=201,
        )
        return created_id(created, "key"), "created"
    key_id, _ = existing
    try:
        # Only the credential rotates: label, enablement, concurrency and the
        # model whitelist stay as the operator left them.
        api.call(
            "PATCH",
            f"/api/providers/{provider_id}/keys/{key_id}",
            {"oauth": oauth},
            expect=200,
        )
    except AdminError as error:
        hint = (
            " (the existing key holds a static credential and cannot be converted)"
            if error.status == 400
            else ""
        )
        fail(f"{error.message}{hint}")
    return key_id, "updated"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Import one Kiro account's OAuth credentials through the admin API.",
        epilog=(
            "Requires CARDINAL_ADMIN_URL (https, or http on loopback) and "
            "CARDINAL_ADMIN_KEY in the environment. A remote admin URL also "
            "needs [gateway].admin_remote = true on the gateway."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Kiro account export JSON (read-only; never modified)",
    )
    parser.add_argument(
        "--account",
        type=int,
        default=0,
        help="index into accounts[] (default: 0)",
    )
    parser.add_argument("--provider", required=True, help="provider name (e.g. kiro)")
    parser.add_argument("--label", required=True, help="key label (e.g. main)")
    args = parser.parse_args(argv)

    admin_url = os.environ.get("CARDINAL_ADMIN_URL", "").strip()
    admin_key = os.environ.get("CARDINAL_ADMIN_KEY", "").strip()
    if not admin_url:
        fail("CARDINAL_ADMIN_URL is not set")
    if not admin_key:
        fail("CARDINAL_ADMIN_KEY is not set")
    if any(not 0x21 <= ord(char) <= 0x7E for char in admin_key):
        # An illegal header value would raise a ValueError naming the key.
        fail("CARDINAL_ADMIN_KEY must be printable ASCII without whitespace")
    base_url = admin_base_url(admin_url)
    if args.account < 0:
        fail("--account must not be negative")
    if not args.provider.strip():
        fail("--provider must not be empty")
    if "/" in args.provider:
        fail("--provider must not contain '/' (the gateway rejects such names)")
    if not args.label.strip():
        fail("--label must not be empty")

    oauth, region = read_account_bundle(args.input, args.account)

    api = AdminApi(base_url, admin_key)
    try:
        provider_id, provider_action, provider_patch = ensure_provider(
            api, args.provider.strip(), region
        )
        key_id, key_action = ensure_key(api, provider_id, args.label.strip(), oauth)
        if provider_patch is not None:
            path, spec = provider_patch
            api.call("PATCH", path, spec, expect=200)
    except AdminError as error:
        fail(error.message)
    print(f"provider {provider_id} ({provider_action}); key {key_id} ({key_action})")


if __name__ == "__main__":
    main()
