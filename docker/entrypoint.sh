#!/bin/bash
# Single-container orchestration: embedded PostgreSQL first, cardinal in the
# foreground second. All persistent state lives under /data; secrets are read
# from the environment or the volume and are never printed.
set -euo pipefail

CARDINAL_UID=10001
CARDINAL_GID=10001
PGDATA_DIR="${PGDATA:-/data/pgdata}"
HOME_DIR="${HOME:-/data/home}"
CONFIG_PATH="$HOME_DIR/.ox/config.toml"
PASSWORD_FILE=/data/db-password
PG_PORT=5432
pg_pid=""
cardinal_pid=""
stopping=0
status=0

fail() {
    printf 'cardinal entrypoint: %s\n' "$1" >&2
    exit 1
}

safe_value() {
    [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]
}

stop_postgres() {
    [[ -n "$pg_pid" ]] || return 0
    gosu postgres pg_ctl -D "$PGDATA_DIR" -m fast -w stop >/dev/null 2>&1 || true
    wait "$pg_pid" 2>/dev/null || true
    pg_pid=""
}

on_signal() {
    stopping=1
    if [[ -n "$cardinal_pid" ]]; then
        kill -TERM "$cardinal_pid" 2>/dev/null || true
    fi
}
trap on_signal TERM INT

# Fail closed on missing or unsafe input; never echo the values themselves.
[[ -n "${GATEWAY_KEY:-}" ]] || fail "GATEWAY_KEY is required"
safe_value "$GATEWAY_KEY" || fail "GATEWAY_KEY must match [A-Za-z0-9_-]"

POSTGRES_USER="${POSTGRES_USER:-cardinal}"
POSTGRES_DB="${POSTGRES_DB:-cardinal}"
ADMIN_REMOTE="${ADMIN_REMOTE:-false}"
LOG_LEVEL="${LOG_LEVEL:-info}"
safe_value "$POSTGRES_USER" || fail "POSTGRES_USER must match [A-Za-z0-9_-]"
safe_value "$POSTGRES_DB" || fail "POSTGRES_DB must match [A-Za-z0-9_-]"
case "$ADMIN_REMOTE" in
    true|false) ;;
    *) fail "ADMIN_REMOTE must be true or false" ;;
esac
[[ "$LOG_LEVEL" =~ ^[A-Za-z0-9_.,=:-]+$ ]] || fail "LOG_LEVEL has unsupported characters"

mkdir -p "$PGDATA_DIR" "$HOME_DIR/.ox" /var/run/postgresql
chown postgres:postgres "$PGDATA_DIR" /var/run/postgresql
chown "$CARDINAL_UID:$CARDINAL_GID" "$HOME_DIR" "$HOME_DIR/.ox"
chmod 700 "$PGDATA_DIR" "$HOME_DIR" "$HOME_DIR/.ox"

# The volume is authoritative: an existing password matches the initialized
# cluster. A caller-supplied password is used only on first initialization.
if [[ -f "$PASSWORD_FILE" ]]; then
    db_password="$(<"$PASSWORD_FILE")"
else
    if [[ -n "${POSTGRES_PASSWORD:-}" ]]; then
        db_password="$POSTGRES_PASSWORD"
    else
        db_password="$(od -An -N24 -tx1 /dev/urandom | tr -d '[:space:]')"
    fi
    safe_value "$db_password" || fail "database password must match [A-Za-z0-9_-]"
    umask 077
    printf '%s\n' "$db_password" >"$PASSWORD_FILE"
fi
chmod 600 "$PASSWORD_FILE"
safe_value "$db_password" || fail "database password must match [A-Za-z0-9_-]"
export POSTGRES_PASSWORD="$db_password"

# cardinal reads its config from the persistent HOME, so a restarted container
# regenerates the same config from the same volume and environment.
config_tmp="$CONFIG_PATH.tmp"
umask 077
cat >"$config_tmp" <<EOF
[gateway]
listen = "0.0.0.0:8787"
sql_dsn = "postgres://${POSTGRES_USER}:${db_password}@127.0.0.1:${PG_PORT}/${POSTGRES_DB}"
gateway_key = "${GATEWAY_KEY}"
admin_remote = ${ADMIN_REMOTE}
payloads = false

[log]
level = "${LOG_LEVEL}"
console = true
EOF
mv -f "$config_tmp" "$CONFIG_PATH"
chown "$CARDINAL_UID:$CARDINAL_GID" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"

printf 'cardinal entrypoint: starting PostgreSQL\n'
gosu postgres /usr/local/bin/docker-entrypoint.sh postgres \
    -c listen_addresses=127.0.0.1 \
    -c unix_socket_directories=/var/run/postgresql &
pg_pid=$!

# Bounded readiness poll; pg_isready over TCP only answers once PostgreSQL
# itself is accepting connections (the entrypoint's temporary init server is
# socket-only).
deadline=$((SECONDS + 120))
until pg_isready -h 127.0.0.1 -p "$PG_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; do
    if (( stopping )); then
        stop_postgres
        exit 0
    fi
    if (( SECONDS >= deadline )); then
        printf 'cardinal entrypoint: PostgreSQL did not become ready within 120s\n' >&2
        stop_postgres
        exit 1
    fi
    if ! kill -0 "$pg_pid" 2>/dev/null; then
        printf 'cardinal entrypoint: PostgreSQL exited during startup\n' >&2
        wait "$pg_pid" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

if (( stopping )); then
    stop_postgres
    exit 0
fi

printf 'cardinal entrypoint: starting cardinal\n'
gosu "$CARDINAL_UID:$CARDINAL_GID" /usr/local/bin/cardinal --config "$CONFIG_PATH" &
cardinal_pid=$!

# wait() can return early when a trapped signal interrupts it; keep waiting
# until the child is really gone so PostgreSQL is stopped strictly afterwards.
while :; do
    wait "$cardinal_pid" || status=$?
    if ! kill -0 "$cardinal_pid" 2>/dev/null; then
        break
    fi
done

if (( stopping )); then
    status=0
fi
trap - TERM INT
stop_postgres
exit "$status"
