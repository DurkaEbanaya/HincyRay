#!/bin/sh
# HincyRay interactive installer for Keenetic + Entware (aarch64).
#
# ATOMIC DESIGN:
#   1. STAGING  — all files downloaded/copied to a temp dir on the same
#      filesystem as /opt (so `mv` is atomic).
#   2. BACKUP   — existing files snapshotted before any modification.
#   3. INSTALL  — atomic `mv` from staging to final paths.
#   4. VERIFY   — health check after daemon start.
#   5. COMMIT   — remove backup on success, OR
#      ROLLBACK — restore from backup on any failure (trap-based).
#
# HincyRay-owned files and runtime state commit together or are restored
# together. Entware package operations remain owned by opkg and complete
# before the HincyRay transaction begins.
#
# Usage:
#   sh /tmp/hincyray-install.sh
#
# Environment variables (all optional):
#   HINCYRAY_BIN_PATH   — path to pre-built hincyray binary (default: /tmp/hincyray)
#   HINCYRAY_XRAY_ZIP   — path to xray zip (default: /tmp/xray.zip)
#   HINCYRAY_LISTEN     — bind address (default: 0.0.0.0:8088)
#   HINCYRAY_SUB_URL    — subscription URL to import automatically
#   HINCYRAY_WIFI_PASSWORD — WiFi VPN password (default: HincyRayVPN2026)
#   HINCYRAY_NONINTERACTIVE — set to 1 for non-interactive full setup

set -eu

VERSION="1.3.4"
GITHUB="https://github.com/DurkaEbanaya/HincyRay"
ENTWARE="${HINCYRAY_ENTWARE:-/opt}"
HINCYRAY_DIR="${ENTWARE}/etc/hincyray"
LOG_DIR="${ENTWARE}/var/log/hincyray"
INIT_SCRIPT="${ENTWARE}/etc/init.d/S99hincyray"
PID_FILE="${ENTWARE}/var/run/hincyray.pid"
LIFECYCLE_LOCK="${ENTWARE}/var/run/hincyray.lifecycle.lock"
DAEMON_BIN="${ENTWARE}/sbin/hincyray"
XRAY_BIN="${HINCYRAY_DIR}/xray"
XRAY_LINK="${ENTWARE}/sbin/xray"
SCRIPTS_DIR="${HINCYRAY_DIR}/scripts"
LISTEN_ADDR="${HINCYRAY_LISTEN:-0.0.0.0:8088}"
LISTEN_PORT="${LISTEN_ADDR##*:}"

# Temp dirs on the SAME filesystem as /opt (required for atomic mv).
# Using $$ (PID) so parallel runs don't clash.
STAGING="${ENTWARE}/tmp/hincyray-staging-$$"
BACKUP="${ENTWARE}/tmp/hincyray-backup-$$"

# Rollback tracking. Each file we touch gets an entry here.
# Format: "dest_path|backup_path" (backup_path may be "NONE" if dest didn't exist).
TOUCHED=""
TRANSACTION_ACTIVE=0
TRANSACTION_COMMITTED=0
DAEMON_WAS_RUNNING=0
RUNTIME_TREE_REGISTERED=0
LIFECYCLE_LOCK_HELD=0
TRANSACTION_MANAGES_DAEMON=0

# ANSI colors (disabled if not a tty)
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Output helpers ───────────────────────────────────────────────────

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
die()   { err "$*"; exit 1; }
step()  { printf "\n${BOLD}${BLUE}━━ %s ━━${NC}\n" "$*"; }

ask() {
    printf "${GREEN}?${NC} %s " "$1"
    read val
    printf '%s' "$val"
}
ask_yn() {
    while true; do
        printf "${GREEN}?${NC} %s [y/n] " "$1"
        read answer
        case "$answer" in
            y|Y|yes|YES) return 0 ;;
            n|N|no|NO)   return 1 ;;
        esac
    done
}
ask_default() {
    printf "${GREEN}?${NC} %s [%s] " "$1" "$2"
    read val
    printf '%s' "${val:-$2}"
}

check_cmd() { command -v "$1" >/dev/null 2>&1; }

public_get() {
    url="$1"
    output="$2"
    curl --fail --silent --show-error --location --output "$output" "$url"
}

# ── Atomic infrastructure ────────────────────────────────────────────

# Register a file for rollback: if we modify `dest`, save its current
# state to backup first, and record the pair for the rollback trap.
register_path() {
    dest="$1"
    backup_name="$2"
    kind="$3"
    backup_path="${BACKUP}/${backup_name}"

    if [ -e "$dest" ] || [ -L "$dest" ]; then
        mkdir -p "$(dirname "$backup_path")"
        cp -a "$dest" "$backup_path" 2>/dev/null \
            || die "Cannot back up $dest to $backup_path"
        TOUCHED="${dest}|${backup_path}|${kind}
${TOUCHED}"
    else
        TOUCHED="${dest}|NONE|${kind}
${TOUCHED}"
    fi
}

register_file() {
    register_path "$1" "$2" file
}

register_runtime_tree() {
    [ "$RUNTIME_TREE_REGISTERED" -eq 0 ] || return 0
    register_path "$HINCYRAY_DIR" "etc/hincyray" tree
    RUNTIME_TREE_REGISTERED=1
}

# Atomic install: mv from staging to dest. The file must already be
# registered for rollback.
atomic_install() {
    src="$1"
    dest="$2"
    if [ ! -f "$src" ]; then
        die "atomic_install: staging file missing: $src"
    fi
    # mv is atomic on the same filesystem. Both STAGING and dest are
    # under /opt, so this is guaranteed.
    mv -f "$src" "$dest"
}

process_is_daemon() {
    pid="$1"
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$DAEMON_BIN" ]
}

stop_daemon_pid() {
    target_pid="$1"
    process_is_daemon "$target_pid" || return 0
    kill "$target_pid" 2>/dev/null || return 1
    for i in 1 2 3 4 5; do
        process_is_daemon "$target_pid" || return 0
        sleep 1
    done
    process_is_daemon "$target_pid" && kill -9 "$target_pid" 2>/dev/null || true
    process_is_daemon "$target_pid" && return 1
    return 0
}

begin_transaction() {
    [ "$TRANSACTION_ACTIVE" -eq 0 ] || return 0
    TOUCHED=""
    RUNTIME_TREE_REGISTERED=0
    DAEMON_WAS_RUNNING=0
    TRANSACTION_MANAGES_DAEMON=0
    TRANSACTION_ACTIVE=1
    TRANSACTION_COMMITTED=0
}

acquire_transaction_lock() {
    [ "$LIFECYCLE_LOCK_HELD" -eq 0 ] || return 0
    if ! mkdir "$LIFECYCLE_LOCK" 2>/dev/null; then
        owner="$(cat "$LIFECYCLE_LOCK/owner" 2>/dev/null || true)"
        case "$owner" in
            ''|*[!0-9]*) owner='' ;;
        esac
        if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
            die "HincyRay lifecycle operation already in progress (pid $owner)"
        fi
        rm -rf "$LIFECYCLE_LOCK"
        mkdir "$LIFECYCLE_LOCK" || die "Cannot acquire HincyRay lifecycle lock"
    fi
    printf '%s\n' "$$" > "$LIFECYCLE_LOCK/owner"
    LIFECYCLE_LOCK_HELD=1
}

release_transaction_lock() {
    if [ "$LIFECYCLE_LOCK_HELD" -eq 1 ]; then
        owner="$(cat "$LIFECYCLE_LOCK/owner" 2>/dev/null || true)"
        [ "$owner" = "$$" ] && rm -rf "$LIFECYCLE_LOCK"
        LIFECYCLE_LOCK_HELD=0
    fi
}

# Rollback: stop the candidate, restore files in reverse registration order,
# then restore the daemon's pre-transaction running/stopped state.
do_rollback() {
    err "Rolling back all changes..."
    rollback_failed=0
    candidate_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ "$TRANSACTION_MANAGES_DAEMON" -eq 1 ] && [ -x "$INIT_SCRIPT" ]; then
        HINCYRAY_LIFECYCLE_OWNER=$$ "$INIT_SCRIPT" stop >/dev/null 2>&1 || true
    fi
    if [ "$TRANSACTION_MANAGES_DAEMON" -eq 1 ] \
        && process_is_daemon "$candidate_pid" \
        && ! stop_daemon_pid "$candidate_pid"; then
        err "Cannot stop candidate daemon pid $candidate_pid; preserving backups"
        return 1
    fi
    while IFS='|' read -r dest backup_path kind; do
        [ -z "$dest" ] && continue
        if [ "$backup_path" = "NONE" ]; then
            if rm -rf "$dest" 2>/dev/null; then
                info "  removed: $dest (was not present before)"
            else
                err "  failed to remove: $dest"
                rollback_failed=1
            fi
        elif [ -e "$backup_path" ]; then
            restore_ready=1
            rm -rf "$dest" 2>/dev/null || restore_ready=0
            if [ "$restore_ready" -eq 1 ] && cp -a "$backup_path" "$dest" 2>/dev/null; then
                info "  restored: $dest"
            else
                err "  failed to restore: $dest"
                rollback_failed=1
            fi
        else
            err "  backup missing for: $dest"
            rollback_failed=1
        fi
    done <<EOF
$TOUCHED
EOF

    if [ "$rollback_failed" -eq 0 ] \
        && [ "$TRANSACTION_MANAGES_DAEMON" -eq 1 ] \
        && [ "$DAEMON_WAS_RUNNING" -eq 1 ] \
        && [ -x "$INIT_SCRIPT" ]; then
        info "Restarting previous daemon..."
        HINCYRAY_LIFECYCLE_OWNER=$$ "$INIT_SCRIPT" start 2>/dev/null || rollback_failed=1
    fi

    if [ "$rollback_failed" -eq 0 ]; then
        release_transaction_lock
        rm -rf "$STAGING" "$BACKUP" 2>/dev/null || true
        err "Rollback complete. System restored to previous state."
        return 0
    fi
    err "Rollback incomplete; backups preserved at $BACKUP"
    return 1
}

commit_transaction() {
    TRANSACTION_COMMITTED=1
    rm -rf "$STAGING" "$BACKUP" 2>/dev/null || true
    TRANSACTION_ACTIVE=0
    TOUCHED=""
    release_transaction_lock
}

on_exit() {
    rc="$1"
    trap - EXIT HUP INT TERM
    if [ "$TRANSACTION_ACTIVE" -eq 1 ] && [ "$TRANSACTION_COMMITTED" -eq 0 ]; then
        do_rollback || rc=1
        [ "$rc" -eq 0 ] && rc=1
    else
        release_transaction_lock
        rm -rf "$STAGING" "$BACKUP" 2>/dev/null || true
    fi
    exit "$rc"
}
trap 'on_exit $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ── Environment detection ────────────────────────────────────────────

detect_env() {
    step "Environment detection"

    ARCH=$(uname -m 2>/dev/null || echo "unknown")
    info "Architecture: ${ARCH}"
    case "$ARCH" in
        aarch64|arm64) ok "Target: aarch64 (Keenetic Giga KN-1012)" ;;
        *) warn "Architecture ${ARCH} — HincyRay is built for aarch64" ;;
    esac

    if [ -d "${ENTWARE}" ] && [ -d "${ENTWARE}/etc/init.d" ]; then
        ok "Entware found at ${ENTWARE}"
    else
        die "Entware not found at ${ENTWARE}. Install Entware first."
    fi

    check_cmd opkg || die "opkg not found. Entware may be broken."

    # Report the current daemon state. Each transaction snapshots it again.
    if [ -r "$PID_FILE" ] && process_is_daemon "$(cat "$PID_FILE" 2>/dev/null)"; then
        info "HincyRay daemon is currently running"
    fi

    # Existing files.
    [ -f "$DAEMON_BIN" ] && info "Existing binary: $DAEMON_BIN" || true
    [ -f "$XRAY_BIN" ] && info "Existing Xray: $XRAY_BIN" || true
    [ -f "$INIT_SCRIPT" ] && info "Existing init script: $INIT_SCRIPT" || true

    # Legacy packages.
    LEGACY=$(opkg list-installed 2>/dev/null | grep -E "xkeen|xray-s|xray_s|mihomo-s|mihomo_s" || true)
    if [ -n "$LEGACY" ]; then
        warn "Legacy proxy packages detected: $(echo "$LEGACY" | tr '\n' ' ')"
    fi
    LEGACY_PKGS="$LEGACY"

    # Available tools.
    check_cmd curl && HAVE_CURL=1 || HAVE_CURL=0
    check_cmd unzip && HAVE_UNZIP=1 || HAVE_UNZIP=0
    check_cmd jq && HAVE_JQ=1 || HAVE_JQ=0

    # v0.7: kernel modules for iptables TPROXY/REDIRECT transparent proxy.
    KERNVER=$(uname -r)
    HAVE_TPROXY=0
    HAVE_SOCKET=0
    HAVE_COMMENT=0
    [ -f "/lib/modules/${KERNVER}/xt_TPROXY.ko" ] && HAVE_TPROXY=1 || true
    [ -f "/lib/modules/${KERNVER}/xt_socket.ko" ] && HAVE_SOCKET=1 || true
    [ -f "/lib/modules/${KERNVER}/xt_comment.ko" ] && HAVE_COMMENT=1 || true

    # v0.7: ndm netfilter hook directory.
    HAVE_NDM_HOOKS=0
    [ -d "/opt/etc/ndm/netfilter.d" ] && HAVE_NDM_HOOKS=1 || true

    # Free disk space.
    FREE_KB=$(df -k "${ENTWARE}" 2>/dev/null | tail -1 | awk '{print $4}')
    [ -n "$FREE_KB" ] && info "Free space: ${FREE_KB} kB" || true
}

# ── Pre-flight: prepare staging and backup dirs ──────────────────────

prepare_dirs() {
    begin_transaction
    mkdir -p "$STAGING" "$BACKUP" || die "Cannot create temp dirs under ${ENTWARE}"
    mkdir -p "${STAGING}/sbin" "${STAGING}/etc/init.d" "${STAGING}/etc/hincyray"
    mkdir -p "${BACKUP}/sbin" "${BACKUP}/etc/init.d" "${BACKUP}/etc"
}

# ── Phase: install dependencies (owned and verified by opkg) ─────────

install_deps() {
    step "Installing dependencies"
    info "Running opkg update..."
    opkg update 2>/dev/null || warn "opkg update failed (may be offline)"

    NEED=""
    [ "$HAVE_CURL" -eq 0 ] && NEED="$NEED curl"
    [ "$HAVE_JQ" -eq 0 ] && NEED="$NEED jq"
    [ "$HAVE_UNZIP" -eq 0 ] && NEED="$NEED unzip"

    # v0.7: check kernel modules.
    [ "$HAVE_TPROXY" -eq 0 ] && warn "xt_TPROXY.ko not found — UDP TPROXY unavailable (TCP-only REDIRECT will be used)"
    [ "$HAVE_SOCKET" -eq 0 ] && warn "xt_socket.ko not found — UDP TPROXY unavailable"
    [ "$HAVE_COMMENT" -eq 0 ] && warn "xt_comment.ko not found — iptables rule tagging unavailable"

    if [ -z "$NEED" ]; then
        ok "All dependencies already present"
        return 0
    fi

    info "Installing:${NEED}"
    # shellcheck disable=SC2086
    opkg install $NEED 2>/dev/null || true
    FAILED=""
    for pkg in $NEED; do
        check_cmd "$pkg" || FAILED="$FAILED $pkg"
    done
    [ -z "$FAILED" ] || die "Required dependencies unavailable after opkg install:${FAILED}"
    ok "Dependencies installed and verified"
}

# ── Phase: stage binary ──────────────────────────────────────────────

stage_binary() {
    step "Staging HincyRay binary"

    BIN_PATH="${HINCYRAY_BIN_PATH:-/tmp/hincyray}"

    if [ ! -f "$BIN_PATH" ]; then
        for try in /tmp/hincyray /root/hincyray /opt/tmp/hincyray; do
            if [ -f "$try" ]; then
                BIN_PATH="$try"
                break
            fi
        done
    fi

    if [ ! -f "$BIN_PATH" ]; then
        RELEASE_URL="https://github.com/DurkaEbanaya/HincyRay/releases/download/v${VERSION}/hincyray"
        if [ "$HAVE_CURL" -eq 1 ] && ask_yn "Binary not found. Download GitHub release v${VERSION}?"; then
            info "Downloading hincyray release asset..."
            if public_get "$RELEASE_URL" "${STAGING}/sbin/hincyray" && [ -s "${STAGING}/sbin/hincyray" ]; then
                ok "Downloaded to staging"
            else
                die "Download failed. Copy the binary manually: scp -P 222 -O hincyray root@<router>:/tmp/hincyray"
            fi
        else
            err "Copy the binary to the router first:"
            err "  scp -P 222 -O hincyray root@<router-ip>:/tmp/hincyray"
            die "Cannot proceed without binary"
        fi
    else
        info "Copying ${BIN_PATH} → staging..."
        cp "$BIN_PATH" "${STAGING}/sbin/hincyray"
    fi

    chmod +x "${STAGING}/sbin/hincyray"

    # Verify it's a valid executable for this arch.
    if "${STAGING}/sbin/hincyray" --help >/dev/null 2>&1; then
        ok "Binary verified in staging"
    else
        # Try file/od to check if it's an ELF.
        if od -An -tx1 -N4 "${STAGING}/sbin/hincyray" 2>/dev/null | grep -q '7f 45 4c 46'; then
            warn "Binary is ELF but may not run (check interpreter/ld-linux)"
        else
            die "Binary is not a valid ELF executable"
        fi
    fi

    # Register existing binary for rollback.
}

# ── Phase: stage Xray ────────────────────────────────────────────────

stage_xray() {
    step "Staging Xray core + assets"

    XRAY_EXISTING=0
    [ -f "$XRAY_BIN" ] && XRAY_EXISTING=1

    if [ "$XRAY_EXISTING" -eq 1 ]; then
        if ! ask_yn "Xray already installed. Reinstall/upgrade?"; then
            ok "Keeping existing Xray"
            return 0
        fi
    fi

    ZIP_PATH="${HINCYRAY_XRAY_ZIP:-/tmp/xray.zip}"

    if [ ! -f "$ZIP_PATH" ]; then
        for try in /tmp/xray.zip /root/xray.zip /opt/tmp/xray.zip; do
            if [ -f "$try" ]; then
                ZIP_PATH="$try"
                break
            fi
        done
    fi

    if [ ! -f "$ZIP_PATH" ]; then
        XRAY_VER=$(ask_default "Xray version to download" "v26.3.27")
        URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-arm64-${XRAY_VER}.zip"
        if [ "$HAVE_CURL" -eq 1 ] && ask_yn "Download Xray ${XRAY_VER} from GitHub?"; then
            info "Downloading..."
            if curl -sSL -o "${STAGING}/xray.zip" "$URL" 2>/dev/null && [ -s "${STAGING}/xray.zip" ]; then
                ZIP_PATH="${STAGING}/xray.zip"
                ok "Downloaded"
            else
                warn "Download failed. Skipping Xray — install manually later."
                return 0
            fi
        else
            warn "Skipping Xray."
            return 0
        fi
    else
        cp "$ZIP_PATH" "${STAGING}/xray.zip"
    fi

    info "Extracting Xray to staging..."
    cd "${STAGING}/etc/hincyray"
    if check_cmd unzip; then
        unzip -o "${STAGING}/xray.zip" xray geosite.dat 2>/dev/null || \
            unzip -o "${STAGING}/xray.zip" 2>/dev/null || true
    else
        # BusyBox unzip fallback — some Entware builds lack unzip.
        # Try python or busybox tar.
        warn "unzip not available — trying alternative extraction"
        if check_cmd python3; then
            python3 -c "
import zipfile, sys
z = zipfile.ZipFile('${STAGING}/xray.zip')
for n in ['xray','geosite.dat']:
    try: z.extract(n, '${STAGING}/etc/hincyray')
    except KeyError: pass
" 2>/dev/null || true
        else
            warn "Cannot extract zip without unzip or python3. Install unzip first."
            cd - >/dev/null 2>&1 || true
            return 0
        fi
    fi
    cd - >/dev/null 2>&1 || true
    rm -f "${STAGING}/xray.zip"

    if [ -f "${STAGING}/etc/hincyray/xray" ]; then
        chmod +x "${STAGING}/etc/hincyray/xray"
        ok "Xray staged"
    else
        warn "Xray binary not found in zip — check archive structure"
        return 0
    fi

    # Register for rollback.
}

# ── Phase: stage init script ─────────────────────────────────────────

stage_init() {
    step "Staging init script"

    cat > "${STAGING}/etc/init.d/S99hincyray" << 'INITEOF'
#!/bin/sh

PATH=/opt/sbin:/opt/bin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
DAEMON=/opt/sbin/hincyray
PIDFILE=/opt/var/run/hincyray.pid
LOCKDIR=/opt/var/run/hincyray.lifecycle.lock
LOGDIR=/opt/var/log/hincyray
LOGFILE=$LOGDIR/hincyray.log

mkdir -p "$LOGDIR" /opt/var/run

daemon_identity() {
    pid="$1"
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$DAEMON" ] || return 1
}

daemon_pid() {
    [ -r "$PIDFILE" ] || return 1
    pid="$(cat "$PIDFILE" 2>/dev/null)"
    daemon_identity "$pid" || return 1
    printf '%s\n' "$pid"
}

acquire_lock() {
    if mkdir "$LOCKDIR" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCKDIR/owner"
        return 0
    fi
    owner="$(cat "$LOCKDIR/owner" 2>/dev/null)"
    case "$owner" in
        ''|*[!0-9]*) owner='' ;;
    esac
    if [ -n "${HINCYRAY_LIFECYCLE_OWNER:-}" ] && [ "$owner" = "$HINCYRAY_LIFECYCLE_OWNER" ]; then
        return 0
    fi
    if [ -z "$owner" ] || ! kill -0 "$owner" 2>/dev/null; then
        rm -rf "$LOCKDIR"
        mkdir "$LOCKDIR" || return 1
        printf '%s\n' "$$" > "$LOCKDIR/owner"
        return 0
    fi
    echo "hincyray lifecycle operation already in progress (pid $owner)" >&2
    return 1
}

release_lock() {
    owner="$(cat "$LOCKDIR/owner" 2>/dev/null)"
    if [ -z "${HINCYRAY_LIFECYCLE_OWNER:-}" ] || [ "$owner" = "$$" ]; then
        rm -rf "$LOCKDIR"
    fi
}

start() {
    if PID="$(daemon_pid)"; then
        echo "hincyray already running (pid $PID)"
        return 0
    fi
    rm -f "$PIDFILE"
    echo "starting hincyray"
    nohup "$DAEMON" </dev/null >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if PID="$(daemon_pid)"; then
        echo "hincyray started (pid $PID)"
    else
        echo "hincyray failed to start — check $LOGFILE"
        rm -f "$PIDFILE"
        return 1
    fi

    i=0
    while [ "$i" -lt 15 ]; do
        if curl -sS --max-time 2 http://127.0.0.1:8088/api/health >/dev/null 2>&1; then
            curl -sS --max-time 10 -X POST http://127.0.0.1:8088/api/core/start \
                >>"$LOGFILE" 2>&1 || true
            break
        fi
        sleep 1
        i=$((i + 1))
    done
}

stop() {
    if PID="$(daemon_pid)"; then
        echo "stopping hincyray (pid $PID)"
        daemon_identity "$PID" && kill "$PID"
        for i in 1 2 3 4 5; do
            daemon_identity "$PID" || break
            sleep 1
        done
        daemon_identity "$PID" && kill -9 "$PID" 2>/dev/null || true
        if daemon_identity "$PID"; then
            echo "hincyray failed to stop (pid $PID)" >&2
            return 1
        fi
    fi
    rm -f "$PIDFILE"
    echo "hincyray stopped"
}

status() {
    if PID="$(daemon_pid)"; then
        echo "hincyray running (pid $PID)"
        return 0
    fi
    echo "hincyray not running"
    return 3
}

acquire_lock || exit 1
trap 'release_lock' EXIT
trap 'release_lock; exit 129' HUP
trap 'release_lock; exit 130' INT
trap 'release_lock; exit 143' TERM

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; start ;;
    status)  status ;;
    *)
        echo "usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
exit $?
INITEOF

    chmod +x "${STAGING}/etc/init.d/S99hincyray"
    ok "Init script staged"
}

# ── Phase: stage wifi script ─────────────────────────────────────────

stage_wifi_script() {
    if [ ! -f "${SCRIPTS_DIR}/wifi-segment-setup.sh" ]; then
        # Look for the script alongside the installer.
        for try in "$(dirname "$0")/wifi-segment-setup.sh" /tmp/wifi-segment-setup.sh; do
            if [ -f "$try" ]; then
                cp "$try" "${STAGING}/etc/hincyray/wifi-segment-setup.sh"
                ok "WiFi setup script staged"
                return 0
            fi
        done
        # Try downloading from GitHub.
        if [ "$HAVE_CURL" -eq 1 ]; then
            URL="https://raw.githubusercontent.com/DurkaEbanaya/HincyRay/v${VERSION}/scripts/wifi-segment-setup.sh"
            if public_get "$URL" "${STAGING}/etc/hincyray/wifi-segment-setup.sh" && [ -s "${STAGING}/etc/hincyray/wifi-segment-setup.sh" ]; then
                ok "WiFi setup script downloaded to staging"
                return 0
            fi
        fi
        warn "wifi-segment-setup.sh not found — copy manually if needed"
    fi
}

# ── Phase: commit (atomic install all staged files) ──────────────────

commit_install() {
    step "Committing installation (atomic)"

    LIFECYCLE_CHANGE=0
    if [ -f "${STAGING}/sbin/hincyray" ] || [ -f "${STAGING}/etc/init.d/S99hincyray" ]; then
        LIFECYCLE_CHANGE=1
        TRANSACTION_MANAGES_DAEMON=1
    fi
    acquire_transaction_lock
    if [ "$LIFECYCLE_CHANGE" -eq 1 ]; then
        register_file "${ENTWARE}/etc/ndm/netfilter.d/hincyray.sh" "etc/ndm/netfilter.d/hincyray.sh"
    fi

    # Stop only the daemon identified by the authoritative PID file. A stale
    # PID must never target an unrelated process after PID reuse.
    if [ "$LIFECYCLE_CHANGE" -eq 1 ] && [ -r "$PID_FILE" ]; then
        OLD_PID="$(cat "$PID_FILE" 2>/dev/null)"
        case "$OLD_PID" in
            ''|*[!0-9]*) OLD_PID='' ;;
        esac
        if [ -n "$OLD_PID" ] \
            && kill -0 "$OLD_PID" 2>/dev/null \
            && [ "$(readlink "/proc/$OLD_PID/exe" 2>/dev/null)" = "$DAEMON_BIN" ]; then
            info "Stopping existing daemon..."
            DAEMON_WAS_RUNNING=1
            if [ -x "$INIT_SCRIPT" ]; then
                HINCYRAY_LIFECYCLE_OWNER=$$ "$INIT_SCRIPT" stop \
                    || die "Existing daemon stop failed"
            else
                stop_daemon_pid "$OLD_PID" || die "Existing daemon stop failed"
            fi
            process_is_daemon "$OLD_PID" && die "Existing daemon did not stop"
        fi
        rm -f "$PID_FILE"
    fi

    if [ "$LIFECYCLE_CHANGE" -eq 1 ]; then
        register_runtime_tree
    else
        [ -f "${STAGING}/etc/hincyray/xray" ] && register_file "$XRAY_BIN" "etc/hincyray/xray"
        [ -f "${STAGING}/etc/hincyray/geosite.dat" ] && register_file "${HINCYRAY_DIR}/geosite.dat" "etc/hincyray/geosite.dat"
        [ -f "${STAGING}/etc/hincyray/wifi-segment-setup.sh" ] && register_file "${SCRIPTS_DIR}/wifi-segment-setup.sh" "etc/hincyray/scripts/wifi-segment-setup.sh"
    fi
    [ -f "${STAGING}/sbin/hincyray" ] && register_file "$DAEMON_BIN" "sbin/hincyray"
    [ -f "${STAGING}/etc/init.d/S99hincyray" ] && register_file "$INIT_SCRIPT" "etc/init.d/S99hincyray"
    [ -f "${STAGING}/etc/hincyray/xray" ] && register_file "$XRAY_LINK" "sbin/xray"

    # Create target directories if they don't exist.
    mkdir -p "$HINCYRAY_DIR" "$LOG_DIR" "${ENTWARE}/sbin" "${ENTWARE}/bin" "${ENTWARE}/etc/init.d"

    # Atomic moves — each mv is atomic on the same filesystem.
    if [ -f "${STAGING}/sbin/hincyray" ]; then
        info "Installing binary..."
        atomic_install "${STAGING}/sbin/hincyray" "$DAEMON_BIN"
        ok "  → $DAEMON_BIN"
    fi

    if [ -f "${STAGING}/etc/hincyray/xray" ]; then
        info "Installing Xray..."
        atomic_install "${STAGING}/etc/hincyray/xray" "$XRAY_BIN"
        ok "  → $XRAY_BIN"
        # Create/update symlink (rm + ln is not atomic, but ln -sf is close enough).
        rm -f "$XRAY_LINK"
        ln -s "$XRAY_BIN" "$XRAY_LINK"
        ok "  → $XRAY_LINK (symlink)"

        for asset in geosite.dat; do
            if [ -f "${STAGING}/etc/hincyray/$asset" ]; then
                atomic_install "${STAGING}/etc/hincyray/$asset" "${HINCYRAY_DIR}/$asset"
                ok "  → ${HINCYRAY_DIR}/$asset"
            fi
        done
    fi

    if [ -f "${STAGING}/etc/init.d/S99hincyray" ]; then
        info "Installing init script..."
        atomic_install "${STAGING}/etc/init.d/S99hincyray" "$INIT_SCRIPT"
        ok "  → $INIT_SCRIPT"
    fi

    if [ -f "${STAGING}/etc/hincyray/wifi-segment-setup.sh" ]; then
        mkdir -p "$SCRIPTS_DIR"
        atomic_install "${STAGING}/etc/hincyray/wifi-segment-setup.sh" "${SCRIPTS_DIR}/wifi-segment-setup.sh"
        chmod +x "${SCRIPTS_DIR}/wifi-segment-setup.sh"
        ok "  → ${SCRIPTS_DIR}/wifi-segment-setup.sh"
    fi

    ok "All files installed atomically"
}

# ── Phase: start daemon and verify ───────────────────────────────────

start_and_verify() {
    step "Starting daemon and verifying"

    info "Starting hincyray..."
    HINCYRAY_LIFECYCLE_OWNER=$$ "$INIT_SCRIPT" start || {
        err "Daemon failed to start"
        warn "Last log lines:"
        tail -20 "${LOG_DIR}/hincyray.log" 2>/dev/null || true
        die "Health check cannot proceed"
    }

    NEW_PID="$(cat "$PID_FILE" 2>/dev/null)"
    process_is_daemon "$NEW_PID" || die "Init script did not register the installed daemon"

    # Wait for this exact daemon to remain alive and become ready.
    info "Waiting for daemon to be ready..."
    READY=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        HEALTH="$(curl -s --max-time 2 "http://127.0.0.1:${LISTEN_PORT}/api/health" 2>/dev/null || true)"
        if process_is_daemon "$NEW_PID" && printf '%s' "$HEALTH" | grep -q '"ok":true'; then
            READY=1
            break
        fi
        sleep 1
    done

    if [ "$READY" -eq 1 ]; then
        HEALTH=$(curl -s "http://127.0.0.1:${LISTEN_PORT}/api/health" 2>/dev/null)
        ok "Daemon healthy: ${HEALTH}"
    else
        err "Daemon did not become healthy within 10 seconds"
        warn "Last log lines:"
        tail -20 "${LOG_DIR}/hincyray.log" 2>/dev/null || true
        die "Health check failed — triggering rollback"
    fi

    STATUS="$(curl -s --max-time 3 "http://127.0.0.1:${LISTEN_PORT}/api/status")"
    ACTIVE_PROFILE="$(printf '%s' "$STATUS" | jq -r '.active_profile_id // empty')"
    ROUTING_ENABLED="$(curl -s --max-time 3 "http://127.0.0.1:${LISTEN_PORT}/api/routing/summary" | jq -r '.enabled // false')"
    if [ -n "$ACTIVE_PROFILE" ] || [ "$ROUTING_ENABLED" = "true" ]; then
        RUNTIME_READY=0
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            RUNTIME="$(curl -s --max-time 3 "http://127.0.0.1:${LISTEN_PORT}/api/safe-mode" 2>/dev/null || true)"
            CORE_STATUS="$(printf '%s' "$RUNTIME" | jq -r '.core_status // ""')"
            FIREWALL_STATUS="$(printf '%s' "$RUNTIME" | jq -r '.firewall_status // ""')"
            if { [ -z "$ACTIVE_PROFILE" ] || [ "$CORE_STATUS" = "running" ]; } \
                && { [ "$ROUTING_ENABLED" != "true" ] || [ "$FIREWALL_STATUS" = "running" ]; }; then
                RUNTIME_READY=1
                break
            fi
            sleep 1
        done
        [ "$RUNTIME_READY" -eq 1 ] \
            || die "Daemon API is healthy but proxy/firewall runtime did not recover"
    fi

    # Determine LAN IP for display.
    LAN_IP=$(ip -o addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $4}' | sed 's/\/.*//' | head -1)
    [ -z "$LAN_IP" ] && LAN_IP="<router-ip>"
    ok "Web panel: http://${LAN_IP}:${LISTEN_PORT}/"
}

# ── Phase: import subscription (post-commit, non-fatal) ──────────────

import_subscription() {
    step "Import subscription"

    SUB_URL="${HINCYRAY_SUB_URL:-}"
    if [ -z "$SUB_URL" ]; then
        if [ "${HINCYRAY_NONINTERACTIVE:-0}" = "1" ]; then
            info "Non-interactive mode, no subscription URL set — skipping"
            return 0
        fi
        SUB_URL=$(ask "Paste subscription URL or share link (vless://, vmess://, trojan://, ss://):")
    fi

    if [ -z "$SUB_URL" ]; then
        info "No subscription provided — import later via web panel"
        return 0
    fi

    API="http://127.0.0.1:${LISTEN_PORT}"
    info "Importing: ${SUB_URL}"
    RESULT=$(curl -s -X POST "${API}/api/profiles/import" --data-binary "$SUB_URL" 2>/dev/null)
    if echo "$RESULT" | grep -q '"imported"'; then
        COUNT=$(echo "$RESULT" | grep -o '"imported":[0-9]*' | grep -o '[0-9]*')
        ok "Imported ${COUNT} profiles"
    else
        warn "Import response: ${RESULT}"
        return 0
    fi

    # Select first profile.
    PROFILES=$(curl -s "${API}/api/profiles" 2>/dev/null)
    FIRST_ID=$(echo "$PROFILES" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
    if [ -n "$FIRST_ID" ]; then
        info "Selecting profile #${FIRST_ID}..."
        curl -s -X POST "${API}/api/active-profile" \
            -H 'Content-Type: application/json' \
            -d "{\"profile_id\":${FIRST_ID}}" >/dev/null 2>&1
        ok "Active profile set"

        info "Starting Xray core..."
        curl -s -X POST "${API}/api/core/start" >/dev/null 2>&1
        sleep 2

        STATUS=$(curl -s "${API}/api/status" 2>/dev/null)
        if echo "$STATUS" | grep -q '"core_status":"running"'; then
            ok "Xray core running"
            SOCKS_PORT=$(echo "$STATUS" | grep -o '"socks_port":[0-9]*' | grep -o '[0-9]*')
            EXIT_IP=$(curl -s --max-time 10 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://api.ipify.org 2>/dev/null)
            if [ -n "$EXIT_IP" ]; then
                ok "Tunnel working! Exit IP: ${EXIT_IP}"
            else
                warn "SOCKS test failed — check profile/server"
            fi
        else
            warn "Core did not start — check logs"
        fi
    fi
}

# ── Phase: WiFi VPN segment (post-commit, non-fatal) ─────────────────

setup_wifi() {
    step "WiFi VPN segment setup"

    if [ ! -f "${SCRIPTS_DIR}/wifi-segment-setup.sh" ]; then
        warn "wifi-segment-setup.sh not installed — skipping"
        return 0
    fi

    SSID=$(ask_default "WiFi SSID" "HincyRay-VPN")
    PASSWORD=$(ask_default "WiFi password" "HincyRayVPN2026")

    info "Creating WiFi segment ${SSID} on 192.168.2.0/24..."
    HINCYRAY_WIFI_SSID="$SSID" HINCYRAY_WIFI_PASSWORD="$PASSWORD" \
        sh "${SCRIPTS_DIR}/wifi-segment-setup.sh"
    ok "WiFi segment created"

    API="http://127.0.0.1:${LISTEN_PORT}"
    if ask_yn "Enable split routing in HincyRay now?"; then
        info "Enabling split routing..."
        curl -s -X POST "${API}/api/routing/settings" \
            -H 'Content-Type: application/json' \
            -d '{"enabled":true}' >/dev/null 2>&1
        curl -s -X POST "${API}/api/routing/apply" >/dev/null 2>&1
        sleep 2
        ok "Split routing enabled"

        if ask_yn "Save Keenetic configuration to flash?"; then
            ndmc -c "system configuration save" 2>/dev/null || true
            ok "Saved to flash"
        fi
    fi

    info "Connect a device to ${SSID} and verify at https://2ip.io/"
}

# ── Phase: auto-settings (post-commit, non-fatal) ────────────────────

setup_auto() {
    step "Auto-settings configuration"

    API="http://127.0.0.1:${LISTEN_PORT}"

    AUTO_SELECT="false"
    AUTO_SWITCH="false"
    BENCH_HOURS="0"

    if ask_yn "Enable auto-select (switch to best profile after benchmark)?"; then
        AUTO_SELECT="true"
    fi
    if ask_yn "Enable auto-switch/failover (switch on health check failure)?"; then
        AUTO_SWITCH="true"
    fi
    HOURS=$(ask_default "Auto-benchmark interval hours (0 = disabled)" "6")
    BENCH_HOURS="$HOURS"

    info "Saving auto-settings..."
    RESULT=$(curl -s -X POST "${API}/api/auto-settings" \
        -H 'Content-Type: application/json' \
        -d "{\"auto_select\":${AUTO_SELECT},\"auto_switch\":${AUTO_SWITCH},\"auto_bench_interval_hours\":${BENCH_HOURS}}" 2>/dev/null)

    if echo "$RESULT" | grep -q 'auto_select'; then
        ok "Auto-settings saved: select=${AUTO_SELECT}, switch=${AUTO_SWITCH}, bench=${BENCH_HOURS}h"
    else
        warn "Save failed: ${RESULT}"
    fi
}

# ── Phase: uninstall ─────────────────────────────────────────────────

do_uninstall() {
    step "Uninstall HincyRay"

    if ! ask_yn "This will remove HincyRay binary, init script, and state. Continue?"; then
        return 0
    fi

    # Stop daemon.
    if [ -f "$INIT_SCRIPT" ]; then
        "$INIT_SCRIPT" stop 2>/dev/null || true
    fi

    # Stop Xray and firewall via API.
    curl -s -X POST "http://127.0.0.1:${LISTEN_PORT}/api/core/stop" >/dev/null 2>&1 || true
    curl -s -X POST "http://127.0.0.1:${LISTEN_PORT}/api/routing/firewall-stop" >/dev/null 2>&1 || true
    sleep 2

    rm -f "$INIT_SCRIPT" "$DAEMON_BIN" "$PID_FILE"
    rm -f "${HINCYRAY_DIR}/state.json" "${HINCYRAY_DIR}/xray-client.json"
    rm -f "${HINCYRAY_DIR}/state.json.corrupt"
    rm -rf "$LOG_DIR"

    if ask_yn "Also remove Xray?"; then
        rm -f "$XRAY_LINK" "$XRAY_BIN"
        rm -f "${HINCYRAY_DIR}/geosite.dat"
    fi

    if ask_yn "Remove HincyRay directory entirely?"; then
        rm -rf "$SCRIPTS_DIR"
        rmdir "$HINCYRAY_DIR" 2>/dev/null || true
    fi

    if ask_yn "Also remove HincyRay-VPN WiFi segment?"; then
        ndmc -c "interface WifiMaster0/AccessPoint1 down" 2>/dev/null || true
        ndmc -c "interface WifiMaster1/AccessPoint1 down" 2>/dev/null || true
        ndmc -c "ip dhcp pool _HINCYRAY disable" 2>/dev/null || true
        ndmc -c "system configuration save" 2>/dev/null || true
    fi

    ok "HincyRay uninstalled"
}

# ── Full setup (atomic core + optional post-commit phases) ───────────

full_setup() {
    step "Full setup"
    info "This will install HincyRay v${VERSION} atomically."
    printf "${DIM}Phases: deps → stage all → commit → verify → configure${NC}\n\n"

    if [ "${HINCYRAY_NONINTERACTIVE:-0}" != "1" ]; then
        if ! ask_yn "Proceed with full setup?"; then
            return 1
        fi
    fi

    [ -z "$LEGACY_PKGS" ] \
        || die "Legacy proxy packages must be removed explicitly before HincyRay installation: $(echo "$LEGACY_PKGS" | tr '\n' ' ')"
    install_deps
    # ── HINCYRAY-OWNED TRANSACTION (rollback if any step fails) ──
    prepare_dirs
    stage_binary
    stage_xray
    stage_init
    stage_wifi_script

    # All files are staged and verified. Now commit atomically.
    commit_install

    # Verify: if this fails, the trap triggers rollback of all files.
    start_and_verify
    commit_transaction

    # ── POST-COMMIT (non-fatal — core is already committed) ──
    # These phases configure the running daemon. Failure here does NOT
    # trigger rollback — the installation is valid, just unconfigured.

    WANT_WIFI=0
    WANT_AUTO=0
    if [ "${HINCYRAY_NONINTERACTIVE:-0}" != "1" ]; then
        ask_yn "Import subscription now?" && import_subscription
        ask_yn "Set up WiFi VPN segment?" && setup_wifi
        ask_yn "Configure auto-settings?" && setup_auto
    else
        import_subscription
    fi

    step "Setup complete!"
    ok "HincyRay v${VERSION} is installed and running."
    LAN_IP=$(ip -o addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $4}' | sed 's/\/.*//' | head -1)
    [ -z "$LAN_IP" ] && LAN_IP="<router-ip>"
    info "Web panel: http://${LAN_IP}:${LISTEN_PORT}/"
    info "Logs: ${LOG_DIR}/hincyray.log"
    info "State: ${HINCYRAY_DIR}/state.json"
    printf "\n${DIM}To save WiFi config to flash: ndmc -c 'system configuration save'${NC}\n"
}

# ── Individual atomic operations ─────────────────────────────────────

do_install_binary() {
    prepare_dirs
    stage_binary
    stage_init
    commit_install
    start_and_verify
    commit_transaction
    ok "Binary upgraded atomically"
}

do_install_xray() {
    prepare_dirs
    stage_xray
    commit_install
    commit_transaction
    ok "Xray installed atomically"
}

do_install_deps() {
    install_deps
    ok "Dependencies installed"
}

do_init_start() {
    prepare_dirs
    stage_init
    commit_install
    start_and_verify
    commit_transaction
}

# ── Menu ─────────────────────────────────────────────────────────────

show_menu() {
    printf "\n"
    printf "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}${CYAN}║       HincyRay v%s Installer (atomic)              ║${NC}\n" "$VERSION"
    printf "${BOLD}${CYAN}╠══════════════════════════════════════════════════════╣${NC}\n"
    printf "${BOLD}${CYAN}║  1. Full setup (recommended)                        ║${NC}\n"
    printf "${BOLD}${CYAN}║  2. Install/upgrade binary only                     ║${NC}\n"
    printf "${BOLD}${CYAN}║  3. Install/upgrade Xray core                       ║${NC}\n"
    printf "${BOLD}${CYAN}║  4. Install dependencies                            ║${NC}\n"
    printf "${BOLD}${CYAN}║  5. Install init script + start daemon              ║${NC}\n"
    printf "${BOLD}${CYAN}║  6. Import subscription                             ║${NC}\n"
    printf "${BOLD}${CYAN}║  7. Setup WiFi VPN segment                          ║${NC}\n"
    printf "${BOLD}${CYAN}║  8. Configure auto-settings                         ║${NC}\n"
    printf "${BOLD}${CYAN}║  9. Uninstall HincyRay                              ║${NC}\n"
    printf "${BOLD}${CYAN}║  0. Exit                                            ║${NC}\n"
    printf "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "${DIM}Atomic: all file operations use staging + backup + rollback.${NC}\n"
    printf "${DIM}If any step fails, the system is restored to its previous state.${NC}\n"
    printf "\n"
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
    detect_env

    # Non-interactive mode: run full setup directly.
    if [ "${HINCYRAY_NONINTERACTIVE:-0}" = "1" ]; then
        info "Non-interactive mode — running full setup"
        full_setup
        return $?
    fi

    while true; do
        show_menu
        CHOICE=$(ask "Select option [0-9]")

        case "$CHOICE" in
            1) full_setup ;;
            2) do_install_binary ;;
            3) do_install_xray ;;
            4) do_install_deps ;;
            5) do_init_start ;;
            6) import_subscription ;;
            7) setup_wifi ;;
            8) setup_auto ;;
            9) do_uninstall ;;
            0|q|Q) info "Goodbye!"; exit 0 ;;
            *) warn "Invalid option: ${CHOICE}" ;;
        esac

        printf "\n"
        if ! ask_yn "Return to menu?"; then
            info "Goodbye!"
            exit 0
        fi
    done
}

main "$@"
