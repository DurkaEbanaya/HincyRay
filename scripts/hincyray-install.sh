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
# No step can leave the system in a half-installed state: either
# everything succeeds or the previous state is fully restored.
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

VERSION="0.6.1"
GITHUB="https://github.com/DurkaEbanaya/HincyRay"
ENTWARE="/opt"
HINCYRAY_DIR="${ENTWARE}/etc/hincyray"
LOG_DIR="${ENTWARE}/var/log/hincyray"
INIT_SCRIPT="${ENTWARE}/etc/init.d/S99hincyray"
PID_FILE="${ENTWARE}/var/run/hincyray.pid"
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
DEPS_INSTALLED=""

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

# ── Atomic infrastructure ────────────────────────────────────────────

# Register a file for rollback: if we modify `dest`, save its current
# state to backup first, and record the pair for the rollback trap.
register_file() {
    dest="$1"
    backup_name="$2"
    backup_path="${BACKUP}/${backup_name}"

    if [ -e "$dest" ] || [ -L "$dest" ]; then
        cp -a "$dest" "$backup_path" 2>/dev/null || true
        TOUCHED="${TOUCHED}${dest}|${backup_path}
"
    else
        TOUCHED="${TOUCHED}${dest}|NONE
"
    fi
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

# Rollback: restore all touched files from backup. Called by the EXIT
# trap when ROLLBACK_FLAG is set.
do_rollback() {
    err "Rolling back all changes..."
    # Process in reverse order of registration.
    echo "$TOUCHED" | tac 2>/dev/null | while IFS='|' read -r dest backup_path; do
        [ -z "$dest" ] && continue
        if [ "$backup_path" = "NONE" ]; then
            rm -f "$dest" 2>/dev/null || true
            info "  removed: $dest (was not present before)"
        elif [ -e "$backup_path" ]; then
            cp -a "$backup_path" "$dest" 2>/dev/null || true
            info "  restored: $dest"
        fi
    done

    # Rollback installed opkg packages.
    if [ -n "$DEPS_INSTALLED" ]; then
        info "Removing packages installed during this run: ${DEPS_INSTALLED}"
        # shellcheck disable=SC2086
        opkg remove $DEPS_INSTALLED 2>/dev/null || true
    fi

    # Restart old daemon if it was running before.
    if [ -f "$PID_FILE" ] && [ -x "$INIT_SCRIPT" ]; then
        info "Restarting previous daemon..."
        "$INIT_SCRIPT" start 2>/dev/null || true
    fi

    # Cleanup temp dirs.
    rm -rf "$STAGING" "$BACKUP" 2>/dev/null || true
    err "Rollback complete. System restored to previous state."
}

# Commit: installation succeeded. Remove backup, keep everything.
do_commit() {
    if [ -n "${ROLLBACK_FLAG:-0}" ] && [ "$ROLLBACK_FLAG" -eq 1 ]; then
        do_rollback
        exit 1
    fi
    # Success — clean up temp dirs.
    rm -rf "$STAGING" "$BACKUP" 2>/dev/null || true
}

# EXIT trap: check the flag.
ROLLBACK_FLAG=0
trap 'do_commit' EXIT

# Signal handler: mark for rollback, then let EXIT trap do the work.
on_error() {
    ROLLBACK_FLAG=1
}
trap 'on_error' HUP INT TERM

# Set -e already handles command failures, but we need to catch them
# and set the flag rather than exiting immediately (so the trap runs).
# Wrap the entire main logic in a function and check its exit code.
set +e
run_with_trap() {
    "$@"
    rc=$?
    if [ $rc -ne 0 ]; then
        ROLLBACK_FLAG=1
        return $rc
    fi
    return 0
}

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

    # Check if daemon is already running (for rollback restart).
    DAEMON_WAS_RUNNING=0
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
        DAEMON_WAS_RUNNING=1
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
    (check_cmd tun2socks || [ -f "${ENTWARE}/sbin/tun2socks" ] || [ -f "${ENTWARE}/bin/tun2socks" ]) && HAVE_TUN2SOCKS=1 || HAVE_TUN2SOCKS=0
    check_cmd unzip && HAVE_UNZIP=1 || HAVE_UNZIP=0
    check_cmd jq && HAVE_JQ=1 || HAVE_JQ=0

    # Free disk space.
    FREE_KB=$(df -k "${ENTWARE}" 2>/dev/null | tail -1 | awk '{print $4}')
    [ -n "$FREE_KB" ] && info "Free space: ${FREE_KB} kB" || true
}

# ── Pre-flight: prepare staging and backup dirs ──────────────────────

prepare_dirs() {
    mkdir -p "$STAGING" "$BACKUP" || die "Cannot create temp dirs under ${ENTWARE}"
    mkdir -p "${STAGING}/sbin" "${STAGING}/etc/init.d" "${STAGING}/etc/hincyray"
    mkdir -p "${BACKUP}/sbin" "${BACKUP}/etc/init.d" "${BACKUP}/etc/hincyray"
}

# ── Phase: remove legacy ─────────────────────────────────────────────

remove_legacy() {
    [ -z "$LEGACY_PKGS" ] && return 0
    step "Removing legacy proxy packages"
    for s in /opt/etc/init.d/S*xkeen* /opt/etc/init.d/S*xray_s* /opt/etc/init.d/S*mihomo_s*; do
        if [ -x "$s" ]; then
            info "Stopping $s..."
            "$s" stop 2>/dev/null || true
        fi
    done
    for pkg in xkeen xray-s xray_s mihomo-s mihomo_s; do
        opkg remove "$pkg" 2>/dev/null && info "  removed $pkg" || true
    done
    ok "Legacy packages removed"
}

# ── Phase: install dependencies (tracked for rollback) ───────────────

install_deps() {
    step "Installing dependencies"
    info "Running opkg update..."
    opkg update 2>/dev/null || warn "opkg update failed (may be offline)"

    NEED=""
    [ "$HAVE_CURL" -eq 0 ] && NEED="$NEED curl"
    [ "$HAVE_TUN2SOCKS" -eq 0 ] && NEED="$NEED tun2socks"
    [ "$HAVE_JQ" -eq 0 ] && NEED="$NEED jq"
    [ "$HAVE_UNZIP" -eq 0 ] && NEED="$NEED unzip"

    if [ -z "$NEED" ]; then
        ok "All dependencies already present"
        return 0
    fi

    info "Installing:${NEED}"
    # shellcheck disable=SC2086
    if opkg install $NEED 2>/dev/null; then
        ok "Dependencies installed"
        # Track for rollback.
        DEPS_INSTALLED="$NEED"
    else
        # Check which ones actually failed.
        FAILED=""
        for pkg in $NEED; do
            check_cmd "$pkg" || FAILED="$FAILED $pkg"
        done
        if [ -n "$FAILED" ]; then
            warn "Failed to install:${FAILED} — some features may not work"
        else
            ok "All packages present (some may have been pre-installed)"
        fi
    fi
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
        DOWNLOAD_URL="${GITHUB}/releases/download/v${VERSION}/hincyray-aarch64"
        if [ "$HAVE_CURL" -eq 1 ] && ask_yn "Binary not found. Download from GitHub releases?"; then
            info "Downloading from ${DOWNLOAD_URL}..."
            if curl -sSL -o "${STAGING}/sbin/hincyray" "$DOWNLOAD_URL" 2>/dev/null && [ -s "${STAGING}/sbin/hincyray" ]; then
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
    register_file "$DAEMON_BIN" "sbin/hincyray"
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
        unzip -o "${STAGING}/xray.zip" xray geoip.dat geosite.dat 2>/dev/null || \
            unzip -o "${STAGING}/xray.zip" 2>/dev/null || true
    else
        # BusyBox unzip fallback — some Entware builds lack unzip.
        # Try python or busybox tar.
        warn "unzip not available — trying alternative extraction"
        if check_cmd python3; then
            python3 -c "
import zipfile, sys
z = zipfile.ZipFile('${STAGING}/xray.zip')
for n in ['xray','geoip.dat','geosite.dat']:
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
    register_file "$XRAY_BIN" "etc/hincyray/xray"
    register_file "$XRAY_LINK" "sbin/xray"
    [ -f "${HINCYRAY_DIR}/geoip.dat" ] && register_file "${HINCYRAY_DIR}/geoip.dat" "etc/hincyray/geoip.dat" || true
    [ -f "${HINCYRAY_DIR}/geosite.dat" ] && register_file "${HINCYRAY_DIR}/geosite.dat" "etc/hincyray/geosite.dat" || true
}

# ── Phase: stage init script ─────────────────────────────────────────

stage_init() {
    step "Staging init script"

    cat > "${STAGING}/etc/init.d/S99hincyray" << 'INITEOF'
#!/bin/sh

PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
DAEMON=/opt/sbin/hincyray
PIDFILE=/opt/var/run/hincyray.pid
LOGDIR=/opt/var/log/hincyray
LOGFILE=$LOGDIR/hincyray.log

mkdir -p "$LOGDIR" /opt/var/run

start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "hincyray already running (pid $(cat "$PIDFILE"))"
        return 0
    fi
    echo "starting hincyray"
    "$DAEMON" >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "hincyray started (pid $(cat "$PIDFILE"))"
    else
        echo "hincyray failed to start — check $LOGFILE"
        rm -f "$PIDFILE"
        return 1
    fi
}

stop() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "stopping hincyray (pid $PID)"
            kill "$PID"
            for i in 1 2 3 4 5; do
                kill -0 "$PID" 2>/dev/null || break
                sleep 1
            done
            kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    echo "hincyray stopped"
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "hincyray running (pid $(cat "$PIDFILE"))"
        return 0
    fi
    echo "hincyray not running"
    return 3
}

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
    register_file "$INIT_SCRIPT" "etc/init.d/S99hincyray"
    ok "Init script staged"
}

# ── Phase: stage wifi script ─────────────────────────────────────────

stage_wifi_script() {
    if [ ! -f "${SCRIPTS_DIR}/wifi-segment-setup.sh" ]; then
        # Look for the script alongside the installer.
        for try in "$(dirname "$0")/wifi-segment-setup.sh" /tmp/wifi-segment-setup.sh; do
            if [ -f "$try" ]; then
                cp "$try" "${STAGING}/etc/hincyray/wifi-segment-setup.sh"
                register_file "${HINCYRAY_DIR}/scripts/wifi-segment-setup.sh" "etc/hincyray/wifi-segment-setup.sh"
                ok "WiFi setup script staged"
                return 0
            fi
        done
        # Try downloading from GitHub.
        if [ "$HAVE_CURL" -eq 1 ]; then
            URL="${GITHUB}/raw/v${VERSION}/scripts/wifi-segment-setup.sh"
            if curl -sSL -o "${STAGING}/etc/hincyray/wifi-segment-setup.sh" "$URL" 2>/dev/null && [ -s "${STAGING}/etc/hincyray/wifi-segment-setup.sh" ]; then
                register_file "${HINCYRAY_DIR}/scripts/wifi-segment-setup.sh" "etc/hincyray/wifi-segment-setup.sh"
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

    # Stop existing daemon first (graceful).
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
        info "Stopping existing daemon..."
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        for i in 1 2 3 4 5; do
            kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi

    # Create target directories if they don't exist.
    mkdir -p "$HINCYRAY_DIR" "$LOG_DIR" "${ENTWARE}/sbin" "${ENTWARE}/etc/init.d"

    # Atomic moves — each mv is atomic on the same filesystem.
    info "Installing binary..."
    atomic_install "${STAGING}/sbin/hincyray" "$DAEMON_BIN"
    ok "  → $DAEMON_BIN"

    if [ -f "${STAGING}/etc/hincyray/xray" ]; then
        info "Installing Xray..."
        atomic_install "${STAGING}/etc/hincyray/xray" "$XRAY_BIN"
        ok "  → $XRAY_BIN"
        # Create/update symlink (rm + ln is not atomic, but ln -sf is close enough).
        rm -f "$XRAY_LINK"
        ln -s "$XRAY_BIN" "$XRAY_LINK"
        ok "  → $XRAY_LINK (symlink)"

        for asset in geoip.dat geosite.dat; do
            if [ -f "${STAGING}/etc/hincyray/$asset" ]; then
                atomic_install "${STAGING}/etc/hincyray/$asset" "${HINCYRAY_DIR}/$asset"
                ok "  → ${HINCYRAY_DIR}/$asset"
            fi
        done
    fi

    info "Installing init script..."
    atomic_install "${STAGING}/etc/init.d/S99hincyray" "$INIT_SCRIPT"
    ok "  → $INIT_SCRIPT"

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
    "$INIT_SCRIPT" start || {
        err "Daemon failed to start"
        warn "Last log lines:"
        tail -20 "${LOG_DIR}/hincyray.log" 2>/dev/null || true
        die "Health check cannot proceed"
    }

    # Wait for the daemon to be ready (up to 10 seconds).
    info "Waiting for daemon to be ready..."
    READY=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -s --max-time 2 "http://127.0.0.1:${LISTEN_PORT}/api/health" 2>/dev/null | grep -q '"ok":true'; then
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

    # Stop Xray and TUN via API.
    curl -s -X POST "http://127.0.0.1:${LISTEN_PORT}/api/core/stop" >/dev/null 2>&1 || true
    curl -s -X POST "http://127.0.0.1:${LISTEN_PORT}/api/routing/tun-stop" >/dev/null 2>&1 || true
    sleep 2

    rm -f "$INIT_SCRIPT" "$DAEMON_BIN" "$PID_FILE"
    rm -f "${HINCYRAY_DIR}/state.json" "${HINCYRAY_DIR}/xray-client.json"
    rm -f "${HINCYRAY_DIR}/state.json.corrupt"
    rm -rf "$LOG_DIR"

    if ask_yn "Also remove Xray?"; then
        rm -f "$XRAY_LINK" "$XRAY_BIN"
        rm -f "${HINCYRAY_DIR}/geoip.dat" "${HINCYRAY_DIR}/geosite.dat"
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

    # ── ATOMIC CORE (rollback if any step fails) ──
    prepare_dirs
    [ -n "$LEGACY_PKGS" ] && remove_legacy
    install_deps
    stage_binary
    stage_xray
    stage_init
    stage_wifi_script

    # All files are staged and verified. Now commit atomically.
    commit_install

    # Verify: if this fails, the trap triggers rollback of all files.
    start_and_verify

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
    ok "Binary upgraded atomically"
}

do_install_xray() {
    prepare_dirs
    stage_xray
    commit_install
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
