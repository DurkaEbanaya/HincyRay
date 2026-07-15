# HincyRay v0.1 &mdash; Keenetic Entware install / runbook

> **v0.7.0 Fixed note:** current HincyRay transparent routing no longer uses the old v0.1.1/v0.4 helper-script TPROXY/tun2socks path described later in this historical runbook. The daemon now installs NAT REDIRECT + TPROXY rules itself and matches clients by Keenetic traffic-policy connmark. For WiFi VPN clients, creating the `HincyRay-VPN` SSID is not sufficient: every client MAC must be assigned to the Keenetic policy used by HincyRay (for example `Policy0` with description `XKeen`).
>
> ```bash
> # Replace with the real client MAC address.
> ndmc -c 'ip hotspot host <client-mac> policy Policy0'
> ndmc -c 'system configuration save'
> ```
>
> Verify that the client is really marked and then redirected:
>
> ```bash
> ndmc -c 'show running-config' | grep -i '<client-mac>'
> iptables -t mangle -L _NDM_HOTSPOT_PREROUTING_MANGL -n -v | grep -i '<client-mac>'
> iptables -t nat -L HINCYRAY -n -v
> ```
>
> Expected: `host <client-mac> policy Policy0`, `MARK set 0xffffaaa`, `CONNMARK save`, and increasing `HINCYRAY` counters when the client opens a site. If the host is `conform`, Keenetic emits a plain `RETURN` for that MAC and HincyRay will not see the traffic.

This is the concrete install and operations guide for HincyRay v0.1 on a Keenetic Giga KN-1012 running Keenetic Homebrew / Entware (aarch64). It is written for an isolated router that may not be able to fetch artifacts directly, so several steps fetch files on a workstation and copy them over `scp`.

v0.1 is a **safe SOCKS-only MVP**. It does **not** install `iptables` / `ip rule` / `nftables` rules, Keenetic routing hooks, or any system-wide policy routing. It only starts Xray with a local SOCKS listener on the router at `127.0.0.1:10808`, and you validate by curling through that SOCKS from the router itself. Your main workstation IP and default route are not touched.

If anything goes wrong, see [Rollback / stop](#rollback--stop) at the bottom.

## Prerequisites

- Keenetic Giga KN-1012 with Keenetic Homebrew / Entware installed and SSH access (`ssh root@<router-ip>`).
- Entware aarch64 userspace at `/opt` with `/opt/etc/init.d/` available.
- A workstation with Rust 2024, `scp`, and `curl`.
- An Xray-core ARM64 binary. v0.1 was validated with the official XTLS/Xray-core ARM64 release.
- `geoip.dat` and `geosite.dat` assets compatible with the Xray version above.
- A VLESS profile reachable through the router (Hysteria2 is **not** supported in v0.1 because Xray does not speak it; selecting one returns a 400).

## Step 0 &mdash; Build the HincyRay binary on the workstation

The router build skips the desktop feature so `eframe` / `egui_extras` / `arboard` are not pulled in:

```bash
cargo build --release --no-default-features --bin hincyray
```

If you need an aarch64-linux target, cross-compile with the appropriate toolchain (e.g. `cargo build --release --no-default-features --bin hincyray --target aarch64-unknown-linux-gnu`). The binary will be at `target/release/hincyray` (or under `target/<triple>/release/hincyray`).

## Step 1 &mdash; Remove old xkeen / xray_s / mihomo_s carefully

The router may have legacy proxy packages from earlier setups. Remove them so they do not race HincyRay for port 10808 or restart Xray behind your back.

First, list what is installed and running:

```bash
ssh root@<router-ip> '
  opkg list-installed | grep -E "xkeen|xray|mihomo|sing-box" ;
  ps | grep -E "xray|mihomo|sing-box|xkeen" | grep -v grep
'
```

Stop their init scripts (Entware init scripts are `/opt/etc/init.d/SNN*`):

```bash
ssh root@<router-ip> '
  for s in /opt/etc/init.d/S*xkeen* /opt/etc/init.d/S*xray_s* /opt/etc/init.d/S*mihomo_s* ; do
    [ -x "$s" ] && "$s" stop
  done
'
```

Disable them so they do not start on boot, then remove the packages:

```bash
ssh root@<router-ip> '
  opkg remove xkeen 2>/dev/null
  opkg remove xray-s 2>/dev/null
  opkg remove xray_s 2>/dev/null
  opkg remove mihomo-s 2>/dev/null
  opkg remove mihomo_s 2>/dev/null
'
```

Verify nothing is listening on 10808/10809/8088 before proceeding:

```bash
ssh root@<router-ip> 'netstat -ltnp 2>/dev/null | grep -E ":10808|:10809|:8088" || true'
```

> Do **not** remove Keenetic system packages or Entware core. Only remove the legacy proxy packages above.

## Step 2 &mdash; Create HincyRay directories on the router

```bash
ssh root@<router-ip> '
  mkdir -p /opt/etc/hincyray
  mkdir -p /opt/var/log/hincyray
  mkdir -p /opt/sbin
'
```

## Step 3 &mdash; Fetch Xray assets on the workstation and copy via scp

The router is often isolated, so fetch on the workstation first. Replace `<xray-version>` with the XTLS/Xray-core release tag you want (the v0.1 validation used a current ARM64 release).

```bash
# On the workstation:
curl -L -o xray.zip "https://github.com/XTLS/Xray-core/releases/download/<xray-version>/Xray-linux-arm64-v<xray-version>.zip"
unzip -l xray.zip   # confirm it contains: xray, geoip.dat, geosite.dat
```

Copy the Xray binary, the assets, and the HincyRay binary to the router:

```bash
# Xray binary and assets
scp xray.zip root@<router-ip>:/tmp/xray.zip
ssh root@<router-ip> '
  cd /opt/etc/hincyray && unzip -o /tmp/xray.zip xray geoip.dat geosite.dat
  chmod +x /opt/etc/hincyray/xray
  ln -sf /opt/etc/hincyray/xray /opt/sbin/xray
  rm -f /tmp/xray.zip
'

# HincyRay binary built in Step 0
scp target/release/hincyray root@<router-ip>:/opt/sbin/hincyray
ssh root@<router-ip> 'chmod +x /opt/sbin/hincyray'
```

Verify on the router:

```bash
ssh root@<router-ip> '
  /opt/sbin/xray version
  /opt/sbin/hincyray --help 2>&1 | head -1 || true
  ls -l /opt/etc/hincyray /opt/sbin/hincyray /opt/sbin/xray
'
```

Expected paths after this step:

- `/opt/etc/hincyray/xray` &mdash; Xray binary (real file).
- `/opt/sbin/xray` &mdash; symlink to the above, so `xray` resolves in `PATH`.
- `/opt/etc/hincyray/geoip.dat`, `/opt/etc/hincyray/geosite.dat` &mdash; Xray assets.
- `/opt/sbin/hincyray` &mdash; HincyRay daemon binary.

## Step 4 &mdash; Install the init script

Install `/opt/etc/init.d/S99hincyray` through `scripts/hincyray-install.sh` (menu item **Install init script + start daemon**). The installer is the canonical owner of this lifecycle contract. Its generated script serializes lifecycle operations, detaches the daemon with `nohup`, stores the authoritative PID in `/opt/var/run/hincyray.pid`, and verifies `/proc/<pid>/exe` before every signal. Do not replace it with a process-name scan or a hand-written PID-only template: both can terminate the invoking SSH shell or signal an unrelated process after PID reuse.

Install and enable it:

```bash
ssh root@<router-ip> '
  chmod +x /opt/etc/init.d/S99hincyray
  /opt/etc/init.d/S99hincyray start
  sleep 1
  /opt/etc/init.d/S99hincyray status
'
```

Confirm the daemon is listening on `8088`:

```bash
ssh root@<router-ip> 'netstat -ltnp 2>/dev/null | grep :8088'
curl -sS http://<router-ip>:8088/api/health
```

The health endpoint should return something like `{"ok":true,"service":"hincyray","version":"0.1.0"}`.

## Step 5 &mdash; Import subscriptions in an isolated network

If the router can reach the subscription URL directly, import via the API:

```bash
curl -sS -X POST http://<router-ip>:8088/api/profiles/import \
  --data-binary 'https://provider.example/sub/<token>'
```

If the router is isolated or the provider rejects non-Happ clients, fetch on the workstation with Happ headers, then upload the decoded JSON:

```bash
# On the workstation: fetch with Happ Android headers (the daemon does this
# automatically when given a URL, but on an isolated router you must do it
# yourself).
curl -sS "https://provider.example/sub/<token>" \
  -H 'User-Agent: Happ/3.22.1' \
  -H 'X-HWID: 0000000000000000' \
  -H 'X-Ver-OS: 15' \
  -H 'X-Bundle-ID: su.happ.proxyutility' \
  -H 'X-Device-model: GM1911' \
  -H 'X-Device-OS: Android' \
  -H 'X-API-Version: 1.0' \
  -o sub-raw.txt

# If the body is base64, decode it. The daemon also tries base64 variants on
# import, so you can usually just upload the raw body. To decode on the
# workstation:
#   base64 -d sub-raw.txt > sub-decoded.json   # macOS: base64 -D
```

Then either paste the decoded JSON into the web panel's import box at `http://<router-ip>:8088/`, or POST it to the API:

```bash
curl -sS -X POST http://<router-ip>:8088/api/profiles/import \
  --data-binary @sub-decoded.json
```

The parser accepts direct `vless://` / `hysteria2://` / `hy2://` links, Xray-style JSON with `outbounds`, and HTTPS subscription URLs. For Happ/TutNet Xray-style JSON that contains DNS-over-HTTPS URLs, the parser falls back to `outbounds` parsing when no direct profiles are found, so embedded DNS URLs are not mistaken for subscriptions.

List imported profiles to confirm:

```bash
curl -sS http://<router-ip>:8088/api/profiles | head -200
```

## Step 6 &mdash; Select the active profile

Pick the profile id from the `/api/profiles` list (the `id` field, zero-based):

```bash
curl -sS -X POST http://<router-ip>:8088/api/active-profile \
  -H 'Content-Type: application/json' \
  --data '{"profile_id":0}'
```

The response includes `xray_config_path` (default `/opt/etc/hincyray/xray-client.json`). If you select a Hysteria2 profile, you get a 400 with a clear error &mdash; Hysteria2 is not supported by the Xray backend in v0.1.

You can also pick the profile from the web panel table at `http://<router-ip>:8088/`.

Inspect the generated config if needed:

```bash
curl -sS http://<router-ip>:8088/api/xray/config
ssh root@<router-ip> 'cat /opt/etc/hincyray/xray-client.json'
```

## Step 7 &mdash; Start the core

```bash
curl -sS -X POST http://<router-ip>:8088/api/core/start
curl -sS http://<router-ip>:8088/api/status
```

`/api/status` should report `"core_status":"running"`. The daemon runs `xray run -format json -c /opt/etc/hincyray/xray-client.json` as a child process.

You can also use the web panel buttons or the init script (which controls the daemon, not Xray directly):

```bash
ssh root@<router-ip> '/opt/etc/init.d/S99hincyray restart'
```

## Step 8 &mdash; Validate via router-local SOCKS

**Important:** this step does **not** change your workstation routes. You are curling from the router through its own local SOCKS listener.

From the router SSH session:

```bash
# Through the SOCKS proxy
curl -sS --socks5-hostname 127.0.0.1:10808 https://api.ipify.org
curl -sS --socks5-hostname 127.0.0.1:10808 https://2ip.io/
```

The IP returned should be the proxy server's exit IP, not your home IP. In the v0.1 validation on KN-1012, the active profile was `Satellite` from a TutNet subscription, and the router-local SOCKS curl returned the proxy exit IP while the workstation's direct IP was unchanged.

Sanity check that your workstation's direct IP is **not** changed (run from the workstation, not through SOCKS):

```bash
curl -sS https://api.ipify.org
```

If the workstation IP is unchanged and the router-local SOCKS curl shows the proxy exit IP, v0.1 is working as designed.

## WiFi VPN segment setup (v0.1.1, opt-in)

v0.1.1 adds an **opt-in** path to route a separate WiFi segment through Xray via TPROXY. The daemon stays SOCKS-only by default; the WiFi VPN segment is set up by four shell scripts under `scripts/`. Nothing is installed automatically.

Copy the scripts to the router once:

```bash
scp -r scripts root@<router-ip>:/opt/etc/hincyray/scripts
ssh root@<router-ip> 'chmod +x /opt/etc/hincyray/scripts/*.sh'
```

Pre-flight: the daemon must already be running with an active VLESS profile and a started Xray core (Steps 4&ndash;7 above), and `jq` must be installed on the router (the Xray config patch script needs it):

```bash
ssh root@<router-ip> 'opkg update && opkg install jq'
```

Then run, in order, on the router:

```bash
# 1. Create the HincyRay-VPN WiFi segment on 192.168.2.0/24 (2.4 + 5 GHz).
#    Override defaults with HINCYRAY_WIFI_PASSWORD / HINCYRAY_WIFI_SSID /
#    HINCYRAY_WIFI_SUBNET / HINCYRAY_WIFI_GATEWAY if needed.
ssh root@<router-ip> 'sh /opt/etc/hincyray/scripts/wifi-segment-setup.sh'

# 2. Patch the generated Xray config with a dokodemo-door TPROXY inbound
#    on 0.0.0.0:10810, then restart the core so Xray picks it up.
ssh root@<router-ip> 'sh /opt/etc/hincyray/scripts/xray-tproxy-inbound.sh'
curl -sS -X POST http://<router-ip>:8088/api/core/restart

# 3. Install iptables mangle TPROXY rules + policy routing for
#    192.168.2.0/24 only. 192.168.1.0/24 is not touched.
ssh root@<router-ip> 'sh /opt/etc/hincyray/scripts/tproxy-setup.sh'
```

Test:

1. Connect a phone to the `HincyRay-VPN` SSID (default password `HincyRayVPN2026`; override it in production via `HINCYRAY_WIFI_PASSWORD`).
2. On the phone, open `https://2ip.io/` or `https://api.ipify.org`. The IP shown should be the **proxy exit IP**, not your home IP. YouTube and other blocked services should work.
3. From a device on the main `192.168.1.0/24` network, confirm the IP is unchanged and the default route is intact:

   ```bash
   curl -sS https://api.ipify.org
   ```

4. On the router, verify the rules:

   ```bash
   ssh root@<router-ip> '
     iptables -t mangle -S HINCYRAY
     ip rule show | grep 0x111
   '
   ```

Rollback (no reboot needed):

```bash
# Removes iptables rules, the HINCYRAY chain, and the policy-routing table.
# After this, 192.168.2.0/24 routes direct again.
ssh root@<router-ip> 'sh /opt/etc/hincyray/scripts/tproxy-rollback.sh'

# Optional: take the HincyRay-VPN SSID down entirely.
ssh root@<router-ip> '
  ndmc -c "interface WifiMaster0/AccessPoint1 down"
  ndmc -c "interface WifiMaster1/AccessPoint1 down"
'
```

Save the WiFi segment to flash (the `iptables` rules are **not** persisted by this; re-run `tproxy-setup.sh` after every reboot):

```bash
ssh root@<router-ip> 'ndmc -c "system configuration save"'
```

Notes:

- Only `192.168.2.0/24` is steered through Xray. `192.168.1.0/24` (Home) keeps the main uplink.
- The Xray config patch (`xray-tproxy-inbound.sh`) is idempotent and skips if a `dokodemo-door` inbound already exists. Re-selecting the active profile through the HincyRay API regenerates `xray-client.json` **without** the TPROXY inbound, so after a profile switch you must re-run the patch and then `POST /api/core/restart` before TPROXY routing works again.
- Keenetic ships the `xt_TPROXY` / `xt_socket` kernel modules built-in; no `modprobe` is needed on KN-1012.

## Logs and state

- Daemon log: `/opt/var/log/hincyray/hincyray.log` (whatever the init script redirects to).
- State file: `/opt/etc/hincyray/state.json` (profiles, active profile, ports, xray path, metrics placeholder, routing rules placeholder).
- Generated Xray config: `/opt/etc/hincyray/xray-client.json`.
- Xray binary: `/opt/etc/hincyray/xray` with symlink `/opt/sbin/xray`.
- Xray assets: `/opt/etc/hincyray/geoip.dat`, `/opt/etc/hincyray/geosite.dat`.

Xray's own stdout/stderr are discarded by the daemon in v0.1 (intentionally, so the long-lived child does not block on a buffered pipe). If you need Xray logs, run `xray` manually with `-c /opt/etc/hincyray/xray-client.json` and stdout to a file, after stopping the daemon-managed core.

## Rollback / stop

To stop the Xray core but keep the daemon running:

```bash
curl -sS -X POST http://<router-ip>:8088/api/core/stop
```

To stop the daemon entirely (this also stops the daemon-managed Xray child because the daemon exits; if you want to be explicit, call `/api/core/stop` first):

```bash
ssh root@<router-ip> '/opt/etc/init.d/S99hincyray stop'
```

To disable autostart on boot without uninstalling:

```bash
ssh root@<router-ip> 'chmod -x /opt/etc/init.d/S99hincyray'
```

To fully uninstall HincyRay (Xray is left in place so you can reuse it):

```bash
ssh root@<router-ip> '
  /opt/etc/init.d/S99hincyray stop
  rm -f /opt/etc/init.d/S99hincyray
  rm -f /opt/sbin/hincyray
  rm -f /opt/etc/hincyray/state.json /opt/etc/hincyray/xray-client.json
  rmdir /opt/etc/hincyray 2>/dev/null || true
  rm -rf /opt/var/log/hincyray
'
```

To also remove Xray (only if you are sure nothing else uses it):

```bash
ssh root@<router-ip> '
  rm -f /opt/sbin/xray /opt/etc/hincyray/xray
  rm -f /opt/etc/hincyray/geoip.dat /opt/etc/hincyray/geosite.dat
  rmdir /opt/etc/hincyray 2>/dev/null || true
'
```

## What v0.1 deliberately does not do (by default)

- No `iptables` / `ip rule` / `nftables` rules installed by the daemon itself.
- No Keenetic routing hooks or service mesh installed by the daemon.
- No transparent proxy or system-wide policy routing installed by the daemon.
- No automatic server selection or failover.
- No Hysteria2 backend.
- No changes to your workstation IP or default route.

The **v0.1.1 opt-in WiFi VPN segment** is the only exception: the four `scripts/` add `iptables` mangle TPROXY rules + a policy-routing table that steer `192.168.2.0/24` through Xray. They are run manually, only affect that subnet, and are not saved to flash unless you run `ndmc -c "system configuration save"`. See [WiFi VPN segment setup (v0.1.1, opt-in)](#wifi-vpn-segment-setup-v011-opt-in) above.

These are tracked as post-MVP in [`docs/keenetic-client-roadmap.md`](keenetic-client-roadmap.md). See [`docs/hincyray-v0.1-status.md`](hincyray-v0.1-status.md) for the precise implemented/not-implemented list.
