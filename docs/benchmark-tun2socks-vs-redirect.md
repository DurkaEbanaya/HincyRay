# Benchmark: tun2socks vs NAT REDIRECT

Laboratory benchmark comparing two proxy routing methods on a Keenetic Giga KN-1012 router, measuring real CPU/RAM overhead and maximum throughput **without internet dependency**.

> **TL;DR**: NAT REDIRECT is **9-35x faster** than tun2socks at similar CPU cost. tun2socks caps at ~160 Mbps upload / ~80 Mbps download; NAT REDIRECT reaches ~1400 Mbps upload / ~2200 Mbps download — nearly wire-speed. However, tun2socks survives Keenetic `ndm` firewall reloads without interruption; iptables-based NAT REDIRECT does not. This is a speed-vs-reliability tradeoff.

---

## Test Environment

| Component | Value |
|---|---|
| **Router** | Keenetic Giga KN-1012 |
| **SoC** | MediaTek MT7981 (Filogic 820) |
| **CPU** | 2× ARM Cortex-A53 @ ~1.3 GHz (ARMv8, part 0xd03) |
| **RAM** | 485 MB (256 MB physical + swap) |
| **Kernel** | 4.9-ndm-5 (KeeneticOS) |
| **Xray** | 26.3.27 (go1.26.1 linux/arm64) |
| **tun2socks** | 2.6.0 (gVisor netstack) |
| **iperf3** | 3.19 (both router and Mac) |
| **Link** | 2.5 Gbps Ethernet (router ↔ Mac) |
| **Proxy outbound** | `freedom` (no remote VPN server — pure overhead measurement) |

### Why `freedom` outbound?

To isolate proxy overhead from internet bandwidth, Xray uses the `freedom` outbound — it connects directly to the iperf3 server on the Mac over LAN, no remote VPN server involved. This means the bottleneck is CPU, not the internet connection.

---

## Methodology

### Three scenarios

| Scenario | Traffic path | TCP stack |
|---|---|---|
| **Baseline** | iperf3 → br0 → Mac (direct, no proxy) | kernel |
| **tun2socks** | iperf3 → TUN device → tun2socks (gVisor) → Xray SOCKS:10810 → freedom → Mac | **userspace** (gVisor) |
| **NAT REDIRECT** | iperf3 → iptables REDIRECT → Xray dokodemo-door:12345 → freedom → Mac | **kernel** |

### Traffic isolation

A secondary IP `192.168.1.250/24` is added to `br0`. iperf3 binds to this address via `--bind`. Only traffic from this IP is routed through the proxy. The router's main IP `192.168.1.1` is unaffected — no routing loop.

### Test matrix

- 3 scenarios × 2 directions (upload, download) × 2 stream counts (P1, P4) × 3 repeats = **36 runs**
- Each run: 30 seconds
- CPU/RAM sampled every 1 second via `/proc/stat` + `/proc/meminfo`
- 3-second cool-down between runs
- Total benchmark time: ~25 minutes (including setup/teardown)

### iperf3 parameters

```
# Upload (router → Mac)
iperf3 -c 192.168.1.95 --bind 192.168.1.250 -t 30 [-P 4]

# Download (Mac → router)
iperf3 -c 192.168.1.95 --bind 192.168.1.250 -t 30 [-P 4] -R
```

### CPU monitoring

Shell script reads `/proc/stat` (CPU jiffies) and `/proc/meminfo` (memory) every 1 second, computes CPU usage as delta between samples. First 3 samples (settling period) are excluded from averages.

---

## Results

### Idle baseline (no traffic, 10s)

| CPU avg | CPU max | RAM used | Temp |
|---|---|---|---|
| 2.6% | 3.9% | 355 MB | 62.7°C |

### Full data (all 36 runs)

| Scenario | Dir | Streams | Run | Throughput (Mbps) | CPU avg (%) | CPU max (%) | RAM used (KB) | Temp Δ (°C) |
|---|---|---|---|---|---|---|---|---|
| **Baseline** | UL | P1 | 1 | 2341.2 | 40.5 | 47.6 | 366,558 | +0.8 |
| **Baseline** | UL | P1 | 2 | 2341.4 | 39.6 | 48.4 | 366,379 | +0.2 |
| **Baseline** | UL | P1 | 3 | 2341.4 | 39.8 | 49.8 | 366,408 | +0.1 |
| **Baseline** | DL | P1 | 1 | 2248.7 | 80.3 | 93.0 | 367,156 | +0.4 |
| **Baseline** | DL | P1 | 2 | 2247.5 | 77.5 | 93.0 | 366,965 | +0.3 |
| **Baseline** | DL | P1 | 3 | 2244.6 | 80.0 | 93.7 | 367,111 | +0.3 |
| **Baseline** | UL | P4 | 1 | 2342.1 | 44.7 | 54.1 | 373,926 | -0.3 |
| **Baseline** | UL | P4 | 2 | 2342.1 | 45.5 | 54.3 | 373,855 | 0.0 |
| **Baseline** | UL | P4 | 3 | 2342.1 | 46.7 | 55.4 | 374,453 | +0.4 |
| **Baseline** | DL | P4 | 1 | 2200.3 | 81.3 | 100.0 | 368,469 | +0.5 |
| **Baseline** | DL | P4 | 2 | 2201.7 | 82.6 | 100.0 | 369,023 | +0.6 |
| **Baseline** | DL | P4 | 3 | 2201.4 | 83.2 | 100.0 | 368,972 | +0.5 |
| **tun2socks** | UL | P1 | 1 | 156.3 | 75.1 | 87.3 | 381,792 | +0.6 |
| **tun2socks** | UL | P1 | 2 | 158.6 | 73.2 | 87.4 | 382,575 | 0.0 |
| **tun2socks** | UL | P1 | 3 | 156.8 | 73.7 | 87.3 | 382,801 | +0.1 |
| **tun2socks** | DL | P1 | 1 | 97.8 | 62.5 | 77.5 | 392,349 | +0.2 |
| **tun2socks** | DL | P1 | 2 | 81.9 | 64.5 | 78.1 | 397,826 | +0.3 |
| **tun2socks** | DL | P1 | 3 | 69.3 | 65.0 | 80.9 | 399,266 | 0.0 |
| **tun2socks** | UL | P4 | 1 | 168.4 | 78.1 | 92.8 | 395,425 | +0.6 |
| **tun2socks** | UL | P4 | 2 | 165.1 | 78.0 | 93.5 | 393,399 | +0.5 |
| **tun2socks** | UL | P4 | 3 | 164.9 | 77.9 | 93.2 | 393,783 | +0.2 |
| **tun2socks** | DL | P4 | 1 | 71.8 | 71.5 | 82.5 | 422,230 | -0.2 |
| **tun2socks** | DL | P4 | 2 | 67.0 | 68.4 | 83.3 | 421,753 | +0.5 |
| **tun2socks** | DL | P4 | 3 | 49.1 | 66.4 | 86.0 | 423,247 | +0.5 |
| **REDIRECT** | UL | P1 | 1 | 1385.9 | 71.4 | 87.7 | 379,231 | +0.1 |
| **REDIRECT** | UL | P1 | 2 | 1390.7 | 73.3 | 87.4 | 379,412 | +0.4 |
| **REDIRECT** | UL | P1 | 3 | 1380.8 | 73.4 | 87.8 | 379,497 | +0.2 |
| **REDIRECT** | DL | P1 | 1 | 2229.5 | 83.1 | 98.6 | 374,724 | +0.3 |
| **REDIRECT** | DL | P1 | 2 | 2231.7 | 82.8 | 98.7 | 374,348 | +0.8 |
| **REDIRECT** | DL | P1 | 3 | 2241.6 | 82.6 | 99.1 | 374,016 | +0.3 |
| **REDIRECT** | UL | P4 | 1 | 1506.4 | 81.9 | 97.9 | 395,656 | +0.5 |
| **REDIRECT** | UL | P4 | 2 | 1519.3 | 81.6 | 98.4 | 395,982 | +0.3 |
| **REDIRECT** | UL | P4 | 3 | 1508.1 | 83.5 | 98.1 | 394,860 | 0.0 |
| **REDIRECT** | DL | P4 | 1 | 2158.3 | 80.5 | 100.0 | 379,175 | -0.1 |
| **REDIRECT** | DL | P4 | 2 | 2160.6 | 79.7 | 99.6 | 379,160 | +0.5 |
| **REDIRECT** | DL | P4 | 3 | 2157.3 | 82.5 | 99.6 | 378,515 | +0.3 |

### Summary (average of 3 runs)

| Scenario | Direction | Streams | Throughput | CPU avg | CPU max | RAM used | RAM vs idle |
|---|---|---|---|---|---|---|---|
| **Baseline** | UL | P1 | **2341 Mbps** | 40.0% | 49.8% | 358 MB | +3 MB |
| **Baseline** | DL | P1 | **2247 Mbps** | 79.3% | 93.7% | 358 MB | +3 MB |
| **Baseline** | UL | P4 | **2342 Mbps** | 45.6% | 55.4% | 365 MB | +10 MB |
| **Baseline** | DL | P4 | **2201 Mbps** | 82.4% | 100% | 360 MB | +5 MB |
| **tun2socks** | UL | P1 | **157 Mbps** | 74.0% | 87.3% | 373 MB | +18 MB |
| **tun2socks** | DL | P1 | **83 Mbps** | 64.0% | 80.9% | 387 MB | +32 MB |
| **tun2socks** | UL | P4 | **166 Mbps** | 78.0% | 93.5% | 385 MB | +30 MB |
| **tun2socks** | DL | P4 | **63 Mbps** | 68.8% | 86.0% | 412 MB | +57 MB |
| **REDIRECT** | UL | P1 | **1386 Mbps** | 72.7% | 87.8% | 370 MB | +15 MB |
| **REDIRECT** | DL | P1 | **2234 Mbps** | 82.8% | 99.1% | 365 MB | +10 MB |
| **REDIRECT** | UL | P4 | **1511 Mbps** | 82.3% | 98.4% | 386 MB | +31 MB |
| **REDIRECT** | DL | P4 | **2159 Mbps** | 80.9% | 100% | 370 MB | +15 MB |

---

## Head-to-head comparison

### Throughput ratio

| Test | tun2socks | NAT REDIRECT | REDIRECT advantage |
|---|---|---|---|
| Upload, P1 | 157 Mbps | 1386 Mbps | **8.8x** |
| Download, P1 | 83 Mbps | 2234 Mbps | **26.9x** |
| Upload, P4 | 166 Mbps | 1511 Mbps | **9.1x** |
| Download, P4 | 63 Mbps | 2159 Mbps | **34.5x** |

### CPU efficiency (Mbps per 1% CPU)

| Scenario | UL P1 | DL P1 | UL P4 | DL P4 |
|---|---|---|---|---|
| Baseline | 58.5 | 28.3 | 51.4 | 26.7 |
| **tun2socks** | **2.1** | **1.3** | **2.1** | **0.9** |
| **NAT REDIRECT** | **19.1** | **27.0** | **18.4** | **26.7** |

NAT REDIRECT is **9-30x more CPU-efficient** than tun2socks.

### RAM overhead (vs idle)

| Scenario | UL P1 | DL P1 | UL P4 | DL P4 |
|---|---|---|---|---|
| Baseline | +3 MB | +3 MB | +10 MB | +5 MB |
| tun2socks | +18 MB | +32 MB | +30 MB | +57 MB |
| NAT REDIRECT | +15 MB | +10 MB | +31 MB | +15 MB |

tun2socks uses **2-4x more RAM** than NAT REDIRECT under load. The gVisor userspace TCP stack allocates significant buffer memory per connection, and this accumulates across runs (see degradation below).

---

## Anomaly: tun2socks download degradation

tun2socks throughput **degrades across consecutive runs** — a pattern not seen in baseline or NAT REDIRECT:

| Run | tun2socks DL P1 | tun2socks DL P4 |
|---|---|---|
| Run 1 | 97.8 Mbps | 71.8 Mbps |
| Run 2 | 81.9 Mbps (-16%) | 67.0 Mbps (-7%) |
| Run 3 | 69.3 Mbps (-29%) | 49.1 Mbps (-32%) |

**Cause**: gVisor's userspace TCP stack accumulates internal buffers across connections that are not fully reclaimed between iperf3 sessions within the same tun2socks process lifetime. Each subsequent run starts with residual buffer state from the previous one, reducing effective throughput. Baseline and NAT REDIRECT use the kernel TCP stack, which properly reclaims connection state.

**Impact**: In production, long-running tun2socks processes serving many short-lived connections (e.g., web browsing) will gradually lose throughput until the process is restarted. This is a structural limitation of userspace TCP stacks, not a bug in tun2socks specifically.

---

## Why the difference?

### tun2socks (gVisor netstack)

```
Application → kernel TUN fd → userspace gVisor TCP state machine
    → SOCKS5 protocol framing → Xray inbound → Xray outbound
    → kernel socket → network
```

Every packet crosses the kernel/userspace boundary **twice** (TUN read + socket write). The gVisor TCP stack re-implements congestion control, retransmission, ACK processing, and flow control **in userspace** — all work the kernel normally does in hardware-accelerated context now runs on the CPU as Go code.

### NAT REDIRECT (kernel TCP)

```
Application → kernel socket (iptables REDIRECT)
    → Xray inbound (reads from kernel socket directly)
    → Xray outbound → kernel socket → network
```

The kernel TCP stack handles the connection. iptables REDIRECT simply remaps the destination port at the NAT layer — the socket is handed to Xray without a userspace TCP stack in between. Xray reads/writes to a normal kernel socket.

### Why tun2socks anyway?

The benchmark measures raw throughput. In production on Keenetic routers, there's a critical factor that throughput doesn't capture:

**Keenetic `ndm` firewall reloads.** When `ndm` (the Keenetic network daemon) reloads — triggered by WAN events, DHCP renewals, WiFi changes, or UI policy changes — it **recreates all iptables chains**. NAT REDIRECT rules disappear instantly. Until rules are reinstalled (by a watchdog or ndm hook script), all proxied traffic stops.

- **tun2socks**: iproute2 `ip rule`/`ip route` are stored in the kernel routing table, which `ndm` does **not** wipe on reload. The TUN device and policy routing survive. Existing TCP sessions through tun2socks continue uninterrupted. Only the mangle MARK rule (for FORWARD acceptance) needs reinstalling, and sessions don't break during the gap.

- **NAT REDIRECT**: the REDIRECT rule in `iptables -t nat` is wiped on `ndm` reload. All proxied traffic stops immediately. Even with an `ndm` hook script in `/opt/etc/ndm/netfilter.d/`, there's a brief window where traffic is not redirected. Existing TCP sessions may break because the NAT conntrack entries are flushed.

### The tradeoff

| | tun2socks | NAT REDIRECT |
|---|---|---|
| **Max throughput** | ~160 Mbps UL / ~80 Mbps DL | ~1400 Mbps UL / ~2200 Mbps DL |
| **CPU per Mbps** | 9-30x worse | baseline |
| **RAM overhead** | +18-57 MB | +10-31 MB |
| **ndm reload survival** | **yes** — iproute2 rules persist | **no** — iptables chains wiped |
| **Session continuity** | **preserved** — SOCKS tunnel in userspace | **broken** — conntrack flushed |
| **Setup complexity** | TUN device + ip rules + ip routes | iptables rule only |
| **Dependency** | tun2socks binary + `/dev/net/tun` | iptables only |

For **home VPN usage** (browsing, streaming, messaging), 160 Mbps is more than sufficient — a 4K stream needs 25 Mbps. The reliability of tun2socks under `ndm` reloads outweighs the throughput advantage of NAT REDIRECT.

For **high-throughput scenarios** (large file transfers, LAN-to-LAN tunneling, multi-gigabit internet), NAT REDIRECT with `ndm` hooks is the better choice — if brief session interruptions during firewall reloads are acceptable.

---

## Reproduction

### Prerequisites on router

- Entware with `iperf3`, `xray`, `tun2socks`, `jq`, `awk`
- `/dev/net/tun` available (Entware `kmod-tun` if needed)
- SSH access on port 222

### Prerequisites on client machine

- `iperf3` installed
- Ethernet connection to router (2.5 Gbps recommended to avoid link bottleneck)

### Running

The benchmark scripts are not included in the repository (they are ad-hoc test artifacts). The methodology described above is sufficient to reproduce. Key configuration files:

**Xray config for tun2socks test** (`xray-tun2socks.json`):
```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "socks-in",
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 10810,
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{
    "tag": "freedom",
    "protocol": "freedom"
  }]
}
```

**Xray config for NAT REDIRECT test** (`xray-redirect.json`):
```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "dokodemo-in",
    "protocol": "dokodemo-door",
    "listen": "0.0.0.0",
    "port": 12345,
    "settings": {"followRedirect": true, "network": "tcp"}
  }],
  "outbounds": [{
    "tag": "freedom",
    "protocol": "freedom"
  }]
}
```

**tun2socks setup** (BusyBox `ip` doesn't support `tuntap`, so tun2socks creates the TUN device itself):
```sh
/opt/sbin/xray run -c xray-tun2socks.json &
/opt/sbin/tun2socks -device tun://tun_bench -proxy socks5://127.0.0.1:10810 -mtu 1400 &
sleep 2
ip addr add 172.20.0.1/30 dev tun_bench
ip link set tun_bench up
ip rule add from 192.168.1.250 table 200
ip route add default dev tun_bench table 200
```

**NAT REDIRECT setup**:
```sh
/opt/sbin/xray run -c xray-redirect.json &
iptables -t nat -A OUTPUT -s 192.168.1.250 -p tcp -d <mac_ip> --dport 5201 -j REDIRECT --to-ports 12345
```

---

## Date

June 21, 2026

## Hardware

- Router: Keenetic Giga KN-1012 (MediaTek MT7981, 2× Cortex-A53, 256 MB RAM)
- Client: macOS machine over 2.5 Gbps Ethernet
- Firmware: KeeneticOS 4.9-ndm-5
- No internet connection used during tests
