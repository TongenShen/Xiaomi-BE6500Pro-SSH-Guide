# Xiaomi BE6500 Pro (RD08) — SSH Access Guide

> Get root on a Xiaomi BE6500 Pro router. Verified on firmware 1.1.96.

[简体中文](README.md) | **English**

## What this is

A complete method to obtain root access on the **Xiaomi BE6500 Pro** (internal model **RD08**, MiWiFi firmware **1.1.96**) by exploiting a pre-existing command injection in the router's own web API, then starting the SSH daemon (`dropbear`) that ships with the firmware but is disabled by default.

**No** disassembly. **No** UART/TTL. **No** firmware downgrade. **No** third-party OS. **No** extra software to install.

**Verified environment**: RD08 / MiWiFi 1.1.96 / kernel 5.4.213 aarch64

## Quick start

```bash
git clone https://github.com/TongenShen/Xiaomi-BE6500Pro-SSH-Guide.git
cd Xiaomi-BE6500Pro-SSH-Guide/skill/scripts

# 1. Identify the device (no password needed)
python3 rd08.py info

# 2. Enable SSH (needs the web admin password)
export RD08_PWD='your-web-admin-password'
python3 rd08.py boot

# 3. Log in
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.1.1
```

`boot` prints the root password (derived from the device serial number) and a ready-to-paste login command.

> The two `-o` flags are **mandatory**. The router's dropbear is v2017.75, which only offers SHA-1 `ssh-rsa` host keys — disabled by default in OpenSSH 8.8+. Without them you get `no matching host key type found`, which looks like a rejection but is actually your client refusing the algorithm.

## How it works (one paragraph)

The web endpoint `api/xqsystem/set_macfilter_rules` reads its `name` parameter with **no validation at all**: `name` sits on the `hackCheck` whitelist so the metacharacter filter returns early, and the handler uses the two-argument `formvalue("name")` rather than the regex-checked variant. The value is then concatenated unescaped into `os.execute("/usr/sbin/macfilter add black <mac> rulename=<name>")`. Since `os.execute` runs as root, an injected `$(...)` executes as root too.

Three defence layers fail independently:

| Layer | Should do | Actually does |
|---|---|---|
| `XQSecureUtil.hackCheck` | strip `` ` ; \| $ & `` and newlines | `name` is whitelisted → passes through untouched |
| Controller param read | validate with regex | uses `formvalue("name")`, no regex |
| `XQFirewall.setMacFilter` | escape before shell | raw string concatenation into `os.execute` |

## What you gain

Root SSH versus the stock web UI:

| Capability | Web UI | Root SSH |
|---|---|---|
| Per-device cumulative traffic | current speed only | ✅ full history |
| Temperature sensors | one coarse value | ✅ **5 independent sensors** |
| WiFi error / retry counters | ❌ | ✅ per interface |
| Disconnect history + reason codes | ❌ | ✅ full logs |
| Kernel log | ❌ | ✅ `dmesg` / `logread` |
| Connection tracking | ❌ | ✅ every flow |
| Kernel config | ❌ | ✅ `/proc/config.gz` |
| Load kernel modules | ❌ | ✅ 260 available |
| Arbitrary config changes | UI-exposed only | ✅ all of `uci` |
| Disable auto-update | surface switch only | ✅ including cron |

Measured on this unit: **4× Cortex-A53 @1.5GHz, 863MB RAM, 512MB flash, WiFi 7 (11be), 2.5G port**.

## The helper script

Pure Python 3 standard library — no `pip install` required.

```bash
python3 rd08.py info        # model/firmware/SN/root-password/ports (no password)
python3 rd08.py probe       # read-only vuln check (timing side-channel, zero traces)
python3 rd08.py boot        # start dropbear
python3 rd08.py persist     # make SSH survive reboots
python3 rd08.py devices     # per-device cumulative traffic
python3 rd08.py wifi        # SSID / channel / encryption
python3 rd08.py wan         # WAN info
python3 rd08.py ota-off     # disable auto-update
python3 rd08.py exec 'cmd'  # run a command via injection (no stdout)
```

## Compatibility

**Verified**: RD08 / 1.1.96

**Possibly works on**:
- Other firmware builds of the RD08 (the vulnerable endpoint exists across versions, but parameter filtering may differ)
- Other Xiaomi routers sharing the same web framework

**To check safely**, run:

```bash
python3 rd08.py probe
```

This is **read-only**. It sends a single `sleep` payload and measures the response delay. If the bug is patched it reports failure and the device is untouched.

## Security implications

> **The vulnerability exists whether or not you enable SSH.** Anyone who obtains your web admin password can get root in about 30 seconds. Turning SSH off does not remove the injection point.

Additionally, **the device serial number derives the root password** (algorithm in the docs). Do not publish your SN or a photo of the router's bottom label.

Recommended after enabling root:

1. Change the web admin password
2. Change the root password (`passwd root`)
3. Bind SSH to the LAN only: `dropbear -p 192.168.1.1:22`

## Risks

- May void your warranty
- Bricking is possible if you write to the wrong flash partition — **back up the flash first** (see the full guide)
- Read the risk section of the full documentation before any write-to-flash operation

## Official firmware mirror

`firmware/miwifi_rd08_firmware_708c2_1.1.96.bin` — the stock 1.1.96 image, unmodified, 42,337,280 bytes.

```
MD5: ca00edece4618f905ee43635292708c2
```

Source is Xiaomi's own CDN URL, as recorded in the router's UCI config:

```
uci get xiaoqiang.common.ROM_DOWNLOAD_URL
```

This exists so you have a rollback path after making changes. **It is not needed to enable SSH.** Reflash via the router's web UI (System → Manual Upgrade) — do not `dd` it.

Firmware copyright belongs to Xiaomi Inc.; it is mirrored here unmodified for the convenience of device owners. Rights holders may request removal.

## Legality

For **devices you own** only. Unauthorized access to devices you do not own may violate computer-misuse laws in your jurisdiction.

## Acknowledgements

The vulnerability analysis and exploitation chain come from public research by others:

- [52pojie — Xiaomi BE6500 Pro: enabling SSH via set_macfilter_rules](https://www.52pojie.cn/forum.php?mod=viewthread&tid=2127776) (RD08 / 1.1.96)
- [leafnsand/xiaomi-rp01-root](https://github.com/leafnsand/xiaomi-rp01-root)
- [c0j0s/Xiaomi-BE6500-Pro](https://github.com/c0j0s/Xiaomi-BE6500-Pro)

This repository contributes **verification on RD08, a troubleshooting log, tooling, and bilingual documentation**. No code was copied from those projects.

## Documentation

| File | Contents |
|---|---|
| [README.md](README.md) | Project entry point (Chinese) |
| [README-full.md](README-full.md) | Full walkthrough: partition backup, disabling auto-update, firmware rollback |
| [skill/SKILL.md](skill/SKILL.md) | Operator manual — 16 sections, five known traps, recovery |
| [skill/QUICKSTART.md](skill/QUICKSTART.md) | Cheat sheet |

## License

MIT for the documentation and scripts — see [LICENSE](LICENSE). The firmware image is excluded from that grant and remains the property of Xiaomi Inc.

## Disclaimer

For technical research and management of your own hardware. You accept all risk. The author is not liable for device damage, data loss, voided warranty, or legal consequences.

**If you are unsure what you are doing, do not proceed.**
