# 速查卡

给急着动手的 Agent。详细说明见 `SKILL.md`。

## 30 秒上手

```bash
cd skill/scripts

# 1. 确认设备（不需要密码）
python3 rd08.py info
# → 会打印型号、固件、SN、推算出的 root 密码、端口状态

# 2. 开 SSH
export RD08_PWD='<Web管理密码>'
python3 rd08.py boot
# → 会打印 root 密码和登录命令

# 3. 登录
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.1.1
```

## 命令一览

| 命令 | 需要密码 | 作用 |
|---|---|---|
| `info` | ❌ | 型号/固件/SN/root密码/端口 |
| `rootpwd <SN>` | ❌ | 从 SN 算 root 密码 |
| `ssh-check` | ❌ | 检查 22 端口 |
| `probe` | ✅ | **只读**验证漏洞是否可用 |
| `boot` | ✅ | 启动 dropbear（开 SSH） |
| `persist` | ✅ | SSH 持久化（重启不丢） |
| `devices` | ✅ | 每设备累计流量 |
| `wifi` | ✅ | SSID/信道/密码（打码） |
| `wan` | ✅ | WAN 口信息 |
| `ota-off` | ✅ | 关闭自动更新 |
| `exec '<命令>'` | ✅ | 注入执行（无 stdout） |
| `login` | ✅ | 只打印 stok |

## 三条铁律

1. **载荷里不能用分号 `;`** —— 会被拆掉，命令静默截断。用 `&&` / `||`。
2. **别连发登录** —— 间隔太快会报 `401 not auth`，不是密码错。
3. **别覆盖 crontab** —— 用 `>>` 或 `sed -i`，别用 `>`。

## 常用信息快查

```sh
# 温度
for f in /sys/class/thermal/thermal_zone*/temp; do
  echo "$(cat $(dirname $f)/type): $(($(cat $f)/1000))°C"; done

# 每接口 WiFi 错误率
for i in wl0 wl1 wl17 wl13; do
  rx=$(cat /sys/class/net/$i/statistics/rx_packets)
  err=$(cat /sys/class/net/$i/statistics/rx_errors)
  [ "$rx" -gt 0 ] && echo "$i: $((err*10000/rx))‱  (err=$err/$rx)"
done

# WiFi 断连统计
grep -c DISASSOC /data/usr/log/messages.0
grep -oE 'sta_mac="[0-9a-f:]+"' /data/usr/log/messages.0 | sort | uniq -c | sort -rn

# 连接跟踪
cat /proc/sys/net/netfilter/nf_conntrack_count

# 内核日志
dmesg | tail -30
```

## 恢复出厂状态

```sh
killall dropbear
rm -rf /data/ssh
sed -i '\|/data/ssh/boot.sh|d' /etc/crontabs/root
killall crond; /usr/sbin/crond -c /etc/crontabs -b
```

## 出问题了

| 现象 | 原因 | 解决 |
|---|---|---|
| `no matching host key type` | OpenSSH 8.8+ 拒绝 SHA-1 | 加 `-o HostKeyAlgorithms=+ssh-rsa` |
| 注入返回 `code:0` 但没效果 | 命令含分号 | 改用 `&&` |
| `401 not auth` | 登录太快 | sleep 1 重试 |
| `Permission denied (publickey)` | 公钥认证不支持 | 用密码 |
| 22 端口打不开 | hostkey 是空文件 | `rm -f` 后再 `dropbearkey` |
