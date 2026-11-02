# Xiaomi BE6500 Pro (RD08) SSH 开启指南

> 在小米路由器 BE6500 Pro 上获取 root 权限的完整方法，附实测记录与配套工具。

## 这是什么

针对 **Xiaomi BE6500 Pro（内部型号 RD08）**，固件 **1.1.96** 上，通过一个已存在的 Web API 命令注入漏洞获取 root 权限，并启动固件内置但默认关闭的 SSH 服务（dropbear）。

**不需要**：拆机、TTL 串口、降级固件、刷第三方系统、安装额外软件。

**实测环境**：RD08 / MiWiFi 1.1.96 / 内核 5.4.213 aarch64

## 快速开始

```bash
git clone <本仓库>
cd skill/scripts

# 1. 确认设备型号与固件（免密码）
python3 rd08.py info

# 2. 开启 SSH（需要 Web 管理密码）
export RD08_PWD='你的Web管理密码'
python3 rd08.py boot

# 3. 登录
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.1.1
```

`boot` 会打印出 root 密码（由设备 SN 推算）和现成的登录命令。

## 文档导航

| 文档 | 内容 |
|---|---|
| [skill/SKILL.md](skill/SKILL.md) | **完整手册** — 原理、步骤、五个坑、能查什么、恢复方法 |
| [skill/QUICKSTART.md](skill/QUICKSTART.md) | 速查卡，急着动手看这个 |
| [skill/scripts/rd08.py](skill/scripts/rd08.py) | 配套脚本，零依赖（纯 Python 3 标准库） |
| [README-full.md](README-full.md) | 更详细的原始教程（含分区备份、自动更新关闭、固件回退） |

## 核心原理（一句话）

Web 管理接口 `api/xqsystem/set_macfilter_rules` 读取 `name` 参数时**没有做任何校验**（该参数在 `hackCheck` 白名单内，且控制器用了不带正则的 `formvalue`），最终被直接拼进 `os.execute()`，因此可以执行任意命令——**以 root 身份**。

## 能做什么

拿到 root 之后，相比 Web 管理界面，你能多访问：

| 能力 | Web 界面 | root SSH |
|---|---|---|
| 每设备累计流量 | 只有当前速度 | ✅ 完整历史 |
| 温度传感器 | 1 个笼统值 | ✅ **5 个独立传感器** |
| WiFi 错误率/重传 | ❌ | ✅ 每接口统计 |
| 断连历史与原因码 | ❌ | ✅ 完整日志 |
| 内核日志 | ❌ | ✅ `dmesg` / `logread` |
| 连接跟踪 | ❌ | ✅ 每条连接明细 |
| 内核配置 | ❌ | ✅ `/proc/config.gz` |
| 加载内核模块 | ❌ | ✅ 260 个可用 |
| 修改任意配置项 | 仅界面暴露的 | ✅ `uci` 全部 |
| 关闭自动更新 | 只有表面开关 | ✅ 含 crontab 定时任务 |

实测这台机器上：**4 核 A53 @1.5GHz，863MB 内存，512MB flash，WiFi 7，2.5G 网口**。

## 配套脚本

```bash
python3 rd08.py info        # 型号/固件/SN/root密码/端口（免密码）
python3 rd08.py probe       # 只读验证漏洞可用性（计时法，零痕迹）
python3 rd08.py boot        # 开 SSH
python3 rd08.py persist     # 让 SSH 重启后自动恢复
python3 rd08.py devices     # 每设备累计流量
python3 rd08.py wifi        # SSID/信道/加密方式
python3 rd08.py wan         # WAN 口信息
python3 rd08.py ota-off     # 关闭自动更新
python3 rd08.py exec '命令'  # 通过注入执行（无 stdout）
```

## 适用范围

**已验证**：RD08 / 1.1.96

**可能适用**：
- 其他固件版本的 RD08（漏洞接口在多个版本中存在，但参数过滤策略可能不同）
- 其他采用相同 Web 框架的小米路由器

**验证方法**：先跑 `python3 rd08.py probe`。它是**只读的**，只发一次 `sleep` 载荷用计时判断，不改任何配置。如果漏洞已被修补，会显示失败，设备不受影响。

## 重要提醒

### ⚠️ 安全影响

**这个漏洞的存在与"你有没有开 SSH"无关。** 任何拿到你 Web 管理密码的人都能在 30 秒内拿到 root。

另外：**设备 SN 可以直接算出 root 密码**（算法见文档）。不要公开你的 SN 或路由器底部标签照片。

建议操作后：
1. 更换 Web 管理密码
2. 更换 root 密码（`passwd root`）
3. 把 SSH 绑定到 LAN：`dropbear -p 192.168.1.1:22`

### ⚠️ 风险

- 可能失去官方保修
- 操作不当有变砖风险（**务必先备份 flash**，见完整文档）
- **任何写 flash 分区的操作前，先读完整文档的风险章节**

### ⚠️ 合法性

仅用于**你自己拥有**的设备。未经授权访问他人设备可能违反当地法律。

## 致谢

漏洞分析与利用链来自公开研究成果：

- [52pojie：小米 BE6500 Pro 通过 set_macfilter_rules 漏洞开启 SSH](https://www.52pojie.cn/forum.php?mod=viewthread&tid=2127776)
- [leafnsand/xiaomi-rp01-root](https://github.com/leafnsand/xiaomi-rp01-root)
- [c0j0s/Xiaomi-BE6500-Pro](https://github.com/c0j0s/Xiaomi-BE6500-Pro)

本仓库提供的是**针对 RD08 的实测验证、排障记录与配套工具**，以及完整的中文文档。

## 免责声明

本项目仅用于技术研究与自有设备管理。使用者自行承担全部风险与后果。作者不对任何设备损坏、数据丢失、保修失效或法律问题负责。

**如果你不确定自己在做什么，请不要执行。**
