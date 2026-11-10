# Linux 防火墙前置条件

[English](../firewall.md) · **中文**

Xtate 的 `zbanner`、`tcp-state`、`tls-state`、`http-state`、H2/H3 以及所有
state 子探针都用 raw packet 完成 TCP 握手。Linux 内核不知道这些连接，会用
RST 终止连接，导致 banner/TLS/探针响应到达前就失败。

## 必须执行

在**扫描端主机**（不是目标端）扫描期间执行：

```bash
sudo ./firewall/add_rules.sh
```

会安装 OUTPUT DROP：

```text
TCP RST       IPv4 + IPv6
ICMP 3/3      IPv4
ICMPv6 1/4    IPv6
```

检查/删除：

```bash
sudo ./firewall/check_rules.sh
sudo ./firewall/rm_rules.sh
```

## 缺失时的现象

```text
open because syn-ack
没有 banner
没有 TLS 输出
没有 state 子探针输出
DoT/DoH 显示 open 但没有 dot/doh 结果
```

任何“open 但没有应用数据”的结果都应先检查这个。

## 运行时提醒

Xtate 启动时会检查 Linux iptables 并输出：

```text
[WRN] firewall RST/ICMP suppression rules are not fully installed
[HIN] run: sudo ./firewall/add_rules.sh
```

`--check --explain-target <ip>` 会显示 `Firewall:` 行。

## 开发者/运维检查清单

- Linux 扫描端：扫描前安装，扫描后立即删除。
- Docker/GitHub Actions 扫描容器：安装 `iptables`，去掉脚本里的 `sudo`，
  处理 CRLF，执行后确认规则存在。
- 目标容器不需要这些规则。
- Windows 没有等价脚本；使用 Npcap/管理员配置，不要假设宿主协议栈的 RST 行为。
- 不要在共享主机上长期保留规则：它会丢弃所有出站 RST。
