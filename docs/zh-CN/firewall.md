# Linux 防火墙前置条件

[English](../firewall.md) · **中文**

Xtate 的 `zbanner`、`tcp-state`、`tls-state`、`http-state`、H2/H3 以及所有
state 子探测都用 raw packet 完成 TCP 握手。Linux 内核不知道这些连接，会用
RST 终止连接，导致 banner/TLS/探针响应到达前就失败。

## 操作系统区分

### Linux

使用 `firewall/add_rules.sh`。规则是主机级的，扫描结束后立即删除。
只适用于下面列出的 stateful 扫描。

### Windows

没有防火墙步骤，**不要在 Windows 上执行 `add_rules.sh`**。
UDP/DNS 扫描不需要任何本地防火墙规则。Xtate 在 Windows 上不会输出
Linux 防火墙警告；只有 `tcp-syn` 会提示：

```text
Windows: tcp-syn can add -scan-arg "--send-rst" ...
```

用于显式关闭半开连接。raw 扫描使用 Npcap 和管理员权限。

## 谁需要

需要：

```text
zbanner
tcp-state（以及所有 tls-state/state 子探测）
```

不需要：

```text
tcp-syn
无状态 TCP 端口扫描
```

UDP DNS 不需要 TCP RST 抑制，但 ICMP port-unreachable 规则可以避免无意义重传。
其他无状态扫描不需要这些规则。

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
没有 state 子探测输出
DoT/DoH 显示 open 但没有 dot/doh 结果
```

任何“open 但没有应用数据”的结果都应先检查这个。

## 运行时提醒

Xtate 启动时只会对需要规则的扫描检查 Linux iptables 并输出：

```text
[WRN] firewall RST/ICMP suppression rules are not fully installed
[HIN] run: sudo ./firewall/add_rules.sh
```

`--check --explain-target <ip>` 会显示 `Firewall:` 行。

## 开发者/运维检查清单

- Linux 扫描端：stateful 扫描前安装，扫描后立即删除；`tcp-syn` 等无状态扫描不需要。
- Docker/GitHub Actions 扫描容器：安装 `iptables`，去掉脚本里的 `sudo`，
  处理 CRLF，执行后确认规则存在。
- 目标容器不需要这些规则。
- Windows 没有防火墙步骤；UDP/DNS 不需要本地规则，raw 扫描使用 Npcap/管理员权限。不要在 Windows 上运行 Linux 的 `add_rules.sh`。
- 不要在共享主机上长期保留规则：它会丢弃所有出站 RST。
