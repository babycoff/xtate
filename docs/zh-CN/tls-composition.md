# TLS 与 STARTTLS 组合

[English](../tls-composition.md) · **中文**

`tls-state` 不是应用层探针，而是 HLTCP 内部的 TLS 中间层：

```text
tcp-state -> tls-state -> TLS 内的 state 子探测
```

子探测看不到明文 STARTTLS 交换，这正是 `--after-tls` 存在的原因。

## 两种组合模式

### 隐式 TLS

服务器直接说 TLS：

```text
SMTPS          465
IMAPS          993
POP3S          995
FTPS implicit  990
MySQL TLS      3306
PostgreSQL TLS 5432
MongoDB TLS    27017
```

`tls-state` 完成握手后，在 TLS 内启动 state 子探测。

### STARTTLS

连接先明文，升级后再 TLS：

```text
SMTP      220 -> EHLO -> STARTTLS -> 220 -> TLS
IMAP      * OK -> a001 STARTTLS -> a001 OK -> TLS
POP3      +OK -> STLS -> +OK -> TLS
FTP       220 -> AUTH TLS -> 234 -> TLS
ManageSieve greeting -> STARTTLS -> "OK" -> TLS
```

`tls-state` 会消费明文 greeting 和升级响应。子探测在 TLS 握手**之后**启动，
不能再等待那个 greeting。

## `--after-tls` 的含义

`--after-tls` **不是**开启 TLS 的开关，只改变子探测状态机：

> “明文 greeting/SSLRequest 阶段已经完成，或者我已经在 TLS 内；
> 跳过这个阶段，直接走 TLS 后的流程。”

它是**子探测参数**，通过 `-subprobe-arg` 传入，不是 `tls-state` 自己的参数。

## 各协议行为

| 探针 | 默认（明文） | `--after-tls` |
|:---|:---|:---|
| `smtp-state` | 等 `220`，发 `EHLO` | 跳过 `220`，发 `EHLO` |
| `imap-state` | 等 `* OK`，发 `CAPABILITY` | 跳过 `* OK`，发 `CAPABILITY` |
| `pop3-state` | 等 `+OK`，发 `CAPA` | 跳过 `+OK`，发 `CAPA` |
| `ftp-state` | 等 `220`，发 `FEAT` | 跳过 `220`，发 `FEAT` |
| `postgres-state` | 发 `SSLRequest`，再发 `StartupMessage` | 跳过 `SSLRequest`，直接 `StartupMessage` |
| `mongodb-state` | 发 `OP_MSG hello` | 不需要，client-first |
| `mysql-state` | 等服务器 greeting | 仅 lab COM_PING 唤醒 |
| `managesieve-state` | 等 capability greeting | 仅 lab NOOP 唤醒 |

## 示例

### STARTTLS SMTP

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 25 -scan tcp-state -probe tls-state   -probe-arg "-subprobe smtp-state --starttls smtp \
              -subprobe-arg --after-tls \
              -sni mail.example -alpn h2 --dump-cert-details"
```

### 隐式 TLS SMTP

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 465 -scan tcp-state -probe tls-state   -probe-arg "-subprobe smtp-state -subprobe-arg --after-tls \
              -sni mail.example --dump-cert-details"
```

### 隐式 TLS PostgreSQL

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 5432 -scan tcp-state -probe tls-state   -probe-arg "-subprobe postgres-state -subprobe-arg --after-tls"
```

### 隐式 TLS MongoDB

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 27017 -scan tcp-state -probe tls-state   -probe-arg "-subprobe mongodb-state"
```

## 什么时候不要用

不要对**普通明文扫描**使用：

```bash
# 正确：默认 state 探针
-scan tcp-state -probe smtp-state

# 错误：跳过真实的 220 greeting
-scan tcp-state -probe smtp-state -probe-arg --after-tls
```

`--after-tls` 只用于 TLS/STARTTLS 组合。

## MySQL / ManageSieve 注意事项

`mysql-state --after-tls` 和 `managesieve-state --after-tls` 是
**lab/兼容性唤醒**，不是标准握手：

- `mysql-state` 在认证前发送 MySQL COM_PING，严格或真实 MySQL 可能拒绝；
- `managesieve-state` 在 capability greeting 前发送 NOOP，不能替代正常
  ManageSieve 握手，严格服务器可能拒绝。

它们只用于让组合矩阵中的 server-first TLS 时序确定，不应作为生产环境保证。

## 为什么不能自动判断

子探测无法知道：

- `tls-state` 是否已经消费 greeting；
- 当前是隐式 TLS 还是 STARTTLS；
- 服务器是否会在 TLS 内再次发送 greeting。

显式参数避免猜测，也让状态机可审查。

## 排障

| 现象 | 可能原因 |
|:---|:---|
| 只有 `open`，没有 TLS 输出 | Linux 防火墙规则缺失；运行 `./firewall/add_rules.sh` |
| 有 TLS info，没有应用结果 | STARTTLS 探针缺少 `--after-tls`，greeting 已被消费 |
| 明文扫描用了 `--after-tls` | 跳过真实 greeting；去掉该参数 |
| MySQL/ManageSieve 被拒绝 | lab 唤醒包在正常 greeting 前发送；只应在 lab 使用 |
