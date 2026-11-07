# QUIC state

[English](../quic-state.md) · **中文**

`quic-state` 是可选的**有状态 QUIC 传输扫描器**。它自己发送/接收原始
IPv4/IPv6 UDP 报文；ngtcp2 负责 QUIC 包状态，GnuTLS 负责 TLS 1.3。Xtate 继续
控制源端口、L3/L4 头、发送节奏、flow 预算、定时器和输出。

它不是浏览器 QUIC 客户端，当前也还不是 HTTP/3。第一个里程碑完成 QUIC/TLS
握手、输出版本/ALPN/证书证据，并运行 state 子探测。HTTP/3 和 DoQ 是建立在该
传输层之上的应用探测。

## 构建

```bash
sudo apt install libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev
./build.sh --compiler gcc --config release
```

CMake 开关：

```bash
-DWITH_NGTCP2=OFF   # 从构建中移除 quic-state
```

`WITH_NGTCP2=ON` 是默认值；如果 ngtcp2/GnuTLS 或 pkg-config 缺失，模块会自动
消失，普通构建不依赖 ngtcp2。

## 架构

```text
目标/源端口
  -> ngtcp2_conn_writev_stream()       # QUIC UDP payload
  -> udp_create_packet()               # IPv4/IPv6 + UDP + Ethernet
  -> Xtate raw socket / NetStack
  -> pcap 接收
  -> 去掉 IP/UDP
  -> ngtcp2_conn_read_pkt()
  -> TLS 握手 + 证书
  -> state 子探测
```

当前 flow 表是带全局互斥锁的有界哈希分桶表，这是第一个里程碑，不是最终高吞吐
设计。后续应改为每 worker 独立哈希表、去掉全局锁，并为定时器重传增加不依赖 TX
线程 stack flush 的原始报文发送路径。

## 最小用法

```bash
# 只取证书/版本证据
xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe close-state \
  -scan-arg "--alpn h3 --sni example.test" --wait 5 --no-status -show info

# 确认模块存在
xtate --list-scan | grep quic-state
```

探测必须是 `state` 类型；`close-state` 是只取证书的模式。

## 参数

| 参数 | 默认 | 含义 |
|:---|:---|:---|
| `--alpn` | `h3` | ALPN 列表；取第一个逗号/空格分隔的 token。 |
| `--sni` | 无 | TLS SNI 主机名。 |
| `--max-flows` | `100000` | 并发 flow 预算。 |
| `--flow-timeout` | `30` | 扫描器 flow 存活秒数。 |
| `--max-udp-payload` | `1200` | QUIC UDP payload 大小（1200..65527），同时作为 `max_udp_payload_size` 通告。 |
| `--handshake-timeout` | `10` | QUIC 握手总超时秒数。 |
| `--initial-rtt` | `100` | 丢包定时器初始 RTT（毫秒），不是测量值。 |
| `--max-data` | `1048576` | 连接级流控上限。 |
| `--max-stream-data` | `131072` | 单 stream 流控上限。 |
| `--max-streams` | `3` | 单向 stream 数量。 |
| `--idle-timeout` | `30000` | idle timeout（毫秒）。 |
| `--cc-algo` | `reno` | `reno`、`cubic`、`bbr` 或 `bbr2`。 |
| `--no-cert` | 关 | 跳过证书解析/输出。 |

## 输出字段

成功握手使用 classification `quic handshake`，包含：

- `quic_version`
- `quic_tls_version`
- `quic_alpn`
- `quic_cert_subject`
- `quic_cert_issuer`
- `quic_cert_sha256`

扫描时刻意关闭证书验证；这些字段是证据，不是信任判断。

## 刻意限制

- 仅 QUIC v1。
- 不做 0-RTT、session resumption、migration、multipath。
- 每目标单连接，不做长连接。
- 第一里程碑不实现 HTTP/3/QPACK 和 DoQ。
- 不做跨连接 follow-up；使用 `close-state` 或后续应用探测。
- 当前 flow 表是全局哈希分桶且受互斥锁保护，不要把它当作高吞吐基准。
- 仅因 ALPN 是 `h3` 不代表已经验证 HTTP/3。

## 验证

本地 lab 使用带自签名证书的 aioquic：

```bash
bash tests/lab/run.sh
```

`quic-state` 用例断言 `quic handshake`、ALPN、TLS 1.3 和证书字段。
`tests/i18n/check_parity.py` 检查中英文帮助。
