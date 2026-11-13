# DNS over HTTPS（DoH）

[English](../dns-over-https.md) · **中文**

`doh` 是 DNS over HTTPS（RFC 8484，HTTP/1.1）的 state 子探测。
TLS 由 `tls-state` 负责。

```text
tcp-state -> tls-state (ALPN http/1.1) -> doh
```

## 运行

HTTP/1.1：

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh -alpn http/1.1 -sni dns.example \
              -subprobe-arg '--req-name=example.com --doh-host=dns.example'" \
  -show info
```

HTTP/2（互联网 DoH 的常见形态）：

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh-h2 -alpn h2 -sni dns.example \
              -subprobe-arg '--dns-name=example.com --authority=dns.example \
                             --path=/dns-query'" \
  -show info
```

Linux 扫描端必须先安装 `firewall/add_rules.sh`；Windows 使用正常的
`-if` / `--router-mac` 配置。

## 参数

| 参数 | 含义 |
|:---|:---|
| `--req-name` | 要查询的 DNS 名（必需） |
| `--req-type` | DNS 类型，默认 `A` |
| `--doh-path` | HTTP 路径，默认 `/dns-query` |
| `--doh-host` | HTTP Host 头；默认使用目标 IP |
| `--dnssec` | 发送 EDNS0 DO=1 |
| `--edns-size` | EDNS0 UDP 大小，默认 1232 |

`doh-h2` 使用 h2 探针的参数：

| 参数 | 含义 |
|:---|:---|
| `--dns-name` | 要查询的 DNS 名（必需） |
| `--dns-type` | DNS 类型，默认 `A` |
| `--path` | HTTP/2 `:path`，默认 `/`；DoH 使用 `/dns-query` |
| `--authority` | HTTP/2 `:authority` / Host |
| `--dnssec` | 发送 EDNS0 DO=1 |

## 输出

```text
doh_status
doh_content_type
doh_dns_len
doh_rcode
doh_ad
doh_answer
doh_rrsig_count
doh_dnskey_count
doh_ds_count
doh_nsec_count
doh_dnssec_present
```

## 注意事项

- `doh` 实现 HTTP/1.1；`doh-h2` 实现 HTTP/2（公共 DoH 的常见形态），分别使用对应 `-alpn`。
- `doh-h2` 使用内置 HTTP/2 实现，支持 HPACK literal name/value 以及 Huffman 响应头。
- DoH over HTTP/3 是后续扩展。
- `doh_dnssec_present` 是部署证据，不是完整 DNSSEC 链验证。
- 这里不使用 DoT 的 2 字节长度前缀；DoH 直接把 DNS 报文作为 HTTP body。
