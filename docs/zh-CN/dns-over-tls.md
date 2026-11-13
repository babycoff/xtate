# DNS over TLS（DoT）

[English](../dns-over-tls.md) · **中文**

`dot` 是 DNS over TLS（RFC 7858）的 state 子探测。TLS 由 `tls-state` 负责，
`dot` 只发送带 2 字节长度前缀的 DNS 查询并解析响应。

```text
tcp-state -> tls-state (ALPN dot) -> dot
```

## 运行

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 853 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe dot -alpn dot -sni dns.example \
              -subprobe-arg '--req-name=example.com --dnssec'" \
  -show info
```

Windows 需要时用 `-if` 和 `--router-mac`。Linux 扫描端必须先安装
RST/ICMP 抑制规则：`sudo ./firewall/add_rules.sh`。

## 参数

| 参数 | 含义 |
|:---|:---|
| `--req-name` | 要查询的 DNS 名（必需） |
| `--req-type` | DNS 类型，默认 `A` |
| `--recursive-desired` | 设置 RD |
| `--dnssec` | 发送 EDNS0 OPT 且 DO=1 |
| `--edns-size` | EDNS0 UDP 大小，默认 1232 |

## 输出

```text
dot_dns_len
dot_rcode
dot_ad
dot_answer
dot_rrsig_count
dot_dnskey_count
dot_ds_count
dot_nsec_count
dot_dnssec_present
```

`dot_dnssec_present` 是部署证据，不是完整 DNSSEC 链验证。

## 注意事项

- 必须使用 `tls-state -alpn dot`；服务器不协商 `dot` 时子探测不会运行。
- 2 字节长度前缀是 RFC 7858 必需的。
- 每个连接只发送一次 DNS 查询/响应。
- 未安装 RST 抑制规则时，Linux 可能在 `tls-state` 完成前重置连接。
