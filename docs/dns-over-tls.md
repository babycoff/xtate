# DNS over TLS (DoT)

**English** · [中文](zh-CN/dns-over-tls.md)

`dot` is a state sub-probe for DNS over TLS (RFC 7858). TLS is owned by
`tls-state`; `dot` only sends the length-prefixed DNS query and parses the
response.

```text
tcp-state -> tls-state (ALPN dot) -> dot
```

## Run

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 853 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe dot -alpn dot -sni dns.example \
              -subprobe-arg '--req-name=example.com --dnssec'" \
  -show info
```

Use `-if` and, on Windows, `--router-mac` as required by the normal HLTCP
interface setup. Linux scanners must install the RST/ICMP suppression rules:
`sudo ./firewall/add_rules.sh`.

## Parameters

| Option | Meaning |
|:---|:---|
| `--req-name` | DNS name to query (required) |
| `--req-type` | DNS type, default `A` |
| `--recursive-desired` | Set RD |
| `--dnssec` | Send EDNS0 OPT with DO=1 |
| `--edns-size` | EDNS0 UDP size, default 1232 |

## Output

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

`dot_dnssec_present` is deployment evidence, not a validated DNSSEC chain.

## Caveats

- `tls-state -alpn dot` is required; a server that does not negotiate `dot`
  will fail before the sub-probe runs.
- The 2-byte length prefix is mandatory (RFC 7858).
- Only one DNS query/response is sent per connection.
- If no RST suppression rules are installed, Linux may reset the connection
  before `tls-state` completes.
