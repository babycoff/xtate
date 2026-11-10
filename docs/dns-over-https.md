# DNS over HTTPS (DoH)

**English** · [中文](zh-CN/dns-over-https.md)

`doh` is a state sub-probe for DNS over HTTPS (RFC 8484, HTTP/1.1). TLS is
owned by `tls-state`.

```text
tcp-state -> tls-state (ALPN http/1.1) -> doh
```

## Run

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh -alpn http/1.1 -sni dns.example \
              -subprobe-arg '--req-name=example.com --doh-host=dns.example'" \
  -show info
```

Linux scanners must install `firewall/add_rules.sh`; Windows needs the normal
`-if` / `--router-mac` setup.

## Parameters

| Option | Meaning |
|:---|:---|
| `--req-name` | DNS name to query (required) |
| `--req-type` | DNS type, default `A` |
| `--doh-path` | HTTP path, default `/dns-query` |
| `--doh-host` | HTTP Host header (required) |
| `--dnssec` | Send EDNS0 DO=1 |
| `--edns-size` | EDNS0 UDP size, default 1232 |

## Output

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

## Caveats

- This release implements HTTP/1.1 only; use `-alpn http/1.1`.
- DoH over HTTP/2/3 is a later extension.
- `doh_dnssec_present` is deployment evidence, not a validated DNSSEC chain.
- The 2-byte DoT length prefix is **not** used here; DoH carries the raw DNS
  message as the HTTP body.
