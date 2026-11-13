# Safety and authorization

`authorized: true` is an attestation by the caller. It is not a credential and
does not prove permission. Xtate will send packets once it is set, so the
decision to set it belongs to the operator, not to the tool.

## Authorization checklist

Before the first packet, record:

- Who authorized the scan (name, team, ticket or written instruction).
- Exact address ranges and exclusions.
- Ports and protocols in scope.
- Time window and maximum rate.
- A contact for accidental impact.
- Whether the targets are production, shared, or third-party infrastructure.

If any item is missing, do not call `start_scan`. Use read-only tools and ask.

## Refuse or stop when

- The request targets the public internet, a cloud provider range, or a network
  the user does not own or explicitly control.
- The user asks to hide the scan, spoof the source, evade detection, or
  "just test" without authorization.
- The target set expands beyond the stated scope.
- A route or interface check shows traffic would leave through the wrong path.
- The time window or rate would exceed what was authorized.
- A job is cancelled, stalled or timed out and the user has not re-authorized a
  retry.

## Operational limits

- Prefer stateless `tcp-syn` or a single targeted probe. Stateful scans open
  connections and are more intrusive.
- Start with a small rate. Increase only with authorization; the protocol cap is
  10000 packets per second, not a target.
- Set `timeout_sec` for every job. Never start an unbounded scan.
- Use a dedicated `result_path`; do not point it at an existing important file.
- Use `include_file` only for a target list in the authorized scope. The file is
  read by the scanner process, so it must not contain secrets.
- Use `dry_run: true` when the goal is only to confirm target expansion.

## Host prerequisites

- Linux raw sockets need root or `CAP_NET_RAW`; stateful scans also need the
  firewall rules that stop the kernel from emitting RST/ICMP for scanned flows.
  See the `xtate://docs/firewall` MCP resource. Do not disable the firewall.
- Windows raw packet capture needs Npcap and administrator privileges.
- On multi-NIC hosts, pass `interface` only after `explain_target` confirms it.
  For `include_file`, route discovery is not implemented; preflight
  representative targets and treat the lack of verification as a risk.

## Data handling

- MCP tool output and result files can contain banners, certificates, hostnames
  and service metadata. Treat them as sensitive customer data.
- Do not paste tokens, credentials or full result chunks into chat.
- Summarize counts and selected fields; keep raw chunks in the job directory.
- Do not commit result files or audit logs to a repository.

## Token hygiene

`XTATE_CONTROL_TOKEN` is a local shared secret between the control plane and the
MCP client. Set it in both environments; never put it in a scan request, a result
path, a prompt, or a committed config file. If the token leaks, restart the
control plane and MCP server with a new token.
