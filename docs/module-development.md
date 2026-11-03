# Writing modules

**English** · [中文](zh-CN/module-development.md)

This guide is the C-level counterpart to [Modules](./modules.md). It describes
the four module registries and the contracts their callbacks must satisfy. The
headers are the source of truth:

- [`src/scan-modules/scan-modules.h`](../src/scan-modules/scan-modules.h)
- [`src/probe-modules/probe-modules.h`](../src/probe-modules/probe-modules.h)
- [`src/output-modules/output-modules.h`](../src/output-modules/output-modules.h)
- [`src/generate-modules/generate-modules.h`](../src/generate-modules/generate-modules.h)

Xtate has no runtime plugin loader. A module is a C struct registered in a
NULL-terminated array. `CMakeLists.txt` globs `src/*.c`, so a new source file is
compiled automatically; it still has to be registered and documented.

## Shared data types

### `Target`

```c
typedef struct Target {
    unsigned  ip_proto;
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned  port_them;
    unsigned  port_me;
} Target;
```

`ip_proto` says what the port means. Ports can be TCP, UDP (`u:`), SCTP or a
module-private value; `get_actual_proto_port()` performs the normal parsing.

### `ProbeTarget`

```c
typedef struct ProbeModuleTarget {
    Target   target;
    unsigned cookie;
    unsigned index;
} ProbeTarget;
```

`index` is the zero-based slot index for a multi-slot ProbeModule. For a
single-slot probe it is always zero. `cookie` is the per-packet cookie used by
stateless UDP probes.

### `OutItem` and `DataChain`

`OutItem` is declared in
[`src/output-modules/output-types.h`](../src/output-modules/output-types.h).
A scan or probe writes:

- `item->level`: `OUT_INFO`, `OUT_FAILURE` or `OUT_SUCCESS`;
- `item->classification` / `item->reason`: short machine-readable strings;
- `item->scan_report` and/or `item->probe_report`: `DataChain` reports;
- `item->no_output = 1` to drop an otherwise produced item.

Use the `dach_*` API from
[`src/util-data/data-chain.h`](../src/util-data/data-chain.h):

```c
dach_set_int(&item->probe_report, "version", 3);
dach_append_str(&item->probe_report, "server", name, strlen(name));
dach_append_banner(&item->probe_report, "banner", px, sizeof_px);
```

Do not free a report yourself; the output layer consumes and releases it.
Do not keep pointers to `Target`, `px` or an `OutItem` after the callback
returns.

---

## Probe modules

Probe modules are the L5+ side of a scan: make a payload, validate a stateless
UDP response, and/or parse a response into an `OutItem`. The registry is
[`src/probe-modules/probe-modules.c`](../src/probe-modules/probe-modules.c).

### Required and optional callbacks

| Callback | When it is required | Contract |
|:---|:---|:---|
| `init_cb` | always | Main thread. Return `false` to abort startup. |
| `make_payload_cb` | TCP/UDP payload | Tx thread or handle thread. Fill at most `PM_PAYLOAD_SIZE` bytes; return the length. |
| `get_payload_length_cb` | `ProbeType_TCP` | Same length as `make_payload_cb` without writing the packet. |
| `validate_response_cb` | `ProbeType_UDP` | Rx thread. Return true when the datagram belongs to this probe. |
| `handle_response_cb` | non-state probes | Handle thread. Fill the item; returning a value is reserved. |
| `conn_init_cb` | state probes | Initialize per-connection `ProbeState`. |
| `make_hello_cb` | state probes | Fill a `DataPass` with the next bytes to send. |
| `parse_response_cb` | state probes | Parse one response and optionally emit output through `OutConf`. |
| `conn_close_cb` | state probes | Release per-connection state. |
| `close_cb` | always | Main thread cleanup; `probe_close_nothing` is fine. |

All callbacks can run concurrently. They must be thread-safe for themselves.
The stateless probe target is not modifiable; read it and copy anything needed.

### A minimal single-slot probe

```c
static size_t example_make(ProbeTarget *target, unsigned char *buf) {
    (void)target;
    return (size_t)snprintf((char *)buf, PM_PAYLOAD_SIZE, "PING\r\n");
}

static size_t example_len(ProbeTarget *target) {
    (void)target;
    return 7;
}

static unsigned example_handle(unsigned th_idx, ProbeTarget *target,
                               const unsigned char *px, unsigned sizeof_px,
                               OutItem *item) {
    (void)th_idx;
    dach_set_int(&item->probe_report, "example_index", target->index);
    dach_append_banner(&item->probe_report, "banner", px, sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "example");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "reply");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe ExampleProbe = {
    .name = "example",
    .type = ProbeType_TCP,
    .desc = "Minimal TCP probe.",
    .init_cb = &probe_init_nothing,
    .make_payload_cb = &example_make,
    .get_payload_length_cb = &example_len,
    .handle_response_cb = &example_handle,
    .close_cb = &probe_close_nothing,
};
```

Register it:

```c
extern Probe ExampleProbe;
...
&ExampleProbe,
//! REGISTER YOUR PROBE MODULE HERE
```

Also add its Chinese description in `src/util-misc/i18n.c` and update the module
lists/counts (`docs/modules.md`, README, tests).

### `ProbeSlotPlan`

A probe can declare several independent pseudo-flows without adding state to
the scanner:

```c
typedef struct ProbeSlotPlan {
    unsigned             count;       /* 0 or 1 = single */
    ProbeSlotTrigger     trigger;
    probe_slots_continue continue_cb; /* optional */
} ProbeSlotPlan;
```

```c
typedef enum ProbeSlotTrigger {
    ProbeSlot_None = 0,
    ProbeSlot_Always = 1,
    ProbeSlot_AfterFirstReply = 2,
} ProbeSlotTrigger;
```

- `count`: slot count; `0` or `1` means single-slot. A `count > 1` with
  `ProbeSlot_None` is rejected at startup.
- `ProbeSlot_Always`: execute all slots from the first iteration. A scan
  transmitter returns `true` to ask for the next slot; the next call receives
  `ProbeTarget.index == 1`, and so on.
- `ProbeSlot_AfterFirstReply`: send slot 0 normally; after a response, call
  `continue_cb(target, px, sizeof_px)`; if it returns true, send slots
  1..count-1.
- `continue_cb` may be `NULL` for `AfterFirstReply`, which means continue after
  the first response.

Slot `i` is mapped to `source_port_start + i` by ZBanner/TCP and UDP. The
source-port range must therefore have at least `count` ports. The engine stores
no target group and does not aggregate; each slot emits its own `OutItem`.

Current executor support:

| Scan | `Always` | `AfterFirstReply` |
|:---|:---:|:---:|
| `zbanner` (TCP) | yes | yes |
| `udp` | yes | rejected at startup |
| `tcp-state` (HLTCP) | not a slot plan | not a slot plan |

Same-connection multi-step logic belongs in HLTCP/state probes, not in a
`ProbeSlotPlan`.

### HLTCP and slot plans (planned)

HLTCP (`tcp-state`) is not wired into `ProbeSlotPlan` yet. Its existing
`ProbeState`/`DataPass` callbacks can already perform multi-step work on one
connection, so the two possible meanings must not be conflated:

- **Independent flows** (`ProbeSlot_Always`): open several TCP connections
  from different source-port slots and run one HLTCP flow per slot. This is
  mechanically possible, but each flow consumes a TCB, timeout state and source
  port; it needs explicit TCB/expiry tests.
- **Connection-local sequence** (`AfterFirstReply`): send the next application
  probe on the **same** connection after the first accepted response. This maps
  naturally to `ProbeState`/`DataPass`, not to the source-port slot executor.

Plan: first document a scope distinction (independent flow vs connection-local
sequence), then implement connection-local `AfterFirstReply` through the state
probe state machine, and only then consider parallel HLTCP `Always`. Do not
multiply HLTCP TCBs silently. No HLTCP slot support is claimed today.

### `ProbeSlot_Always` examples

Two built-in developer modules exercise the API and double as copyable
templates:

- `slot-test` (`src/probe-modules/slot-test-probe.c`): three TCP slots; each
  payload is `slot:<n>\n`; response fields `slot_test_slot` and
  `slot_test_payload`.
- `slot-test-udp` (`src/probe-modules/slot-test-udp-probe.c`): the same shape
  over UDP, with `ProbeSlot_Always`.

Both are registered in the normal probe inventory. They are intentionally
trivial and are covered by `tests/lab/run.sh`.

### UDP notes

UDP has no handshake, so `ProbeSlot_AfterFirstReply` is not meaningful for the
current UDP executor and is rejected. Use `ProbeSlot_Always`.

UDP probe responses are matched by the source port slot and by
`validate_response_cb`. Target ports must use the UDP prefix:

```bash
sudo ./bin/xtate -ip 192.0.2.10 -p u:8082 -scan udp -probe slot-test-udp \
  -src-port 47000-47255 -show info
```

`PM_PAYLOAD_SIZE` is 2048, but a packet must also fit in the IP/UDP headers and
`PKT_BUF_SIZE`; keep payloads below roughly 2000 bytes.

---

## Scan modules

A scan module sends the first packet for each target and validates/handles
received packets. The registry is
[`src/scan-modules/scan-modules.c`](../src/scan-modules/scan-modules.c).

| Callback | Contract |
|:---|:---|
| `init_cb` | Main thread. Validate the probe type, source ports, and module args. |
| `transmit_cb` | Tx thread. Fill `px`/`len`; return `true` when the same logical target needs another packet. |
| `validate_cb` | Rx thread. Decide `pre->go_record`, dedup behavior and target pre-validation. |
| `handle_cb` | Handle thread. Emit `OutItem`, send follow-up packets through `NetStack`. |
| `poll_cb` | Handle thread, every loop; must not block. |
| `close_cb` | Main-thread cleanup. |
| `status_cb` | Main-thread status suffix, at most `SM_STATUS_SIZE`. |

`transmit_cb` is also how `ProbeSlot_Always` works:

```c
if (probe->slots.trigger == ProbeSlot_Always &&
    target->index + 1 < probe_slot_count(probe))
    return true;
```

The transmit loop keeps the same generated target and increments
`ScanTarget.index`; the next slot therefore uses the next source port. This is
why a slot count must fit the source-port range.

Stateless scans (ZBanner, tcp-syn, UDP) must not retain per-target state. Use
the cookie and source-port slot to recognize responses. Stateful TCP belongs in
`tcp-state`/HLTCP.

Add `required_probe_type`, `bpf_filter`, `params`, descriptions, registration,
i18n and module lists just like a probe. `scan_init_nothing`,
`scan_poll_nothing`, `scan_close_nothing` and `scan_no_status` are reusable
no-op callbacks.

---

## Output modules

Output modules serialize an `OutItem`; they do not parse packets. The registry
is [`src/output-modules/output-modules.c`](../src/output-modules/output-modules.c).

```c
typedef struct OutputModule {
    const char *name;
    const char *short_desc;
    const char *desc;
    bool        need_file;
    ConfParam  *params;

    output_modules_init   init_cb;
    output_modules_result result_cb;
    output_modules_close  close_cb;
} OutputModule;
```

- `init_cb(xconf, out)`: open the file/connection; `out->output_filename` is
  already parsed.
- `result_cb(item)`: called under the output module mutex, so one module does
  not need its own lock. Read the `DataChain` links and serialize them.
- `close_cb(out)`: flush and close.
- `need_file`: require `-output-file`.
- `params`: module arguments from `-output-arg`.

The output layer owns `item` and its chains. Do not keep item pointers after
`result_cb` returns. `output_result_nothing` and `output_close_nothing` are
no-op helpers.

---

## Generate modules

Generators enumerate `(target, endpoint)` pairs. They are low-level and run in
Tx threads; `hasmore_cb` and `generate_cb` must be thread-safe per tx index. The
registry is
[`src/generate-modules/generate-modules.c`](../src/generate-modules/generate-modules.c).

| Callback | Contract |
|:---|:---|
| `init_cb` | Main thread. Set target/endpoint counts and optionally request IPv4/IPv6 adapter init. |
| `hasmore_cb` | Tx threads and main thread. Return false when this tx index is exhausted. |
| `generate_cb` | Tx thread. Fill a `Target` from index/repeat/source parameters. |
| `close_cb` | Main-thread cleanup. |

`generate_cb` should be deterministic for a given `(tx_index, index, repeat)`
and must not depend on mutable global state that differs between threads. It
receives a `struct source_t` for source IP/port masking. `blackrock` is the
reference implementation.

Use `generate_init_nothing` only when the module has no real initialization.
The main thread prints target/endpoint counts from `init_cb`; leave them zero
when unknown.

---

## Adding a module: checklist

1. Add the `.c` file under the right `src/*-modules/` directory.
2. Add the `extern` and registry entry (`//! REGISTER YOUR ... MODULE HERE`).
3. Add Chinese help text to `src/util-misc/i18n.c`; the help tests exercise it.
4. Add parameters with `ConfParam` and help strings; support `-*-arg`.
5. Update `docs/modules.md`, the README lists/counts, and the Chinese docs.
6. Add a focused test. Prefer a real lab path when packets are involved; for a
   probe slot plan, add a case to `tests/lab/run.sh`.
7. Run the normal test set:

```bash
bash tests/include/check_headers.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/xtate --selftest
XTATE_BIN=./build/xtate bash tests/jarm/test.sh
XTATE_BIN=./build/xtate bash tests/i18n/test.sh
```

## Common mistakes

- Declaring `get_payload_length_cb` inconsistent with `make_payload_cb`.
- Indexing the payload without checking `target->index < probe_slot_count()`.
- Holding a `ProbeTarget`/`OutItem` pointer after a callback.
- Doing blocking I/O in `poll_cb`.
- Assuming `-p 8082` is UDP; use `u:8082`.
- Using `ProbeSlot_AfterFirstReply` on UDP; use `Always`.
- Adding scanner-side group state for multi-slot probes. The scanner emits one
  item per slot; aggregation belongs to an output-side tool such as
  `tools/jarm_aggregate.py`.
- Forgetting the i18n entry: English-only module descriptions fail the help
  localization test.
