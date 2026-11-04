# 编写模块

**中文** · [English](../module-development.md)

这篇文档是 [模块说明](./modules.md) 的 C 接口版本，说明四类模块的注册表和
回调契约。头文件是最终依据：

- [`src/scan-modules/scan-modules.h`](../../src/scan-modules/scan-modules.h)
- [`src/probe-modules/probe-modules.h`](../../src/probe-modules/probe-modules.h)
- [`src/output-modules/output-modules.h`](../../src/output-modules/output-modules.h)
- [`src/generate-modules/generate-modules.h`](../../src/generate-modules/generate-modules.h)

Xtate 没有运行期插件加载。一个模块就是一个 C 结构体，加上以 `NULL` 结尾的
注册表里的一行。`CMakeLists.txt` 会 glob `src/*.c`，所以新 `.c` 会自动参与
编译，但仍然必须手动注册、写帮助并更新文档。

## 公共数据类型

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

`ip_proto` 决定端口含义。端口可以是 TCP、UDP（`u:`）、SCTP 或模块自定义
值；正常解析由 `get_actual_proto_port()` 完成。

### `ProbeTarget`

```c
typedef struct ProbeModuleTarget {
    Target   target;
    unsigned cookie;
    unsigned index;
} ProbeTarget;
```

`index` 是多 slot 探测中从 0 开始的 slot 编号；单 slot 探测始终为 0。
`cookie` 是无状态 UDP 探测的每包 cookie。

### `OutItem` 与 `DataChain`

`OutItem` 定义在
[`src/output-modules/output-types.h`](../../src/output-modules/output-types.h)。
扫描模块或探测模块填写：

- `item->level`：`OUT_INFO` / `OUT_FAILURE` / `OUT_SUCCESS`；
- `item->classification` / `item->reason`：短的机器可读分类和原因；
- `item->scan_report` / `item->probe_report`：`DataChain` 报告；
- `item->no_output = 1`：丢弃本来会产生的输出。

报告使用
[`src/util-data/data-chain.h`](../../src/util-data/data-chain.h) 的
`dach_*` API：

```c
dach_set_int(&item->probe_report, "version", 3);
dach_append_str(&item->probe_report, "server", name, strlen(name));
dach_append_banner(&item->probe_report, "banner", px, sizeof_px);
```

不要自行释放报告；输出层会消费并释放 `OutItem`。回调返回后不要再保存
`Target`、`px` 或 `OutItem` 的指针。

---

## 可复制示例

[`examples/modules/`](../../examples/modules/) 为每种模块类型提供一个
编译检查过的模板：

| 模板 | 类型 |
|:---|:---|
| [`tcp-probe.c`](../../examples/modules/tcp-probe.c) | 单 slot TCP 探测 |
| [`udp-probe.c`](../../examples/modules/udp-probe.c) | UDP 探测 |
| [`state-probe.c`](../../examples/modules/state-probe.c) | HLTCP 状态探测 |
| [`output-module.c`](../../examples/modules/output-module.c) | 输出模块 |
| [`generate-module.c`](../../examples/modules/generate-module.c) | 目标生成模块 |

它们**不会注册**进生产二进制。使用时复制到对应的 `src/*-modules/`，修正
相对 include，添加注册表、i18n、文档和测试。编译检查已接入 CI：

```bash
bash tests/module-examples/test.sh
```

内置的 `slot-test` / `slot-test-udp` 仍然是 `ProbeSlot_Always` 的运行期示例；
这些模板覆盖其它模块类型和 state probe 形状。

---

## 探测模块（Probe）

探测模块负责生成载荷、校验无状态 UDP 响应，或解析响应并填写 `OutItem`。注册表在
[`src/probe-modules/probe-modules.c`](../../src/probe-modules/probe-modules.c)。

### 必需和可选回调

| 回调 | 何时需要 | 契约 |
|:---|:---|:---|
| `init_cb` | 总是 | 主线程；返回 `false` 终止启动。 |
| `make_payload_cb` | TCP/UDP 载荷 | Tx 或 handler 线程；最多写 `PM_PAYLOAD_SIZE` 字节，返回长度。 |
| `get_payload_length_cb` | `ProbeType_TCP` | 与 make 相同长度，但不写包。 |
| `validate_response_cb` | `ProbeType_UDP` | Rx 线程；判断数据报是否属于本探测。 |
| `handle_response_cb` | 非 state 探测 | Handler 线程；填写 item，返回值当前保留。 |
| `conn_init_cb` | state 探测 | 初始化每连接 `ProbeState`。 |
| `make_hello_cb` | state 探测 | 通过 `DataPass` 填写下一段要发的数据。 |
| `parse_response_cb` | state 探测 | 解析响应并通过 `OutConf` 输出。 |
| `conn_close_cb` | state 探测 | 释放每连接状态。 |
| `close_cb` | 总是 | 主线程清理；可用 `probe_close_nothing`。 |

所有回调都可能并发执行，必须自身线程安全。无状态探测的 target 不可修改；
只读并复制需要的数据。

### 最小单 slot 探测

完整版本见 [`examples/modules/tcp-probe.c`](../../examples/modules/tcp-probe.c)。

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

注册：

```c
extern Probe ExampleProbe;
...
&ExampleProbe,
//! REGISTER YOUR PROBE MODULE HERE
```

还要在 `src/util-misc/i18n.c` 添加中文描述，并更新模块列表/数量
（`docs/modules.md`、README、测试）。

### `ProbeSlotPlan`

探测模块可以声明多个独立伪连接，而不给扫描器增加状态：

```c
typedef struct ProbeSlotPlan {
    unsigned             count;       /* 0 或 1 = 单 slot */
    ProbeSlotTrigger     trigger;
    probe_slots_continue continue_cb; /* 可选 */
} ProbeSlotPlan;
```

```c
typedef enum ProbeSlotTrigger {
    ProbeSlot_None = 0,
    ProbeSlot_Always = 1,
    ProbeSlot_AfterFirstReply = 2,
} ProbeSlotTrigger;
```

- `count`：slot 数；`0` 或 `1` 表示单 slot。`count > 1` 却使用
  `ProbeSlot_None` 会在启动时被拒绝。
- `ProbeSlot_Always`：第一次迭代就发送全部 slot。扫描模块的 transmit 回调
  返回 `true` 请求下一个 slot，下一次调用会看到 `ProbeTarget.index == 1`，
  以此类推。
- `ProbeSlot_AfterFirstReply`：先正常发送 slot 0；收到响应后调用
  `continue_cb(target, px, sizeof_px)`，返回 true 才发送 slot 1..count-1。
- `AfterFirstReply` 的 `continue_cb` 可以为 `NULL`，表示收到第一个响应后继续。

slot `i` 在 ZBanner/TCP 和 UDP 中都映射到 `source_port_start + i`，因此
源端口范围必须至少覆盖 `count`。引擎不保存目标 group，也不做聚合；每个
slot 输出自己的 `OutItem`。

当前执行器支持情况：

| 扫描模块 | `Always` | `AfterFirstReply` |
|:---|:---:|:---:|
| `zbanner`（TCP） | 支持 | 支持 |
| `udp` | 支持 | 启动时拒绝 |
| `tcp-state`（HLTCP） | 不是 slot plan | 不是 slot plan |

同一连接上的多步交互属于 HLTCP/state 探测，不属于 `ProbeSlotPlan`。

### HLTCP 与 slot plan（计划中）

HLTCP（`tcp-state`）目前还没有接入 `ProbeSlotPlan`。它现有的
`ProbeState`/`DataPass` 回调已经能在同一条连接上做多步交互，但两种“slot”
含义不能混为一谈：

- **独立 flow**（`ProbeSlot_Always`）：从不同源端口 slot 建多条 TCP 连接，
  每条连接跑一条 HLTCP flow。技术上可行，但每条 flow 都占一个 TCB、超时状态
  和源端口，必须补 TCB/过期测试。
- **连接内序列**（`AfterFirstReply`）：在**同一条连接**上，收到第一个被接受
  的响应后发送下一个应用层探测。这天然对应 `ProbeState`/`DataPass`，不是
  源端口 slot 执行器。

计划：先明确 scope（独立 flow vs 连接内序列），再用 state probe 状态机实现
连接内 `AfterFirstReply`，最后才考虑并行 HLTCP `Always`。不能悄悄成倍放大
HLTCP 的 TCB 数量。当前不宣称 HLTCP 支持 slot plan。

### 探针控制参数与指纹

研究型探针应当显式、可调：

- 暴露 payload/标识字符串（例如 SSH 的 `--send-banner`）；
- 暴露输出开关和上限，而不是固定输出；
- 协议有文本字段时，默认使用**明面上的** Xtate 标记，并且可替换/关闭；
- 不要隐藏身份，也不要使用未文档化的标记。

两个新协议探针遵循这个规则：

- `ssh`：`--send-banner` 修改标识字符串，默认
  `SSH-2.0-Xtate_1.0\r\n`；`--no-banner`、`--no-software`、`--no-kex`、
  `--record-kexinit` 控制输出；报告 `ssh_banner`、`ssh_protocol`、
  `ssh_software`、`ssh_comment`、全部十个 KEXINIT name-list 和
  `ssh_first_kex_follows`。
- `h2c`：仅 cleartext（不做 TLS/ALPN）。`--settings-hex` 修改客户端 SETTINGS payload；`--ping-hex` 修改
  PING payload（默认 `Xtate/29`，明面标记），`--no-ping` 关闭；
  `--all-frames`、`--max-frames`、`--no-settings`、`--record-raw` 控制输出；
  报告帧头、`http2_settings_count`、`http2_set_<id>` 值和可选原始帧。

### TLS 上的 HTTP/2

`h2` 是 **state probe**，不是单 slot TCP 探针：

```bash
-scan tcp-state -probe tls-state \
  -probe-arg "-subprobe h2 -sni example.test -alpn h2"
```

它在 `tls-state` 完成 ALPN `h2` 后发送 HTTP/2 preface、SETTINGS 和最小
HPACK 请求，并解析 SETTINGS/HEADERS/DATA。参数：`--path`、`--authority`、
`--user-agent`/`--no-user-agent`、`--settings-hex`、`--max-frames`、
`--max-data`、`--record-raw`、`--no-decode-headers`。
HPACK 目前支持静态表和 literal，不支持 Huffman/动态表索引。

### `ProbeSlot_Always` 示例

内置两个开发测试探针，可直接当模板：

- `slot-test`（`src/probe-modules/slot-test-probe.c`）：三个 TCP slot，载荷
  `slot:<n>\n`，输出 `slot_test_slot` / `slot_test_payload`；
- `slot-test-udp`（`src/probe-modules/slot-test-udp-probe.c`）：同样形状的
  UDP `ProbeSlot_Always`。

它们正常出现在 probe 列表里，并由 `tests/lab/run.sh` 覆盖。

### UDP 注意事项

模板见 [`examples/modules/udp-probe.c`](../../examples/modules/udp-probe.c)。

UDP 没有握手，当前 UDP 执行器拒绝 `ProbeSlot_AfterFirstReply`，请使用
`ProbeSlot_Always`。

UDP 响应通过源端口 slot 和 `validate_response_cb` 匹配。目标端口必须使用
UDP 前缀：

```bash
sudo ./bin/xtate -ip 192.0.2.10 -p u:8082 -scan udp -probe slot-test-udp \
  -src-port 47000-47255 -show info
```

`PM_PAYLOAD_SIZE` 为 2048，但还要容纳 IP/UDP 头和 `PKT_BUF_SIZE`；载荷建议
控制在约 2000 字节以内。

---

## 扫描模块（Scan）

扫描模块为目标发送第一个包，并校验/处理收到的包。注册表在
[`src/scan-modules/scan-modules.c`](../../src/scan-modules/scan-modules.c)。

| 回调 | 契约 |
|:---|:---|
| `init_cb` | 主线程。校验 probe 类型、源端口和参数。 |
| `transmit_cb` | Tx 线程。填写 `px`/`len`；返回 `true` 表示同一逻辑目标还要再发一个包。 |
| `validate_cb` | Rx 线程。决定 `pre->go_record`、去重和目标预校验。 |
| `handle_cb` | Handler 线程。产出 `OutItem`，通过 `NetStack` 发后续包。 |
| `poll_cb` | Handler 线程每轮调用；不能阻塞。 |
| `close_cb` | 主线程清理。 |
| `status_cb` | 主线程状态后缀，最多 `SM_STATUS_SIZE`。 |

`transmit_cb` 也是 `ProbeSlot_Always` 的工作方式：

```c
if (probe->slots.trigger == ProbeSlot_Always &&
    target->index + 1 < probe_slot_count(probe))
    return true;
```

发送循环保持同一个 generator target，并递增 `ScanTarget.index`；下一个 slot
因此使用下一个源端口。这也是 slot 数量必须落在源端口范围内的原因。

无状态扫描（ZBanner、tcp-syn、UDP）不能保存逐目标状态；用 cookie 和源端口
slot 识别响应。有状态 TCP 放在 `tcp-state`/HLTCP。

像 probe 一样添加 `required_probe_type`、`bpf_filter`、`params`、描述、注册、
i18n 和模块列表。`scan_init_nothing`、`scan_poll_nothing`、
`scan_close_nothing`、`scan_no_status` 是可复用空实现。

---

## 输出模块（Output）

编译模板见 [`examples/modules/output-module.c`](../../examples/modules/output-module.c)。

输出模块序列化 `OutItem`，不解析网络包。注册表在
[`src/output-modules/output-modules.c`](../../src/output-modules/output-modules.c)。

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

- `init_cb(xconf, out)`：打开文件/连接；`out->output_filename` 已解析。
- `result_cb(item)`：在输出模块 mutex 下调用，模块本身不需要再加锁；读取
  `DataChain` 并序列化。
- `close_cb(out)`：flush 并关闭。
- `need_file`：要求必须给 `-output-file`。
- `params`：`-output-arg` 的模块参数。

输出层拥有 `item` 及其 chain；`result_cb` 返回后不要保存 item 指针。
`output_result_nothing` 和 `output_close_nothing` 是空实现辅助。

---

## 生成模块（Generate）

编译模板见 [`examples/modules/generate-module.c`](../../examples/modules/generate-module.c)。

生成模块枚举 `(target, endpoint)` 对，运行在 Tx 线程；`hasmore_cb` 和
`generate_cb` 必须按 tx index 线程安全。注册表在
[`src/generate-modules/generate-modules.c`](../../src/generate-modules/generate-modules.c)。

| 回调 | 契约 |
|:---|:---|
| `init_cb` | 主线程。设置 target/endpoint 数量，按需请求 IPv4/IPv6 适配器初始化。 |
| `hasmore_cb` | Tx 线程和主线程。当前 tx index 枚举完后返回 false。 |
| `generate_cb` | Tx 线程。根据 index/repeat/source 参数填写 `Target`。 |
| `close_cb` | 主线程清理。 |

对给定的 `(tx_index, index, repeat)`，`generate_cb` 应当确定且不依赖跨线程
可变全局状态。它接收 `struct source_t` 的源 IP/端口掩码。`blackrock` 是参考
实现。

没有真正初始化时可用 `generate_init_nothing`。主线程用 `init_cb` 的计数打印
目标/端点信息；不知道时留 0。

---

## 新增模块检查清单

1. 在对应 `src/*-modules/` 下添加 `.c`。
2. 添加 `extern` 和注册表条目（`//! REGISTER YOUR ... MODULE HERE`）。
3. 在 `src/util-misc/i18n.c` 添加中文帮助；帮助测试会检查。
4. 用 `ConfParam` 声明参数和帮助；支持 `-*-arg`。
5. 更新 `docs/modules.md`、README 列表/数量以及中文文档。
6. 添加聚焦测试。涉及真实报文时优先做 lab 路径；slot plan 加一条
   `tests/lab/run.sh` 用例。
7. 运行常规测试：

```bash
bash tests/include/check_headers.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/xtate --selftest
XTATE_BIN=./build/xtate bash tests/jarm/test.sh
XTATE_BIN=./build/xtate bash tests/i18n/test.sh
```

## 常见错误

- `get_payload_length_cb` 与 `make_payload_cb` 长度不一致。
- 生成载荷时不检查 `target->index < probe_slot_count()`。
- 回调返回后继续持有 `ProbeTarget` / `OutItem` 指针。
- 在 `poll_cb` 里做阻塞 I/O。
- 把 `-p 8082` 当成 UDP；应写 `u:8082`。
- 对 UDP 使用 `ProbeSlot_AfterFirstReply`；应使用 `Always`。
- 给多 slot 探测增加扫描器端 group 状态。扫描器每个 slot 输出一条 item；
  聚合应交给 `tools/jarm_aggregate.py` 这类输出侧工具。
- 忘记 i18n：只有英文的模块描述会导致帮助本地化测试失败。
