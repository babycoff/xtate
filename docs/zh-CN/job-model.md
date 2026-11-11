# Job 模型与超时

[English](../job-model.md) · **中文**

长时间扫描需要受管 job，而不是阻塞式工具调用。job manager 是 MCP、TUI 和后续
GUI 共用的后端。

## API

```c
JobManager *job_manager_create(unsigned max_jobs);
Job *job_start(JobManager *, char *const argv[], const char *result_path,
               const char *log_path, unsigned timeout_sec);
JobState job_poll(Job *);
bool job_cancel(Job *);
bool job_wait(Job *, unsigned timeout_ms);
```

状态：`queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out`、
`stalled`。

`timeout_sec` 可选（0 = 不限制）；没有 `--job-timeout` 时 `--job-run` 会读取它。
`--job-stall-timeout` 检测无输出进展，不要求预先知道扫描总时长。

## 平台映射

| 关注点 | Linux | Windows |
|:---|:---|:---|
| 进程 | `fork`/`execv` | `CreateProcessA` |
| 进程组 | `setsid` | `CREATE_NEW_PROCESS_GROUP` |
| 终止 | `SIGTERM`/进程组 | `TerminateProcess`/`TerminateJobObject` |
| 父进程退出 | `PR_SET_PDEATHSIG` | Job Object `KILL_ON_JOB_CLOSE` |
| 时钟 | `CLOCK_MONOTONIC` | `GetTickCount64` |
| 输出 | `dup2` 到文件 | `STARTF_USESTDHANDLES` |

不使用 shell；`argv` 直接传递。

## 设计规则

- worker 复用同一个 `xtate` 二进制，不引入解释器。
- 每个 job 独立结果文件；超时/取消保留部分结果。
- timeout 是总墙钟时间，不是单连接超时。
- 后续本地控制 API（`job.start/status/results/cancel`）复用该 manager；
  MCP/TUI/GUI 都是客户端。
- job id 稳定；生命周期错误码为 `SCAN_TIMEOUT`、`SCAN_CANCELLED`、
  `JOB_NOT_FOUND`、`JOB_LIMIT_REACHED`。
- 当前控制面单线程，调用方串行访问。

## 当前状态

核心 manager + Linux/Windows 实现 + Linux smoke test：
`tests/job/test_job.c`（timeout、cancel、complete）。CLI/MCP 接线是下一步。

## CLI

```bash
xtate --job-run=request.json --job-result=out.ndjson --job-timeout=30
```

只有 `--job-run` 的 worker 会写 heartbeat。普通 CLI 扫描
（`xtate -ip ... -scan ...`）不会写 heartbeat，不改变行为，也不产生额外文件。
`--job-heartbeat` 是内部 worker 参数。

以受管 worker 启动同一二进制，等待完成并输出：

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

worker 输出 NDJSON（`--show all`、`--wait 1`）。`--job-timeout` 是总墙钟上限。

## 测试

```bash
XTATE_BIN=bin/xtate bash tests/job/test_cli.sh
```

覆盖 completed job、结果文件和 timed_out job。

## Heartbeat 与 stall 检测

普通 CLI 扫描不会写 heartbeat 文件；只有 `--job-run` worker 会写。

worker 在状态循环中写 `<result>.heartbeat`：

```text
time=...
sent=...
targets=...
success=...
failed=...
info=...
```

heartbeat 带 `phase=tx|draining`；非 `tx` 阶段表示已停止发包、正在收尾，
不参与“无进展”判定。heartbeat 使用临时文件 + rename 原子写入。

manager 把 heartbeat 过期视为 worker 卡死。扫描进展看
`packets_sent`/`targets_done` 是否变化，不看结果文件增长；没有存活目标时
结果不增长仍然可能是正常扫描。结果文件增长只作为辅助信息。
`--job-heartbeat-timeout` 默认 30 秒；`--job-stall-timeout` 检测 heartbeat
正常但无进展的情况。

## 测试

Linux：`tests/job/test_heartbeat.c` 覆盖 heartbeat 新鲜/进展、过期 heartbeat、
以及 `phase=draining` 豁免。Windows：`tests/job/test_heartbeat.ps1` 启动 job，
检查 completed 和 heartbeat 内容。当前 worker phase 只有 `tx` 和 `draining`，
尚未引入单独的 `waiting` 阶段。

## 大结果处理（P0a）

- `job_read_results` 使用 `uint64_t` offset 和 64 位 seek，只返回完整行，并给出
  `next_offset`/`truncated`。
- heartbeat 节流到约每秒一次。
- `job_manager_set_retention` / `job_manager_prune` 限制保留的完成 job 数量并按
  TTL 过期。
- 控制客户端必须请求有界 chunk，不能一次读取整个结果文件。
