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

状态：`queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out`。

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

以受管 worker 启动同一二进制，等待完成并输出：

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

worker 输出 NDJSON（`--show all`、`--wait 1`）。`--job-timeout` 是总墙钟上限。
