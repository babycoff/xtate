# 参数解析器测试计划

**中文** · [English](../parser-test-plan.md)

这是 CLI 与模块参数解析器的调研/实施计划，还不是完整测试套件。

## 当前解析面

- 全局表：`src/xconf.c` 的 `ConfParam config_parameters[]`。
- 模块表：`Probe.params`、`Scanner.params`、`Output.params`、
  `Generator.params`。
- 入口：`conf_set_params_from_args`、`conf_set_params_from_str`、
  `conf_set_params_from_substr`。
- 参数切分：`safe_str_to_args`（双引号）、`safe_substr_to_args`（单引号）。
- 嵌套参数：`-scan-arg`、`-probe-arg`、`-output-arg`、`-gen-arg`；
  `tls-state` 还有 `-subprobe` / `-subprobe-arg`。

## 需要测试的发现点

### 参数语法

- `--name=value`、`--name:value`、`--name value`；
- 单横线别名和标点不敏感匹配（`exclude-file` / `excludefile`）；
- `--flag` 带/不带意外 value；
- 未知选项、缺 value、value 以 `-` 开头；
- 重复选项：last wins 还是拒绝，要一致；
- 超长选项名/value；
- `--` 处理和非选项位置 token。

### 值解析器

- `conf_parse_int`：空、部分数字、正负号、溢出；
- `conf_parse_bool`：别名、非法值、`0/1`；
- `conf_parse_size`/`conf_parse_time`：后缀边界、溢出、非法后缀
  （不能在 parser 测试里直接 `exit()`）；
- 模块 setter 的 hex 解析（`settings-hex`、`--header` 形式）；
- MAC/地址边界。

### 引号与嵌套

- 双引号、单引号、转义引号和反斜杠；
- `-probe-arg "-subprobe h2 -subprobe-arg --path=/h2"`；
- 带空格的 subprobe 参数；
- 未闭合引号：确定报错，不挂起；
- HTTP header value 中的嵌套引号；
- 含 `=`、`:`、`[`、`]` 的 value；
- Windows/Git Bash 路径转换是 shell 问题，不是 parser 行为。

### 模块集成

四类注册表各选代表模块：

- probe：`http`、`ssh`、`h2`、`jarm`；
- scan：`zbanner`、`udp`、`tcp-state`；
- output：`ndjson`、`csv`；
- generate：`blackrock`、`ip-list`。

确认解析错误在扫描开始前报告并返回非零。

### 交互/恢复

- `set key = value`、`set-scan`、`set-probe`；
- 畸形 `recover.conf`；
- 恢复配置中的未知/缺失键；
- 交互式 help 不修改配置。

## 测试框架设计

新增 `tests/config/test.sh`，必要时加小型 C helper：

1. 用隔离的 `XTATE_BIN` 构建。
2. 子进程带 timeout，捕获 stdout/stderr/rc。
3. 非法输入断言精确错误文本。
4. 纯函数（`conf_parse_int`、`conf_parse_bool`、splitter）用
   `--selftest` 风格 unit helper，不必每个 case 都 fork。
5. 对危险 exit 路径（size 后缀）先改成返回错误，再加测试。
6. parser 测试不发起真实扫描；只用 `--list-*`/`--help-*` 和模块帮助路径。

## 验收

- parser 测试在 Linux CI 运行，不需要网络/root。
- 每个非法形式非零退出并给出明确消息。
- 缺 value 时没有越界读；setter 中的 `exit()` 不能处于未测试状态。
- 嵌套模块参数至少有一个成功和一个失败 case。
- 改 parser 语义前先有现有 CLI 行为特征测试。

## 优先级

P2/P3。应放在大型 HTTP 探针重写或更多嵌套 subprobe 参数之前，因为它们依赖同一
套 parser。
