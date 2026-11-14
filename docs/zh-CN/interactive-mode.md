# 交互式模式

[English](../interactive-mode.md) · **中文**

启动：

```bash
xtate -interactive
# 或
xtate -interact
```

## TTY 与脚本模式

两种模式使用同一套命令解析。

- **TTY**：显示 banner、行编辑、历史和 `<TAB>` 补全。
- **非 TTY**（管道/文件输入）：不显示 banner、不启用 ANSI、不启用行编辑、不自动重启。适合脚本和 CI，输出确定。

示例：

```bash
printf 'set rate = 100\nset-scan tcp-syn\nset-probe null\nquit\n' |
  xtate -interactive
```

脚本模式下 `quit` 保存 `recover.conf`；`exit` 不保存直接退出。

## 命令

```text
help                 概览和命令列表
run                  执行已配置的扫描
check                校验当前配置，不发送报文
set key = value      设置全局参数
set-scan <module>    选择扫描模块
set-probe <module>   选择探测模块
set-subprobe <module> 选择内层探测（仅适用于支持子探针的探测）
set-subprobe-arg <args> 设置内层探测参数（整体作为一个单引号字符串）
history clear        删除已保存的命令历史
set-out <module>     选择输出模块
set-gen <module>     选择生成模块
echo                 打印当前配置
show                 echo 的别名
show diff            只显示非默认配置
show all             包含默认值（等同于 echo-all）
echo-all             打印包含默认值的全部配置
clear                重置为默认配置（保留 `seed`）
update-seed          用新的随机值替换全局 seed
unset-scan           取消扫描模块及其参数
unset-probe          取消探测模块及其参数
unset-out            取消输出模块及其参数
unset-gen            取消生成模块及其参数
list-param [filter]  列出全局参数，可按名称 token 过滤
list-scan            列出扫描模块
list-probe           列出探测模块
list-out             列出输出模块
list-gen             列出生成模块
help <command>       查看单条交互命令帮助
help-param <name>    全局参数详细帮助
help-scan <module>   扫描模块帮助
help-probe <module>  探测模块帮助
help-out <module>    输出模块帮助
help-gen <module>    生成模块帮助
search-param <text>  模糊搜索全局参数
search-module <text> 模糊搜索所有模块注册表
conf-save <file>     保存当前配置
conf-read <file>     读取配置文件
conf-recover         载入 `recover.conf`
version              打印 Xtate 版本
quit                 保存到 `recover.conf` 并退出
exit                 不保存直接退出
```

`<TAB>` 可补全命令、参数名和模块名；补全菜单同时显示简短说明。
`set <param> = ...` 会补全已知值（`lang`、输出级别、布尔值）、模块名和文件路径
（包括 `conf-save`/`conf-read`）。选择模块后，`*-module-args` 会补全该模块的
`--options`。

## 扫描/探测兼容性与 check

`set-scan` 会清除不兼容的探测并打印警告；`set-probe` 会拒绝当前扫描引擎无法承载的探测。这与 CLI/MCP 的校验一致，包括 `quic-state`/`tls-state` 和 `tcp-state`/`http3-state` 的限制。

运行 `check` 可在不发送报文的情况下校验当前模块、探测组合和速率，并打印简短配置摘要；目标和路由检查仍属于 CLI `--check` / GUI 预检。

## 子探针

`set-subprobe` 和 `set-subprobe-arg` 只在当前探测支持内层探测时有用（目前是 `tls-state`），其它情况会明确警告。内层探测必须是 state 类型；TCP/UDP 探测、`tls-state` 自身和 `http3-state` 都会被拒绝。参数值整体保存为一个单引号字符串，例如：

```text
set-scan tcp-state
set-probe tls-state
set-subprobe close-state
set-subprobe-arg --max-body=4096 --method=POST
```

等价于 `-probe-arg "-subprobe close-state -subprobe-arg '--max-body=4096 --method=POST'"`。

## 速率

`set rate = <数字>` 接受任意正浮点值，包括小数（`0.5` 表示两秒一个包）和每秒数百万包的速率。零、负值和非数字会被拒绝。交互模式没有 GUI 的速率上限。浏览器 GUI 的 1–10000 只是界面安全限制。

## 历史

TTY 模式自动加载/保存命令历史：

- Linux/macOS：`$HOME/.xtate_history`
- Windows：`%APPDATA%\xtate_history`

非 TTY 模式不写历史。行编辑最多保留最近 256 条；`history clear` 会删除已保存文件并清空内存中的历史。

## 语言

交互帮助跟随全局语言设置：

```bash
xtate --lang zh -interactive
```

命令名和参数名仍是稳定的英文标识；描述和提示会翻译。

## 当前限制

- `run` 为前台执行：扫描停止后回到提示符。
- Windows TTY 扫描结束后不支持自动重启。Xtate 会明确提示；请手动再次运行 `xtate -interactive`。Linux 会用 `recover.conf` 重新执行。
- 补全覆盖命令/模块/参数名、常见值和文件路径；模块参数值的补全仍有限。
- `list-param <filter>` 按完整名称 token 匹配，不做任意子串匹配。
- 非 TTY 模式只去掉终端 UI，不改变扫描本身对目标、权限和
  libpcap/Npcap 的要求。
- Windows 中文 TTY 输出只在交互期间临时切到 UTF-8 代码页，正常退出/Ctrl-C
  时恢复；重定向输出仍为 UTF-8。
