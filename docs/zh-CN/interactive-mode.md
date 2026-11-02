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
printf 'set rate = 1000\nset-scan tcp-syn\nset-probe null\nquit\n' |
  xtate -interactive
```

脚本模式下 `quit` 保存 `recover.conf`；`exit` 不保存直接退出。

## 命令

```text
help                 帮助概览和命令列表
set key = value      设置全局参数
set-scan <module>    选择扫描模块
set-probe <module>   选择探测模块
set-out <module>     选择输出模块
set-gen <module>     选择生成模块
list-param [过滤词]  列出全局参数，可按名称 token 过滤
list-scan/probe/out/gen  列出模块
echo / show          打印当前配置
show diff            只显示非默认配置
show all             显示包含默认值的全部配置
help <command>       查看单条交互命令帮助
help-param <name>    全局参数详细帮助
help-scan <module>   模块帮助
run                  执行当前配置的扫描
quit                 保存并退出
exit                 不保存直接退出
```

`<TAB>` 可补全命令、参数名和模块名；补全菜单同时显示简短说明。
`set <参数> = ...` 会补全已知值（`lang`、输出级别、布尔值）、模块名和文件路径
（包括 `conf-save`/`conf-read`）。选择模块后，`*-module-args` 会补全该模块的
`--选项`。

## 历史

TTY 模式自动加载/保存命令历史：

- Linux/macOS：`$HOME/.xtate_history`
- Windows：`%APPDATA%\xtate_history`

非 TTY 模式不写历史。

## 语言

交互帮助跟随全局语言设置：

```bash
xtate --lang zh -interactive
```

命令名和参数名仍是稳定的英文标识；描述和提示会翻译。

## 当前限制

- `run` 为前台执行：扫描停止后回到提示符。
- Windows TTY 扫描结束后不会自动重启；需要手动再次启动。Linux 会用
  `recover.conf` 重新执行。
- 补全覆盖命令/模块/参数名、常见值和文件路径；模块参数值的补全仍有限。
- `list-param <过滤词>` 按完整名称 token 匹配，不做任意子串匹配。
- 非 TTY 模式只去掉终端 UI，不改变扫描本身对目标、权限和
  libpcap/Npcap 的要求。
