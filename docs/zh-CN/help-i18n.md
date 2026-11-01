# 中文帮助与 i18n 框架

[English](../help-i18n.md) · **中文**

Xtate 提供一个小型、零依赖的本地化层，只针对**人类可读的帮助文本**。它不是“整个程序的中文版”：命令行参数名、模块名、结果值和机器可读输出保持英文，避免脚本和输出 schema 随界面语言变化。

## 用法

```bash
xtate --lang zh --help
xtate --lang zh --help-scan tcp-syn
xtate --lang zh --usage
xtate --lang zh --intro
xtate --lang zh --list-scan
xtate --lang en --help
```

也支持环境变量：

```bash
XTATE_LANG=zh ./xtate --usage
```

`--lang` / `--language` 接受 `en`、`english`、`zh`、`zh-CN`、`zh_CN`、`cn`、`chinese`。非法值会作为命令行错误处理，而不是静默回退到英文，避免拼写错误被误认为成功。默认是 `en`。

## 设计

- **英文源字符串是规范 key。** `i18n_tr()` 在 `src/util-misc/i18n.c` 中精确查找；没有条目就返回英文原文。
- **翻译不会错误漂移到别的字符串。** 帮助文本不做模糊匹配；英文句子改了但 catalog 未更新时，自动回退英文。
- **只翻译人类帮助文本。** 参数名、模块名、`classification`/`reason` 值、JSON/CSV 字段名和扫描结果不随语言变化。
- **UTF-8 感知换行。** `xprint()` 解码 UTF-8，CJK/全角字符按两个终端列计算，并避免行首出现 `。`、`，`、`）`、`！` 等常见收尾标点。
- **Windows 控制台。** Windows 下选择 `zh-CN` 时切换到 UTF-8 输出代码页；MSVC/clang-cl 使用 `/utf-8` 统一源字符集和执行字符集。Xtate 会保存原代码页并在退出时恢复，避免把调用方的控制台留在被修改状态。

catalog 是**故意不完整**的：未翻译的参数/模块描述仍是英文且可正常使用。这是增量翻译框架，不是“全部字符串已翻译”的声明。

## 当前覆盖

已翻译：

- 欢迎语、程序描述、作者/GitHub/联系方式；
- 用法标题和常见示例说明；
- 全局帮助的章节标题；
- 模块帮助标签（名称、探测类型、描述等）；
- 列表/搜索标题；
- `--lang` 参数本身。

回退英文：

- 大部分全局参数和模块参数描述；
- 模块描述和简短描述；
- 错误消息和日志。

## 添加翻译

在 `src/util-misc/i18n.c` 的 `i18n_catalog[]` 加一条：

```c
{"Set the language of human-facing help text: en or zh-CN. Untranslated strings fall back to English.",
 "设置人类可读帮助文本的语言：en 或 zh-CN。未翻译的字符串回退到英文。"},
```

key 必须与英文源字符串**完全一致**，包括行尾 `\n`。占位符（`%s`、`%u`、`%d`）顺序保持一致；不要翻译参数名或结果值。

修改帮助代码后重新构建并检查两种语言：

```bash
./build/xtate --lang en --help
./build/xtate --lang zh --help
./build/xtate --lang zh --help-scan tcp-syn
./build/xtate --lang zh --usage
./build/xtate --lang nope --version  # 必须失败

# 仓库内置确定性检查
XTATE_BIN=$PWD/build/xtate bash tests/i18n/test.sh
```

Windows 检查请在能显示 UTF-8 的控制台进行；程序会自行设置代码页，但终端字体仍需包含中文字形。

## 限制

- 不自动检测系统语言；使用 `--lang` 或 `XTATE_LANG`。
- 暂不支持从右到左语言或复数规则。
- 输出模块和状态栏不翻译；它们属于机器/运维接口。
- catalog 允许不完整；缺少条目是安全的英文回退，不是错误。
