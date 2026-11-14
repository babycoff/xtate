# 表面同步检查清单

Xtate 通过多个相互独立的表面暴露同一组能力：CLI 及其帮助、MCP 服务器、浏览器控制台、Docker 镜像，以及中英文文档。任何会到达用户的改动，都必须同步到所有描述它的表面。本页是简短、可审查的清单；`tests/release/test_surface_consistency.py` 会自动检查其中可机械验证的部分。

提交 PR 前运行：

```bash
python3 tests/release/test_surface_consistency.py --binary ./bin/xtate
```

该测试只读。它比较已构建的二进制和仓库文本，因此必须先构建。它已接入 Linux 集成和 Windows CI。

## 新增全局参数

| 表面 | 需要更新 |
|---|---|
| 解析器 | `src/xconf.c` 的 `config_parameters[]`；有状态参数还需 `SET_*`/echo 处理。 |
| 英文帮助 | 同一条目中的长、短描述。只有代码默认值确实如此时才写默认值。 |
| 中文帮助 | `src/util-misc/i18n.c` 的 `i18n_global_help[]`（否则中文回退英文）。 |
| Usage 示例 | 只有当参数改变常见工作流时才加 `--usage` 示例。 |
| GUI | 安全的全局控制可通过 `/api/options` 暴露；否则保持 CLI/MCP 专用并在文档说明。 |
| MCP | 只有代理确实需要时才加入 `src/util-scan/mcp-server.c` 的扁平 `start_scan` schema；CLI 始终是完整表面。 |
| 文档 | `docs/help-i18n.md`、`docs/` 下相关页面及中文对应页。 |
| 测试 | 至少覆盖解析/默认值；若帮助数量变化，更新表面测试预期。 |

优先一个参数，不要制造多个名字。别名放入 `alias` 数组，不能产生第二条帮助条目。

## 新增模块（scan、probe、output 或 generate）

| 表面 | 需要更新 |
|---|---|
| 注册 | 对应 `src/*-modules/` 文件中的模块定义与注册。 |
| 帮助 | 模块描述和每个参数描述；用 `--help-scan|probe|out|gen <name>` 实测。 |
| 数量 | `README.md`、`docs/modules.md` 及所有引用数量的页面中的 Windows 与完整 Linux 数量。 |
| MCP | `list_modules`、`describe_probe`、`start_scan` 从注册表读取；不要另建硬编码列表。只有工具契约变化时才改 `docs/mcp-server.md`。 |
| GUI | 模块目录由 `/api/modules` 提供；scan→probe 选项来自 `probe_type`，不得硬编码；`tls-state` 只接受 state 子探针。只有渲染契约变化时才改 `docs/gui.md`。 |
| Docker | Ubuntu 镜像从源码构建可选模块；若模块新增依赖，检查 `docker/ubuntu24-build/Dockerfile` 和能力输出。 |
| 测试 | 加入对应的 schema/module validator 预期和最小行为测试。 |

模块帮助是用户可见文本。编译通过不代表帮助正确，必须运行模块帮助并阅读。

## 版本变更

版本变更涉及的文件最多：

- `CMakeLists.txt`（`project(... VERSION ...)` 与 `XTATE_VERSION_SUFFIX`）。
- `src/version.h` 由 CMake 从 `src/version.h.in` 生成；正常构建不要手改。提交的陈旧副本会被表面门禁发现。
- `README.md`、`README.zh-CN.md` 的徽章和“当前版本”文字。
- `docs/README.md`、`docs/zh-CN/README.md`、`docs/getting-started.md`、`docs/zh-CN/getting-started.md`、`docs/known-limitations.md` 及所有写“当前版本”的页面。
- `docs/release-notes/<version>.md` 和中文对应页。
- `BUILD-INFO` 由打包脚本生成，不要手改。

历史发布说明保留原版本号，升级当前版本时不要改写它们。

## 新增 GUI 路由或 MCP 工具

| 表面 | 需要更新 |
|---|---|
| 代码 | `src/util-scan/gui.c` 路由表或 `src/util-scan/mcp-server.c` 的 `tools_json`。 |
| 文档 | `docs/gui.md` 或 `docs/mcp-server.md`；中文对应页。 |
| 契约测试 | `tests/gui/test_gui.py` 或 `tests/mcp/test_mcp_contract.py`。 |
| 安全 | GUI 路由的环回/Host/token 检查；MCP 工具的授权与参数限制。 |

表面门禁比较路由名和工具名与文档是否一致，但不证明授权行为；授权由契约测试覆盖。

## 新增依赖或构建选项

- `CMakeLists.txt` 选项和 `NOT_FOUND_*` 回退。
- `README.md` 构建表、`docs/getting-started.md`、平台/依赖页面。
- `docker/ubuntu24-build/Dockerfile` 和能力输出。
- CI 构建矩阵：至少一个精简构建和一个完整构建。
- 依赖缺失时构建仍必须成功。

## 发布流程

1. 更新版本和发布说明。
2. 运行表面门禁、版本一致性测试，以及受影响平台的完整测试层级。
3. 构建 Windows 和 Linux 发布产物，记录 SHA256。
4. 在干净主机上验证归档（`--version`、`--selftest`）。
5. 只发布 RC；正式版等待维护者确认。
6. 发布后重新下载资产并核对记录的哈希。
