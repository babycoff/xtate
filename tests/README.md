# Tests

The project-wide policy and matrix live in
[docs/testing.md](../docs/testing.md) / [中文](../docs/zh-CN/testing.md).

| Suite | Command | Notes |
|:---|:---|:---|
| header self-containment | `bash tests/include/check_headers.sh` | every header compiles alone |
| built-in | `xtate --selftest` | every build |
| i18n | `XTATE_BIN=./bin/xtate bash tests/i18n/test.sh` | help coverage |
| interactive | `XTATE_BIN=./bin/xtate bash tests/interactive/test.sh` | non-TTY script mode |
| PTY | `XTATE_BIN=./bin/xtate bash tests/interactive/tty.sh` | Linux; needs `script` |
| platform matrix | `bash tests/platform/matrix.sh` | Debian 10 + Alpine musl; `XTATE_CN_MIRROR=1` opt-in |
| large batch | `tests/large-batch/` | see its README/scripts |

Set `XTATE_BIN` to the exact binary under test. On Windows use Git Bash and
`bin/xtate.exe`; the PTY suite skips without util-linux `script`.
