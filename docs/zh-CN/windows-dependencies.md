# Windows 可选依赖

[English](../windows-dependencies.md) · **中文**

没有这些库 Xtate 也能构建和运行；它们只增加可选模块：

| 依赖 | 解锁 | 是否必需 |
|:---|:---|:---|
| OpenSSL | `tls-hello`、`tls-state`、JARM 相关探测 | 可选 |
| PCRE2 | `recog`、`nmap` 等正则类探测 | 可选 |
| LibXml2 | Recog XML 解析 | 可选 |
| libbson + libmongoc | `bson` / `mongodb` 输出 | 可选 |

Windows 上缺少依赖只会移除对应模块；核心扫描器和 `tcp-syn`/`zbanner` 仍可构建。
`--version` 中每个缺失的可选库显示 `(null)`。

## 推荐：Scoop + vcpkg（MSVC / ClangCL）

```powershell
scoop install vcpkg
# Scoop 会为新 shell 设置 VCPKG_ROOT
vcpkg install pcre2 libxml2 mongo-c-driver --triplet x64-windows
```

`scripts\build-windows.ps1` 会自动：

1. 读取 `VCPKG_ROOT`（当前 shell 或用户环境变量）；
2. 找到 `scripts\buildsystems\vcpkg.cmake`；
3. 给 **MSVC** 和 **ClangCL** 传 `CMAKE_TOOLCHAIN_FILE`；
4. 把 vcpkg 的运行时 DLL 复制到项目 `bin\`。

完整 MSVC 构建的 `xtate --version` 会显示 PCRE2、LibXml2、libbson、libmongoc。

手动运行 CMake 时需要自己传：

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
```

## MinGW

vcpkg 的 `x64-windows` 包是 **MSVC ABI**，MinGW 不能链接。不要让 MinGW 使用它们。

两种方案：

### A. MSYS2 包（MinGW 更推荐）

在 MSYS2 MINGW64 shell 中：

```bash
pacman -S mingw-w64-x86_64-pcre2 \
  mingw-w64-x86_64-libxml2 \
  mingw-w64-x86_64-mongo-c-driver \
  mingw-w64-x86_64-openssl
```

使用 MSYS2 的 MinGW 编译器构建；CMake 会在 `/mingw64` 下找到这些库。

### B. vcpkg MinGW triplet

```powershell
vcpkg install pcre2:x64-mingw-static `
  libxml2:x64-mingw-static `
  mongo-c-driver:x64-mingw-static `
  openssl:x64-mingw-static
```

```powershell
cmake -S . -B build-mingw -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER=gcc `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-mingw-static
```

需要 DLL 时用 `x64-mingw-dynamic`。部分 vcpkg port 期望带前缀的编译器
（如 `x86_64-w64-mingw32-gcc`），普通 Scoop `gcc.exe` 可能需要别名或改用 MSYS2。
`scripts\build-windows.ps1` 目前不会自动给 MinGW 挂 vcpkg；自动路径只覆盖 MSVC/ClangCL。

## 预期 CMake 提示

- Conda/Miniconda 里找到但不完整的 PCRE2：
  `missing: PCRE2_INCLUDE_DIR 8BIT` —— 是 Conda 的 CMake 配置不完整，不是 Xtate 构建失败；
  请改用 vcpkg 或 MSYS2。
- `Could NOT find LibXml2`、`bson-1.0`、`mongoc-1.0` —— 可选库缺失；需要对应模块时安装。

## 清理

`scripts\clean-windows.ps1` 清理项目构建目录、`bin\xtate*.exe` 和运行库 DLL；
**不会**卸载 vcpkg 包或删除 vcpkg 缓存。
