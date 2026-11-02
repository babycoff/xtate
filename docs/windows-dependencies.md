# Windows optional dependencies

**English** · [中文](zh-CN/windows-dependencies.md)

Xtate builds and runs without these libraries. They only add optional modules:

| Dependency | Enables | Required? |
|:---|:---|:---|
| OpenSSL | `tls-hello`, `tls-state`, JARM-related probes | optional |
| PCRE2 | `recog`, `nmap` and other regex-based probes | optional |
| LibXml2 | Recog XML parsing | optional |
| libbson + libmongoc | `bson` / `mongodb` output | optional |

On Windows, missing dependencies simply remove the corresponding modules; the
core scanner and `tcp-syn`/`zbanner` still build. `--version` shows `(null)` for
each missing optional library.

## Recommended: Scoop + vcpkg (MSVC / ClangCL)

```powershell
scoop install vcpkg
# Scoop sets VCPKG_ROOT for new shells.
vcpkg install pcre2 libxml2 mongo-c-driver --triplet x64-windows
```

`scripts\build-windows.ps1` automatically:

1. reads `VCPKG_ROOT` (current shell or the user environment);
2. finds `scripts\buildsystems\vcpkg.cmake`;
3. passes `CMAKE_TOOLCHAIN_FILE` to **MSVC** and **ClangCL**;
4. copies vcpkg's app-local runtime DLLs into the project `bin\`.

A full MSVC build then reports PCRE2, LibXml2, libbson and libmongoc in
`xtate --version`.

If you invoke CMake manually, pass the toolchain yourself:

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
```

## MinGW

The `x64-windows` vcpkg packages are **MSVC ABI** and cannot be linked by MinGW.
Do not point MinGW at them.

Two options:

### A. MSYS2 packages (recommended for MinGW)

From an MSYS2 MINGW64 shell:

```bash
pacman -S mingw-w64-x86_64-pcre2 \
  mingw-w64-x86_64-libxml2 \
  mingw-w64-x86_64-mongo-c-driver \
  mingw-w64-x86_64-openssl
```

Build with the MSYS2 MinGW compiler; CMake finds the libraries under
`/mingw64`.

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

Use `x64-mingw-dynamic` if you prefer DLLs. Some vcpkg ports expect
prefix-named compilers (`x86_64-w64-mingw32-gcc`), so a plain Scoop `gcc.exe`
may need aliases or MSYS2. `scripts\build-windows.ps1` does **not** auto-attach
vcpkg to MinGW yet; the automatic path covers MSVC/ClangCL only.

## Expected CMake messages

- A found-but-incomplete PCRE2 from Conda/Miniconda:
  `missing: PCRE2_INCLUDE_DIR 8BIT` — the Conda CMake config is incomplete; it
  is not an Xtate failure. Use vcpkg or MSYS2 instead.
- `Could NOT find LibXml2`, `bson-1.0`, `mongoc-1.0` — optional libraries are
  absent; install with vcpkg/MSYS2 if you need those modules.

## Cleaning

`scripts\clean-windows.ps1` removes project build trees, `bin\xtate*.exe` and
runtime DLLs. It does **not** uninstall vcpkg packages or delete the vcpkg cache.
