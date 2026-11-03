# Windows quick start (beginner)

**English** · [中文](zh-CN/windows-quickstart.md)

This guide is for a **first local try** on Windows 10/11 x64. It builds Xtate
from source, because a release may not include a pre-built Windows executable.
It deliberately uses only the core scanner: `tcp-syn` and the basic TCP probes
build without optional libraries. TLS/PCRE2/XML/MongoDB are optional and are
covered in [Windows optional dependencies](./windows-dependencies.md).

> Scans need Administrator privileges and the Npcap driver. Building and
> `--selftest` do not need Npcap.

## 1. What you need

| Item | Why | Needed for first build? |
|:---|:---|:---|
| Windows 10/11 x64 | supported platform | yes |
| PowerShell | build and run commands | yes |
| Git for Windows | clone the source | yes |
| Visual Studio 2022 Build Tools with **Desktop development with C++** | MSVC compiler, Windows SDK | yes |
| CMake | configure the project | yes |
| [Npcap](https://npcap.com/#download) | packet capture/injection driver | only for actual scans |
| Ninja | faster builds, required by ClangCL path | optional |
| OpenSSL / PCRE2 / LibXml2 / MongoDB | optional modules only | no |

Do **not** download Npcap from third-party mirrors. Use the official installer.

## 2. Install the prerequisites

Open a normal PowerShell window (not Administrator yet) and run:

```powershell
winget install --id Git.Git -e
winget install --id Kitware.CMake -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e `
  --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Ninja-build.Ninja -e
```

If `winget` is not available, install the same applications manually:

- Git: <https://git-scm.com/download/win>
- CMake: <https://cmake.org/download/>
- Visual Studio Build Tools / Visual Studio Community:
  <https://visualstudio.microsoft.com/downloads/>
  - Select the **Desktop development with C++** workload.
  - Include the Windows 10/11 SDK and MSVC compiler.

Close and reopen PowerShell after installation so `git`, `cmake` and the
compiler are found.

Verify:

```powershell
git --version
cmake --version
```

If CMake or `git` is still not found, reopen the terminal or check that the
installer added the program to `PATH`.

### Install Npcap

Download the official installer:

<https://npcap.com/#download>

During setup:

1. Allow the installer to run as Administrator.
2. **Check “Install Npcap in WinPcap API-compatible Mode”.**
   Xtate loads `wpcap.dll` at runtime; the compatibility mode puts it where
   Windows can find it after the build.
3. Accept the default service/driver options unless you have a reason not to.
4. Reboot if the installer asks.

Check the service after installation:

```powershell
Get-Service *npcap*
```

The exact service display name can vary, but the Npcap driver should be
present and running.

> You do **not** need the Npcap SDK to build Xtate: the source loads the pcap
> API dynamically. The Npcap runtime/driver is needed only for actual scans.

## 3. Clone and build

In PowerShell:

```powershell
git clone https://github.com/babycoff/xtate.git
cd xtate
```

Build the recommended MSVC Release binary:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1 `
  -Toolchain msvc -Config Release -Yes
```

What the script does:

- copies the source to an ASCII staging path below
  `%LOCALAPPDATA%\xtate-build`;
- finds Visual Studio, configures CMake and builds;
- writes the main binary to `bin\xtate.exe`;
- keeps per-toolchain copies in `bin\` and `artifacts\`.

If PowerShell refuses to run the script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

That changes the policy only for the current window.

### Verify the build

No Administrator rights and no Npcap are needed for these checks:

```powershell
.\bin\xtate.exe --version
.\bin\xtate.exe --selftest
```

A successful selftest ends with:

```text
Regression test: success!
```

If you want a Debug binary:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1 `
  -Toolchain msvc -Config Debug -Yes
.\bin\xtate_debug.exe --selftest
```

## 4. Run your first scan

Open **Terminal (Admin)** / **PowerShell as Administrator**:

- Right-click the Start button → **Terminal (Admin)**, or
- right-click PowerShell → **Run as administrator**.

Change to the repository directory:

```powershell
cd C:\path\to\xtate
```

List adapters:

```powershell
.\bin\xtate.exe --list-if
```

Pick the adapter connected to your test network, then scan a **private lab
subnet** you own or are authorized to test:

```powershell
.\bin\xtate.exe -if "Ethernet" -ip 192.168.1.0/24 -p 80 `
  -scan tcp-syn -rate 1000 -show failed
```

Notes:

- Quote an adapter name that contains spaces.
- `-show failed` shows closed ports; without it only successes are visible.
- Start with a low rate such as `-rate 1000`.
- Do **not** scan public IP ranges or networks without permission.
- On Windows, `tcp-syn` can optionally close half-open connections with
  `-scan-arg "--send-rst"`.

Expected output includes rows such as:

```text
open  192.168.1.10:80
closed 192.168.1.11:80
```

## 5. Optional features

The core build is enough for `tcp-syn` and basic TCP probing. Optional modules:

| Feature | Dependency | How to add it |
|:---|:---|:---|
| TLS probes (`tls-hello`, `tls-state`) | OpenSSL | see [Windows optional dependencies](./windows-dependencies.md) |
| regex/Recog probes | PCRE2 | same |
| XML/Recog parsing | LibXml2 | same |
| BSON/MongoDB output | libbson + libmongoc | same |

`--version` prints `(null)` for optional libraries that are not present. That is
not a broken build.

`zbanner` and `tcp-state` need kernel RST suppression on Linux; Windows uses
Npcap and behaves differently. For a first try, stick to `tcp-syn` and a
private target. Read [ZBanner](./zbanner.md) and [HLTCP](./hltcp.md) before
using those engines on Windows.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|:---|:---|:---|
| `Visual Studio not found` / MSVC missing | C++ workload not installed | rerun the Visual Studio Installer and add **Desktop development with C++** |
| `cmake` or `git` not recognized | terminal was open before installation | close and reopen PowerShell |
| `wpcap.dll` not found / no adapter | Npcap missing or not in WinPcap-compatible mode | reinstall Npcap and enable compatibility mode |
| `--list-if` shows no adapter | not elevated, driver not running, or adapter disabled | run as Administrator; check `Get-Service *npcap*`; enable the adapter |
| `Access is denied` / no packets | not Administrator | run Terminal as Administrator |
| Build script refuses due to path | non-ASCII path with MinGW | use the MSVC build first; the script already stages to an ASCII path for the build |
| Windows Defender/Firewall prompt | Npcap driver/send permission | allow the driver/terminal for the lab network |
| Scan returns no replies | target/firewall/route issue | test with `-ip` of a known host first; see [Troubleshooting](./troubleshooting.md) |

## 7. Clean up

Remove project build trees and binaries:

```powershell
pwsh -File .\scripts\clean-windows.ps1
```

Remove the staging directory too:

```powershell
pwsh -File .\scripts\clean-windows.ps1 -IncludeStage
```

Uninstall Npcap from **Settings → Apps** if you no longer need packet capture.

## 8. What Windows CI covers

The repository's Windows CI builds with **MSVC, ClangCL, and MinGW** using both **UCRT64 and legacy MINGW64** MSYS2 environments, runs
`--version`, `--selftest`, and the parser/i18n tests. It does **not** install the
Npcap driver and does **not** run live packet tests. A local Npcap installation
and an Administrator shell are still required for a real scan.
