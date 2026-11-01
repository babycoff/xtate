# Security policy

[中文](#中文)

Xtate is a dual-use network scanner. Its security policy covers the **Xtate
codebase**, not the systems you choose to scan.

## Supported versions

Security fixes are applied to the current **2.20.x** release line. Older
releases may not receive fixes; please reproduce on the latest release before
reporting.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Preferred channels:

1. GitHub private vulnerability reporting / Security Advisories:
   <https://github.com/babycoff/xtate/security/advisories/new>
2. If private reporting is unavailable, email **shineccy@aliyun.com** with a
   subject beginning `[xtate security]`.

Please include:

- affected version, OS/architecture, compiler and build configuration;
- the feature or component involved (scanner, probe, output module, pcap
  adapter, parser, build system);
- a minimal local reproduction, or a sanitized pcap/config if one is essential;
- observed impact: crash, memory corruption, out-of-bounds read/write, denial of
  service, output corruption, data loss, credential exposure, etc.;
- any known mitigations.

Do **not** include third-party scan data, real customer traffic, private keys,
tokens or credentials. Sanitize IP addresses and payloads before sharing.

## Scope

In scope:

- memory-safety bugs in packet parsing, pcap handling, protocol parsers, TLS/HTTP
  probes, BSON/JSON output and module lifecycle;
- remotely triggerable crashes or denial of service in Xtate itself;
- output data loss or silent corruption that a user cannot detect;
- privilege, capability or file-permission issues in the scanner;
- supply-chain or build-system issues in this repository.

Out of scope:

- scanning third-party networks, detection by remote IDS, or the legality of a
  particular scan;
- false positives/negatives inherent in active measurement (for example a
  firewall dropping replies);
- vulnerabilities in target services that Xtate merely connects to;
- expected limitations documented in [docs/known-limitations.md](docs/known-limitations.md);
- issues that require a malicious local administrator or a compromised host.

## Safe research expectations

Only test against systems you own or have explicit written permission to test.
Do not run destructive scans or exploit target services as part of a report. A
minimal loopback, VM or Docker lab reproduction is preferred; the maintainers
can often reproduce from a pcap replay.

We will make a good-faith effort to acknowledge a report, investigate it and
coordinate disclosure. There is no guaranteed response SLA. Please allow time
for a fix before public disclosure; credit can be given if desired.

## 中文

Xtate 是双用途网络扫描器。本安全策略覆盖 **Xtate 代码库本身**，不覆盖你选择扫描的目标系统。

### 支持版本

安全修复应用于当前 **2.20.x** 发布线。旧版本可能不再修复；报告前请先在最新版本复现。

### 报告漏洞

**不要为安全漏洞开公开 issue。**

首选渠道：

1. GitHub 私密漏洞报告 / Security Advisories：
   <https://github.com/babycoff/xtate/security/advisories/new>
2. 如果私密报告不可用，发邮件到 **shineccy@aliyun.com**，主题以 `[xtate security]` 开头。

请尽量包含：

- 受影响版本、操作系统/架构、编译器与构建配置；
- 涉及组件（扫描模块、探测模块、输出模块、pcap 适配器、解析器、构建系统）；
- 最小本地复现，或确有必要时提供脱敏 pcap/配置；
- 影响：崩溃、内存破坏、越界读写、拒绝服务、输出损坏、数据丢失、凭据泄露等；
- 已知缓解措施。

不要附带第三方扫描数据、真实客户流量、私钥、token 或凭据。分享前请脱敏 IP 和 payload。

### 范围

在范围内：

- 包解析、pcap 处理、协议解析器、TLS/HTTP 探测、BSON/JSON 输出、模块生命周期中的内存安全问题；
- Xtate 自身可被远程触发的崩溃或拒绝服务；
- 用户无法察觉的输出数据丢失或静默损坏；
- 扫描器的权限、capability 或文件权限问题；
- 本仓库的供应链或构建系统问题。

不在范围内：

- 扫描第三方网络、被远程 IDS 检测，或某次扫描的合法性；
- 主动测量固有的误报/漏报（例如防火墙丢包）；
- Xtate 只是连接的目标服务自身漏洞；
- 已在 `docs/known-limitations.md` 中记录的限制；
- 需要恶意本地管理员或已失陷主机才能触发的问题。

### 安全研究预期

只测试你拥有或获得明确书面授权的系统。不要在报告中执行破坏性扫描或利用目标服务。优先使用最小的 loopback、虚拟机或 Docker 实验环境；维护者通常可以用 pcap 回放复现。

我们会善意地确认、调查并协调披露，但不承诺固定响应时限。公开披露前请给修复留出时间；如愿意可以署名致谢。
