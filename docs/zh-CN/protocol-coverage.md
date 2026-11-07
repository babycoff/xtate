# 协议覆盖计划

**中文** · [English](../protocol-coverage.md)

这是后续计划，不承诺实现所有协议。参考清单来自 zgrab2 模块表
（<https://github.com/zmap/zgrab2>）。Xtate 把 zgrab2 作为行为和测试参考，
不复制代码，也不承诺输出兼容。

## Xtate 当前覆盖

| 协议 | 状态 | 说明 |
|:---|:---|:---|
| HTTP | `http`、`http-state` | HTTP/1 冻结在结构化响应解析阶段。 |
| JARM | `jarm` | Salesforce 1.0、官方实现对比、`--first-probe`。 |
| SSH | `ssh` | banner/software/KEXINIT 列表；真实 KEX 交换待做。 |
| TLS | `tls-state`、`tls-hello` | 证书/细节、ALPN、SNI、JARM；有 STARTTLS 适配。 |
| SMTP | 仅 STARTTLS | `tls-state --starttls smtp`；还没有完整 SMTP 命令探针。 |
| IMAP | 仅 STARTTLS | `tls-state --starttls imap`；还没有完整 IMAP 探针。 |
| POP3 | 仅 STARTTLS | `tls-state --starttls pop3`；还没有完整 POP3 探针。 |
| FTP | 仅 STARTTLS | `tls-state --starttls ftp`；还没有完整 FTP 探针。 |
| MongoDB | 仅输出模块 | `mongodb` 输出不是 MongoDB 握手探针。 |
| Banner | `null`/`hello` | 通用抓取，不是协议感知。 |
| 其它 | 未实现 | 见下表。 |

## zgrab2 参考矩阵

**Tier 1**：单请求/短交互，风险低，优先做。
**Tier 2**：有状态/多步或二进制握手。
**Tier 3**：OT/工业协议，解析和安全评审成本最高。

| 协议 | zgrab2 | Xtate 状态 | 计划层级 | 引擎 |
|:---|:---:|:---|:---:|:---|
| AMQP | 有 | 未实现 | 2 | state |
| BACnet | 有 | 未实现 | 3 | UDP/state |
| Banner | 有 | 仅通用 | 1 | tcp/udp |
| DNP3 | 有 | 未实现 | 3 | state |
| Fox | 有 | 未实现 | 3 | state |
| FTP | 有 | 仅 STARTTLS | 2 | state |
| HTTP | 有 | 部分/冻结 | - | tcp/state |
| IMAP | 有 | 仅 STARTTLS | 2 | state |
| IPP | 有 | 未实现 | 2 | state |
| JARM | 有 | 完成 | - | tcp slots |
| ManageSieve | 有 | 未实现 | 2 | state |
| Memcached | 有 | 未实现 | 1 | tcp |
| Modbus | 有 | 未实现 | 3 | state |
| MongoDB | 有 | 仅输出 | 2 | state |
| MQTT | 有 | 未实现 | 1 | tcp/state |
| MSSQL | 有 | 未实现 | 2 | state |
| MySQL | 有 | 未实现 | 2 | state |
| NTP | 有 | 未实现 | 1 | UDP |
| Oracle | 有 | 未实现 | 2 | state |
| POP3 | 有 | 仅 STARTTLS | 2 | state |
| PostgreSQL | 有 | 未实现 | 2 | state |
| PPTP | 有 | 未实现 | 2 | state |
| Redis | 有 | 未实现 | 1 | tcp |
| Siemens S7 | 有 | 未实现 | 3 | state |
| SMB | 有 | 未实现 | 2 | state |
| SMTP | 有 | 仅 STARTTLS | 2 | state |
| SOCKS5 | 有 | 未实现 | 1 | tcp |
| SSH | 有 | 部分 | 2 | state |
| Telnet | 有 | 未实现 | 1 | tcp |
| TLS | 有 | 完成/部分 | - | state/tcp |

## 实现规则

- 探针输出**结构化字段**，不只是 banner：版本、协商方法/算法、服务身份和
  有界错误原因。
- 单包协议用 `tcp`/`udp`；多步握手用 `tcp-state` 上的 `state` 探针。不要给
  ZBanner 增加 per-target 状态。
- 隐式 TLS 和四种 STARTTLS 复用现有 TLS 层。
- 所有 payload 有界；禁止无界读取、正则回溯和解压。
- 可选协议库保持可选，不改变默认构建。
- 每个新探针都有本地确定性 fake server 和 lab case；公网目标不是测试夹具。

## 建议批次

### Batch A——高价值、低复杂度

Redis、Memcached、MQTT、Telnet、SOCKS5、NTP，以及协议感知 banner。
大多只需要一次请求/响应加小型结构化解析器。

### Batch B——数据库与邮件握手

MySQL、PostgreSQL、MSSQL、MongoDB、SMTP、IMAP、POP3、FTP、ManageSieve。
需要状态化读取、多行解析、TLS/STARTTLS 组合，并默认不进行认证尝试。

### Batch C——企业/文件服务

AMQP、IPP、SMB、Oracle、PPTP。二进制结构和协商路径更大，必须有测试夹具和
有界解析器。

### Batch D——OT/工业

Modbus、DNP3、BACnet、Siemens S7、Fox。作为独立安全评审工作流；默认绝不
发送写/控制请求。

## 非目标

- zgrab2 输出兼容；
- 未做许可证审查就复制 zgrab2 代码；
- 凭据猜测、认证绕过或默认密码喷洒；
- 在扫描器热路径做无界协议 fuzz。

## 单批验收

- 每个协议至少一个本地夹具；
- 成功和畸形响应都有确定性用例；
- 中英文文档列出字段；
- `--help-probe` 说明请求内容和安全边界；
- 缺少可选依赖不影响 Linux/Windows 默认构建。
