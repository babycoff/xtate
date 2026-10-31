# ZBanner：无状态 TCP banner

[English](../zbanner.md) · **中文**

ZBanner 能从真实服务拿到真实的 TCP 响应，**却不保留任何每目标连接状态**。连接由对端的 TCP 栈持有；Xtate 只持有一个密钥和一点算术。回包到达时，用包内字段重新算出这个密钥并比对——对得上，这个回包就是我们的。

正是这个差别让大规模 banner 抓取变得可负担。常规的 banner 抓取要为每个目标分配 TCB、定时器和重传队列；ZBanner 一样都不分配。它发出两个包、读回两个包，然后用一个 RST 关闭连接。

### 设计理念：状态在对端，事件在我们这边

ZBanner 有意定位为**无状态事件扫描器**，不是每目标连接跟踪器：

- 没有 TCB、没有每目标定时器、没有重传队列。SYN、SYN-ACK 或 banner 段丢失，该目标就没有结果；恢复方式是重跑（`--repeat` 或再扫一遍），而不是在扫描器内维护重试状态机。
- 去重表是一张有界的近似缓存，用于抑制重复和计数，不是可靠性机制。高扇出时 entry 会被淘汰，因此 `banner idx` 和 all-banner 的 limit/floor 都是近似值；`banner seqno` 才是精确的段字段。
- 结果是**事件流**（open、closed、ack、banner segment……），不是每目标一条记录。按目标聚合留给下游后处理；在扫描器里加 target map 会重新引入这个设计刻意避免的内存开销。
- 这些是取舍，不是缺失功能：目标部署保持内存有界，把可靠性和聚合交给操作者或后处理器。

## 思路

TCP 建立连接需要三样东西：客户端给出的初始序号、服务器对它的确认，以及客户端对服务器的确认。ZBanner 用由连接元组推出的 **SipHash cookie** 填第一个位置：

```
cookie = siphash24(entropy, ip_them, port_them, ip_me, port_me)   // low 32 bits
```

对于不知道 `entropy` 的路径外攻击者，这个 cookie 不可预测；而我们在之后的任何时刻，都能从同一元组的任意报文重新算出它。这就是全部的“状态”：`entropy` 是一个全局种子，元组在每个回包里都会带回来。

因为 cookie 就是我们的 ISN，服务器的 SYN-ACK 会确认 `cookie + 1`。当某个包自称是回包时，我们重算 cookie 并检查确认号字段。不需要查表，因为根本没有表。

## 交互序列

![ZBanner 序列：携带 SipHash cookie 的 SYN，确认 cookie + 1 的 SYN-ACK，携带探测载荷的 ACK，携带 banner 的 ACK，最后是 RST；没有 TCB，也没有超时表](../../screenshots/zbanner-sequence.svg)

1. **SYN**——`seq = cookie`，`ack = 0`。源端口是 `source_port_start + probe_slot`，于是探测槽位随端口号一起走，而不用占内存。
2. **SYN-ACK**——服务器确认 `cookie + 1`。只有当 `ackno == cookie + 1`、且目的端口落在我们的源端口区间内时，才接受这个包。
3. **ACK + 载荷**——`seq = cookie + 1`（服务器刚刚确认过的值），`ack = server_seq + 1`。探测载荷追加在这个 ACK 上。
4. **ACK + banner**——服务器确认我们的数据。它的 `ackno` 等于 `cookie + 1 + payload_len`，这既是一次存活检查，也是一次长度检查。载荷字节被交给探测模块。
5. **RST**——关闭连接。不需要清理任何东西，因为什么都没有分配。

### 首部字段，精确到值

| 报文 | `seq` | `ack` | 接受条件 |
|:---|:---|:---|:---|
| SYN（我方） | `cookie` | 0 | 无条件发送 |
| SYN-ACK（对方） | `server_seq` | `cookie + 1` | `ackno == cookie + 1` |
| ACK + 探测载荷（我方） | `cookie + 1` | `server_seq + 1` | 收到可接受的 SYN-ACK 后发送 |
| ACK + banner（对方） | `server_seq + 1` | `cookie + 1 + payload_len` | `ackno == cookie + payload_len + 1` |
| RST（我方） | banner 的 `ackno` | banner 的 `seq + 1` | 收到 banner 后发送 |

所有比较都按 32 位无符号进行，因此接近 `2^32 - 1` 的 cookie 也能正确回绕。

banner 的判定条件值得再讲一遍。我们从序号 `cookie + 1` 开始发了 `payload_len` 个字节，因此服务器期望的下一个字节是 `cookie + 1 + payload_len`，它的 `ackno` 正好就是这个值。于是这次校验一次性验证了三件事：这个包属于这条连接、服务器收到了我们的全部数据、以及我们认为发出的字节数与探测实际构造的字节数一致。

## 为什么载荷挂在第三个 ACK 上

TCP 的 ACK 允许携带数据。把 `ACK + 载荷` 放进同一个报文，意味着握手和请求只花一个包，也意味着连接一建立服务器就开始处理请求，不存在“先完成握手、再发数据”的往返。

代价在于：第三个 ACK 是在收到 SYN-ACK 之后由处理线程生成的，而不是由发送线程生成，所以探测载荷必须在那一刻可重建。探测模块暴露两个函数——`make_payload`（这里用它）和 `get_payload_length`（接收路径校验时用它），对同一目标两者必须返回相同的长度。若不一致，所有 banner 都会被静默丢弃，而不是被错误分类。

`--with-ack` 会在数据段之前插入一个裸 ACK，变成教科书式的三次握手，然后再发载荷，代价是每目标多一个包。它之所以存在，是因为有些服务器（模块文档也坦言这并未完全搞清楚）似乎只接受这种形状的连接，也因为它是 ZBanner 的早期形态；在现在的代码里，它是一个研究开关，而不是优化。

## 关闭，或者不关闭

首个数据段之后，默认行为是发 RST。由于没有 TCB，这个 RST 不是“清理”，而是告诉服务器会话结束的唯一手段。如果 RST 在路径上某处被过滤，服务器会保留半开或已建立的连接，并可能重传 banner——这就是慢速扫描看起来像目标在“话多”的原因。

`--no-rst` 抑制 RST，让服务器一直握着这条连接直到超时。它是研究开关：适合观察目标在 banner 之后的行为，不适合做普查。

`--all-banner` 是另一个方向：不在一个数据段后关闭，而是逐个确认到达的数据段（`ack = seqno_them + app_length`）并继续读。`--all-banner-limit` 限制段数，`--all-banner-floor` 抑制低于阈值的段的结果。`banner idx` 仍来自去重表的重复计数，只是近似值；`banner seqno` 是该段精确的 TCP 序号，是排序/去重 banner 数据的可靠字段。limit/floor 仍然使用近似 index；触发 limit 的那一段会标记 `truncated: 1`。

多段数据建议使用：

```bash
-scan-arg "--all-banner --all-banner-limit 8 --tcp-win 65535 --max-packet-len 65535 --snaplen 65535"
```

启动时如果 `--all-banner` 搭配过小的窗口、包长或 snaplen，或搭配 `Multi_AfterHandle` / `Multi_DynamicNext`，会给出警告。

## 用法

ZBanner 需要一个 TCP 类型的探测模块——能产生字节、也能解释响应的那种。模块自己的参数经 `--scan-arg` 传入，探测参数经 `--probe-arg` 传入。

```bash
# Linux: stop the kernel from resetting connections it does not know about
./firewall/add_rules.sh

# Grab a banner with an HTTP request
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http -show info

# A TLS ClientHello without a full handshake; ServerHello is parsed for fingerprints
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# Read every banner segment, not just the first
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80 -scan zbanner -probe http \
  -scan-arg '--all-banner --all-banner-limit 8' -show info

# A textbook handshake before the payload (research; one extra packet per target)
sudo ./bin/xtate -ip 10.0.0.0/24 -p 22 -scan zbanner -probe hello \
  -scan-arg '--with-ack'

./firewall/rm_rules.sh
```

`--show info` 通常是必须的：ZBanner 的结果标为 `info` 级，而 `info` 输出默认不显示。`-p` 接受 `80,443,8000-8100` 以及 `u:`/`s:`/`o:` 前缀，用于非 TCP 协议。

## 扫描之前：压制内核

ZBanner 发出的报文描述的是本机内核一无所知的连接。当 SYN-ACK 或 banner 到达一个内核认为已关闭的源端口时，内核会向目标回 RST——正好打断 ZBanner 想用的那条连接。扫描器无法在进程内部阻止这件事，必须在防火墙上处理：

```bash
./firewall/add_rules.sh   # drop outgoing RST and ICMP port-unreachable
./firewall/rm_rules.sh    # remove the rules afterwards
```

这些规则是全局的：安装期间，主机上**每一个**应用都会失去出向 RST，浏览器或 SSH 的异常连接无法被干净地复位。扫描结束时要移除规则。脚本只适用于 Linux。

Windows 上扫描器使用 Npcap。本地测试（Windows 11、Npcap loopback + WSL 目标）中，Windows 协议栈没有对 raw socket 的 SYN-ACK/ACK 组合发 RST，因此不需要全局 RST 辅助。但这不改变 Windows 的其它要求：Npcap、capture driver 的管理员权限、正确的 adapter 选择，且没有 PF_RING/`sendmmsg` 等价路径。ZBanner 和 [HLTCP](./hltcp.md) 仍需要可用的 capture/injection 路径。

## 解读结果

| `classification` | `reason` | 含义 |
|:---|:---|:---|
| `open` | `syn-ack` | 端口应答了 SYN；探测载荷已发出。 |
| `fake-open` | `zerowin` | 窗口为零的 SYN-ACK。常见于 SYN 代理或 accept 队列已满；不会发载荷。 |
| `closed` | `rst` | 端口用 RST 应答。 |
| `responsed` | `ack with data` | 探测模块未设置分类时的兜底值。 |

同一个目标可能产生多行：SYN-ACK 带来的 `open`、每个 banner 段一行，以及启用 `--record-ack` 时的 `acknowledged` 行。把这些行合并成每目标一条记录，是使用方的工作——若在 ZBanner 内部完成，就恰好需要它当初刻意避免的每目标状态。

## ZBanner 不是什么

| | masscan / zmap SYN 扫描 | ZBanner |
|:---|:---|:---|
| SYN 序号 | 随机，无法回验 | 带密钥的 cookie，收到即可验证 |
| 收到 SYN-ACK 时 | 接受、记录、RST | 验证、完成握手、发出探测 |
| 应用层数据 | 无——连接从未真正建立 | 挂在第三个 ACK 上 |
| 连接状态 | 无 | 无（由对端持有） |
| 结果 | 开放 / 关闭 | 开放 / 关闭，外加真实 banner 字节 |

与 [HLTCP](./hltcp.md) 的比较则是另一类问题。ZBanner 每个目标只问一个问题、只读第一个答案；HLTCP 则维持一段对话。ZBanner 能发 ClientHello 并解析明文 ServerHello，但它无法完成 TLS 1.3 握手、无法跟完多段证书链、也无法再发第二个请求。需要这些能力时，用 `-scan tcp-state`；需要普查时，两个引擎里只有 ZBanner 能在不建表的前提下扩展。

## 已知限制

- **没有每目标超时，也没有重传。** 丢掉一个 SYN 就少一条结果；丢掉一个 banner 段就少一段 banner。`--repeat-synack`、`--repeat-banner`、`--repeat-ack` 和 `--repeat-rst` 只是把重复到达的结果重新输出，没有任何机制会重发从未到达的包。
- **去重是近似的。** 它是一张按 `--dedup-win` 定容的四路桶表，采用随机淘汰。当某个地址段产生很高扇出时，表项会被挤掉，重复计数随之不可靠——`--all-banner` 的记账也会受牵连。
- **零窗口默认报成 `fake-open`。** accept 队列已满的真实服务同样会通告零窗口；这类目标会被分类为 `fake-open`，不会请求 banner。`-scan-arg "--probe-zerowin"` 是研究开关：仍然分类为 `fake-open`，但会继续发送探测载荷。
- **默认只读一个 banner 段。** 非 SYN 模板通告 1024 字节窗口，且首个数据段之后立即 RST，因此大 banner 和多段 TLS 握手会被截断。请使用 `--all-banner`，并调整 `--tcp-win`、`--max-packet-len` 和 `--snaplen`；这些值仍太小时启动会警告。
- **不处理乱序。** 数据段按到达顺序处理，没有重组队列，也没有重新排序。
- **载荷大小受包缓冲限制。** 有效上限是 `PKT_BUF_SIZE - 64`（1984 字节）。声明/实际载荷超过上限时不会发送，并记录警告；不支持把超大探测载荷分段。
- **multi-probe 需要足够的源端口。** 源端口范围必须至少提供 `multi_num` 个槽位，启动时会拒绝过小的范围。`--all-banner` 搭配 `Multi_AfterHandle` 或 `Multi_DynamicNext` 时会警告，因为这些模式可能按段输出结果。
- **只有一个接收线程。** 去重与校验都跑在那一个接收线程上，因此无论你配置多少发送或处理线程，接收侧处理都是吞吐上限。

完整的清单（含传输层与平台方面的注意事项）见 [known-limitations.md](./known-limitations.md)。要在 ZBanner 与有状态引擎之间做选择，见 [scanning-modes.md](./scanning-modes.md) 与 [hltcp.md](./hltcp.md)。
