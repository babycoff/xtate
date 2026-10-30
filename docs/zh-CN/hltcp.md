# HLTCP：混合状态 TCP 与 TLS

[English](../hltcp.md) · **中文**

ZBanner 每个目标只问一个问题，只读第一个答案。有些问题需要一段对话：完成 TLS 握手、读取证书链、在隧道里发一个 HTTP 请求、读回响应。这要求我们这侧有真正的 TCP 状态机，而每目标一份状态机正是大规模扫描负担不起的。

HLTCP 就是那个折中。它是一个用户态 TCP 栈——用源码自己的话说叫 “hybrid-state lightweight TCP”（混合状态轻量 TCP 栈）——**只在发 SYN 时完全不保留状态**，等目标证明自己会说话之后才分配连接控制块。你为真实存在的连接付内存，而不是为探测过的目标付内存。

本栈所处的线程模型见 [architecture.md](./architecture.md)，无状态替代方案见 [zbanner.md](./zbanner.md)。

## “混合状态”到底指什么

- **SYN 阶段：无状态。** 初始序号是连接元组的 SipHash cookie，与 ZBanner 用的是同一套构造。不存任何东西。SYN-ACK 到达时，从包内字段重算 cookie 并与 `ackno - 1` 比较；相等，这条连接就是我们的——也只有到这时才分配 TCB。
- **SYN-ACK 之后：有状态。** 无法从单个报文恢复的东西都放进 TCB：四元组、双向序号、未确认的段、MSS、连接年龄、探测模块的私有会话状态，以及一个超时项。

因此丢掉一个 SYN 不会留下任何痕迹：没有表项可超时，也不会尝试重传。用可靠性换占用，就是这个设计的核心。

这个栈保留的大致是“跨越一个以上报文才有意义的东西”。它丢弃 `LISTEN`、`SYN_RCVD`、`FIN_WAIT*`、`CLOSE_WAIT`、`LAST_ACK` 和 `TIME_WAIT`；乱序队列；接收缓冲；RTT 估计与拥塞控制；发送窗口管理；以及半关闭语义。数据是逐段确认的，而不是按窗口确认。

## 状态机

三个 TCP 状态、五个应用状态、五个事件：

| TCP 状态 | 含义 | 应用状态 | 含义 |
|:---|:---|:---|:---|
| `SYN_SENT` | 初始值；TCB 不会停留在该状态 | `INIT` | 刚创建 |
| `SENDING` | 有未确认数据在途 | `RECV_HELLO` | 等待服务器先开口 |
| `RECVING` | 等待接收 | `RECVING` | 等待载荷 |
| | | `SEND_FIRST` | 轮到我们发第一批字节 |
| | | `SENDING` | 应用层发送尚未完成 |

事件是 `CONNECTED`、`RECV_TIMEOUT`、`RECV_PAYLOAD`、`SENDING` 和 `SEND_SENT`。两台状态机是刻意分开的：TCP 状态回答“是否有数据在途”，应用状态回答“现在轮到谁说话”。

## 连接生命周期

```
tx:  SYN(seq=cookie, ack=0)
rx:  SYN-ACK(seq=s, ack=cookie+1) -> validate ackno-1 == cookie
     handle: record open; create TCB(seqno_me=ack, seqno_them=s+1)
     stack:  send ACK; TCP state -> RECVING; conn_init(); notify CONNECTED
app:  SEND_FIRST -> make_hello() -> DataPass -> send_data()
     head segment goes out immediately as PSH|ACK
peer: ACK retires the segment; when the queue empties, SEND_SENT -> RECVING
peer: DATA -> duplicate prefix trimmed, seqno_them advances, one ACK per segment
     -> parse_response(); if the probe returns data, send it; if is_close, close
```

对端 RST 会立刻销毁 TCB。对端 FIN 得到的是 RST 而不是 FIN/ACK——没有 `TIME_WAIT`，也没有优雅关闭。超过过期时间的连接会被发 RST 并销毁；探测模块请求关闭的连接同样如此。销毁的 TCB 回到空闲链表被复用，但进程运行期间内存从不归还操作系统。

## HLTCP 之上的 TLS

TLS 是这个栈存在的理由，它的实现方式是把字节流交给 OpenSSL，而不是自己解析记录。

- **一个 `SSL_CTX`，初始化一次。** `TLS_method()`、不验证对端、不设最小/最大协议版本、安全级别 0、`ALL:eNULL` 密码套件、全部 TLS 1.3 套件、允许不安全的遗留重协商。这不是一个安全的 TLS 客户端，也没打算是；它的配置目标是能和老服务器说话，并观察它们说什么。
- **每连接：** 两个 `BIO_s_mem()` BIO（一读一写）、一个 4 KiB 的 scratch 缓冲、一个 `SSL` 对象，以及一份目标副本，供 OpenSSL 回调取回目标。`SSL_set_connect_state` 把它设为客户端，`SSL_set_bio` 把内存 BIO 接上。
- **驱动握手。** `SSL_do_handshake()` 返回 `WANT_READ`，同时把 ClientHello 写进写 BIO；HLTCP 把这些字节当作 TCP 载荷发出。每个到达的段被写入读 BIO，再驱动一次握手。出向字节从写 BIO 抽走；入向明文要到握手完成后才有意义。
- **记录什么。** 协商出的 TLS 版本、密码套件、对端证书链（base64，每张证书一个字段）、证书主题（subject）与主题备用名称（subject alternative names），以及通过 OpenSSL info 回调暴露的 TLS alert。
- **握手之后**，TLS 探测模块变成嵌套应用探测模块的传输层。子探测产生的明文被 `SSL_write` 加密、作为 TCP 数据抽走；到达的密文被 `SSL_read` 解密后交给子探测。嵌套的 HTTP 探测完全不知道 TLS 的存在——它只是拼一个 HTTP 请求、解析一个 HTTP 响应。

### SNI 与 ALPN 是可选开启的

TLS 状态探测默认不发送 SNI（server name indication），也不发送 ALPN 协议列表；每次握手都是面向 IP 地址而不是主机名。在共享主机和 CDN 上，这会返回默认证书和默认虚拟主机，可能属于一个和你以为在探测的站点完全无关的站点。

Xtate 的目标集是 IP 地址，因此不存在可自动推导的主机名。有状态探测采用**整个运行共用一份显式 SNI** 的方式：

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe close-state -sni www.example.com -alpn h2,http/1.1 --dump-cert" \
  -rate 100 -show info
```

- `-sni <hostname>` 为本次运行的**所有目标**设置同一个 SNI。适用于这一批 IP 都属于同一个 CDN/虚拟主机的情况；不同主机名请分开运行。
- `-alpn <list>` 接受逗号/空格分隔的协议列表（如 `h2,http/1.1`），保持顺序；不设置则不发送 ALPN 扩展。
- 这是 `tls-state` 的探测参数，不是全局目标/主机名解析器；它不会做反向 DNS，也不会自动从 IP 得到 vhost。
- 无状态的 `tls-hello` 和 `jarm` 仍使用各自固定的扩展行为，不受这两个有状态参数控制。

按 IP/CIDR 映射到主机名（最长前缀匹配）可以作为后续扩展，目前尚未实现。今天要扫描多个 vhost，就按 SNI 值分开运行。

## 探测嵌套与 DataPass

状态探测可以组合：

```
tcp-state -> tls-state -> http-state / hello-state / recog-state / get-state / close-state
```

外层扫描模块是 `tcp-state`。探测模块是 `tls-state`，它用 `-subprobe` 指定自己的内层探测，用 `-subprobe-arg` 传递内层探测的参数：

```bash
--probe-arg "-subprobe http-state -subprobe-arg '--all-banner'"
```

`tls-state` 拒绝非状态型的子探测，并把子探测的多探测模式与数量复制到自己身上，让多探测语义穿透这一层。生命周期回调同样嵌套：子探测的连接初始化在 TCB 创建时运行，它的关闭在 `SSL` 对象释放之前运行。

层与层之间的粘合剂是 **DataPass**（`data`、`len`、`is_dynamic`、`is_close`）。`is_dynamic` 是所有权标志：静态数据（`0`）是发送方承诺在真正发出前不会改变的常量，下层不得释放；动态数据（`1`）已被复制到堆上，所有权随之向下传递，所以每一层都可以放心复用自己的 scratch 缓冲。`is_close` 要求 TCP 层在发完这份数据后关闭连接。由于每层读写的是同一个结构体，TLS 探测和 HTTP 探测可以彼此独立地编写。

两处粗糙的边角：子探测的 `conn_init` 在 TCB 创建时就运行，早于 TLS 握手完成（源码自己标了 `FIXME`）；并且现有状态探测都没有把 `hello_wait` 设为非零，所以“等服务器先开口”这个应用状态实际上是闲置的。

## 内存与并发

每个处理线程拥有**自己的 TCP 连接表**。由于分发对源 IP 做哈希，一条连接只会由一个线程处理，所以热路径不加锁。这是本设计的核心并发主张，只要处理线程数在扫描期间保持不变，它就成立。

| 项目 | 开销 |
|:---|:---|
| TCB 加一个未确认段 | 几百字节 |
| 哈希桶数组 | 每桶 8 字节，按扫描速率定容 |
| 超时轮 | 每张表约 8 MiB，固定，与连接数无关 |
| 包缓冲池（全局） | 16384 块 × 2048 字节，约 32 MiB |
| TLS 会话 | OpenSSL 的 `SSL`、会话与对端证书链：几 KB 到几十 KB |

最后一行占主导：纯 TCP 状态很便宜，TLS 连接不便宜，单连接开销中超过 85% 属于 OpenSSL。这个引擎适合对有意思的主机做定点取证，不适合对互联网做 TLS 普查。

表容量的选择是估算而不是预算：大致 `rate / 5 / handlers` 个桶，向上取 2 的幂，下限为十，并夹在 2^10 到 2^24 之间。表满不会拒绝新连接，只是让链变长；TCB 走池化复用，所以峰值占用会常驻。

## 容量与超时

- **连接过期：** 默认 30 秒（`-scan-arg "--conn-expire 30"`）；到期后栈发 RST 并回收 TCB。
- **重传：** 固定 1 秒 RTO，重发队首未确认段。没有 RTT 估计、没有退避，也不重传 SYN 或纯 ACK。
- **每个 TCB 一个定时器槽**，连接活跃期间每秒重新挂载。RTO 与过期共用这个槽，于是两种行为会互相覆盖对方的调度。
- **接收窗口：** 非 SYN 的 TCP 模板默认通告 1024 字节，这会让对端发出大量小段。如果扫描感觉慢，先试着调大 `--tcp-win`（并相应调整 `--max-pkt-len`）——模块自己的帮助文本也是这么说的。
- **多探测：** 探测槽位编码为源端口偏移，因此 `--source-port` 区间至少要等于探测模块的 `multi_num`，否则槽位会串线。

## 用法

```bash
# The kernel must not reset connections it does not know about (same as ZBanner)
./firewall/add_rules.sh
# TLS evidence: version, cipher, certificate chain (tls-state needs a state sub-probe)
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan tcp-state -probe tls-state \
  --probe-arg "-subprobe close-state --dump-version --dump-cipher --dump-cert" -show info
# HTTPS: complete TLS, then speak HTTP inside the tunnel
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan tcp-state -probe tls-state \
  --probe-arg "-subprobe http-state -subprobe-arg '--all-banner'" -show info
# A plain TCP conversation with no TLS
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80 -scan tcp-state -probe http-state -show info
./firewall/rm_rules.sh
```

模块专属选项经 `--scan-arg`（给 `tcp-state`）和 `--probe-arg`（给探测模块）传入。例如 `-scan-arg '--conn-expire 15 --record-all-ttl'` 会缩短连接存活时间并记录每个段的报文级细节；各模块的选项由 `--help-probe` 和 `--help-scan` 列出。

## 已知限制

- **不重传 SYN。** TCB 只在收到 SYN-ACK 后才存在，所以 `SYN_SENT` 的超时分支永远不会触发。丢掉一个 SYN 就是一次无声的漏报——重跑扫描，或把范围收窄到更有价值的目标。
- **不补发 ACK。** 如果我们对 SYN-ACK 的 ACK 丢了，对方重传的 SYN-ACK 会被忽略而不是被确认，于是对端会一直重传到我们 30 秒过期为止。
- **不处理乱序。** 超出期望序号的数据直接丢弃、不缓存；恢复全靠对端重传。大证书链和多段 TLS flight 是最常见的受害者。
- **固定 1 秒 RTO，无退避。** 在高延迟链路上会重传得过于急切。
- **没有优雅关闭。** FIN 得到 RST 应答，没有 `TIME_WAIT`，TLS 也不发 `close_notify`。目标会看到异常终止——对扫描可接受，对长期监测则很吵。
- **关闭端口不产生输出。** 匹配不到 TCB 的 RST 不会变成结果，所以 `tcp-state` 只报告开放端口。ZBanner 两者都报，因此两个引擎在端口普查上并不等价。
- **SNI/ALPN 是可选开启的。** 默认情况下虚拟主机和 CDN 目标返回默认证书；当目标 IP 属于一个已知主机名时，在 `tls-state` 上设置 `-sni`/`-alpn`。
- **OpenSSL 内存。** 每条存活的 TLS 连接占几 KB 到几十 KB；决定内存上限的是它，而不是 TCP 栈。
- **去重被关闭。** `tcp-state` 把去重交给状态机自己处理，因此重复报文行为比 ZBanner 弱。

这些问题的细节与规避办法，连同 ZBanner 与平台方面的注意事项，都收录在 [known-limitations.md](./known-limitations.md)。要在两个引擎之间选择，见 [scanning-modes.md](./scanning-modes.md)。
