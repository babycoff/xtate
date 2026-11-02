# 目标与端口

[English](../targets-and-ports.md) · **中文**

Xtate 扫描的是一个**乘积空间**：每个目标地址都会与每个目标端口组合。`-ip` 提供地址，`-p` 提供端口，生成模块（GenerateModule）决定最终 `(address, port)` 对的访问顺序。默认生成模块是 `blackrock`，它以无状态、均匀分散的方式置换这个空间。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

> 本文档对应 Xtate v2.21.4。命令行才是最终依据：`--help`、`--help-scan <module>` 和 `--help-probe <module>` 会给出你所构建版本的准确参数。

## 地址目标

`-ip` 是 `--target-ip` 的短形式（别名：`--range`、`--dst-ip`）。它接受四种写法，并且可以在一个逗号分隔的值里混用：

| 写法 | 示例 |
|:---|:---|
| 单个地址 | `192.168.1.10` |
| 闭区间范围 | `10.0.0.1-10.0.0.100` |
| CIDR 网段 | `10.0.0.0/24` |
| 列表 | `10.0.0.0/24,192.168.1.5,2001:db8::1` |

IPv6 使用相同的写法；范围两端都需要写完整的 IPv6 地址。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn
sudo ./bin/xtate -ip 10.0.0.10-10.0.0.20 -p 22 -scan tcp-syn
sudo ./bin/xtate -ip 2001:db8::/126 -p 443 -scan tcp-syn
sudo ./bin/xtate -ip 2001:db8::1-2001:db8::ff -p 443 -scan tcp-syn
```

每个 `-ip` 都会**替换**地址列表而不是追加，因此请用一个选项加逗号分隔列表，不要重复写 `-ip`。至少需要一个目标：地址列表为空时 `blackrock` 会拒绝启动。对链路本地作用域的 IPv6 目标，必须用 `-src-ip`（`--source-ip`）显式设置源地址；全局作用域的源地址会从网卡上自动发现。

## 目标文件

`-iL`（`--include-file`）从文件而不是命令行读取列表。文件格式与 `-ip` 相同，每行可以有一个或多个条目；`#` 开始注释；`-` 表示从 stdin 读取。

```bash
# ranges.txt:
#   10.0.0.0/24      # datacenter
#   192.168.1.0/24   # lab
#   2001:db8::/64    # IPv6 test allocation
sudo ./bin/xtate -iL ranges.txt -p 80,443 -scan tcp-syn
cat ranges.txt | sudo ./bin/xtate -iL - -p 80,443 -scan tcp-syn
```

与 `-ip` 一样，`-iL` 会替换掉它要设置的地址列表，且可以容纳数百万条范围。列表在扫描开始前会被解析并排序，因此只要有一行写错，本次运行就会在早期失败。

## 排除目标

有三个选项可以从目标空间中减掉部分工作。排除规则在所有目标和端口输入解析完成**之后**才应用，因此命令行上 `-ip` 与 `--exclude` 的先后顺序无关紧要。

| 选项 | 移除的内容 |
|:---|:---|
| `--exclude` | 地址、范围或 CIDR 网段（语法同 `-ip`） |
| `--exclude-file` | 同上，但从文件读取 |
| `--exclude-port` | 端口或端口范围（语法同 `-p`） |

```bash
# Scan a /8 but not the RFC1918 hole in it, and skip two ports
sudo ./bin/xtate -ip 10.0.0.0/8 --exclude 10.10.0.0/16,10.20.1.1 \
  --exclude-port 80,443 -p 80,443,8080 -scan tcp-syn

# Or read both lists from files
sudo ./bin/xtate -ip 10.0.0.0/8 --exclude-file excludes.txt -p 80,443 -scan tcp-syn
```

`--exclude` 每次使用都会重置排除表，也就是说第二个 `--exclude` 会替换第一个。请把所有要排除的范围放进一个选项，或改用 `--exclude-file`。还有一道保护性检查：如果请求的空间包含超过十亿个 IP 地址且没有 IPv4 `--exclude`，`blackrock` 会拒绝启动；加一个无害的 `--exclude 255.255.255.255` 作为明确确认即可。

## 按 ASN 指定目标

不必逐个列出地址，你可以要求某个 AS 通告的全部前缀。映射来自 `ip2asn` TSV 文件，用 `--ip2asn-v4` / `--ip2asn-v6` 加载（主名是 `--ip2asn-v4-file` / `--ip2asn-v6-file`）。`--asn-v4`（`--target-asn-v4`）和 `--asn-v6`（`--target-asn-v6`）负责添加地址；`--exclude-asn-v4` / `--exclude-asn-v6` 负责移除地址。ASN 用逗号分隔（空白也可以分隔）。没有加载 ip2asn 文件时扫描会报错停止，而不是悄悄什么都不扫。

```bash
sudo ./bin/xtate --ip2asn-v4 /path/to/ip2asn-v4.tsv \
  --asn-v4 13335,15169 --exclude-asn-v4 16509 \
  -p 443 -scan tcp-syn -rate 5000
```

## 端口

`-p` 是 `--port` 的短形式。它的语法与 nmap 类似：

| 写法 | 含义 |
|:---|:---|
| `80` | 单个端口 |
| `80,443` | 端口列表 |
| `8000-8100` | 闭区间范围 |
| `u:161` | UDP 端口 161 |
| `s:38412` | SCTP 端口 38412 |
| `o:1-20` | “其他协议”编号 1..20，供 `yarrp-echo` 之类的模块使用 |

协议前缀会作用于它之后的所有内容，直到出现下一个前缀，因此 `-p 80,u:161,162` 会扫描 TCP 80，然后是 UDP 161 和 UDP 162。前缀大小写不敏感（`U:`、`u:`、`T:`、`S:`、`O:`）。在内部，每种传输层协议各自维护 0..65535 的独立空间，所以 TCP 53 和 UDP 53 是两个不同的端口。

```bash
# TCP 80 and 443, plus UDP 161 and the UDP range 1024-1100
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80,443,u:161,u:1024-1100 -scan udp -probe echo
```

每个目标地址都会与整个端口列表做笛卡尔积。为了保证可移植性，应始终传入 `-p`；如果一个端口都不剩，`blackrock` 会告警并替换成伪端点 `o:0`，而多数扫描模块会忽略它——此时 TCP 扫描没有多少有用的数据可发。

### 常用端口

`--top-port N` 把内置 TCP 端口列表中的前 `N` 个条目加入端口表；`--udp-top-port N` 对 UDP 列表做同样的事。它们是**追加**到端口表，而不是替换：

```bash
sudo ./bin/xtate -ip 10.0.0.0/24 -p 8443 --top-port 100 -scan tcp-syn
```

`-p` 会先清空端口表，所以要把 `-p` 放在 `--top-port` / `--udp-top-port` **之前**；放在它们之后的 `-p` 会把它们添加的端口清掉。

### 不读取端口的模块

`icmp-echo`、`icmp-time`、`arp-req` 和 `ndp-ns` 不读取端口，它们的文档也明确要求不要指定端口。`yarrp-echo` 和 `yarrp-udp` 则借用端口列表承载 TTL 范围（`-p o:1-20`），因此这些模式必须提供 `o:` 规格。每种模式的具体要求见[扫描模式](./scanning-modes.md)。

## 分片、续扫与种子

`--shard k/n` 把一次逻辑扫描拆分到 `n` 个实例上：第 `k` 个实例从偏移 `k-1` 开始，之后每 `n` 个包取一个。这就是从多台主机扫描同一个目标空间而不重叠的办法。

```bash
# Host 1 of 4, host 2 of 4, ... - all with the same seed
sudo ./bin/xtate -ip 10.0.0.0/8 -p 80,443 -scan tcp-syn -seed 1234 --shard 1/4
sudo ./bin/xtate -ip 10.0.0.0/8 -p 80,443 -scan tcp-syn -seed 1234 --shard 2/4
```

所有分片**必须使用同一个 `-seed`**；否则每个实例会产生不同的置换，分片之间就会重叠。使用分片但没有显式指定种子时，Xtate 会发出告警。种子还用于派生 TCP/UDP cookie，因此要在分片之间和多次运行之间保持不变。`-seed time` 会显式用本地时钟重新播种；如果不给 `-seed`，Xtate 会自行采集熵。

`--resume-index N` 从索引 `N` 而不是 0 开始置换。通常不需要手写：第一次按 `Ctrl-C` 时，Xtate 会把当前位置连同其余配置写入 `resume.conf`，之后用 `sudo ./bin/xtate --conf resume.conf` 继续。只有在目标集合、端口列表、生成模块和种子都不变时续扫才有意义——它们共同构成了展平后的索引空间。`--no-resume-file` 会阻止写入 `resume.conf`（适用于目标列表过大、保存很慢的情况）。

## 扫描前检查目标空间

列举模式接受与扫描相同的目标和端口选项，但不发送任何数据包：

```bash
# Every unique ip:port in scan order
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80,443 -scan tcp-syn --list-target

# The target addresses as CIDR blocks
sudo ./bin/xtate -ip 10.0.0.0/24,192.168.1.5 -scan tcp-syn --list-cidr
```

`--list-target` 会打印打乱后的乘积空间；加载 ip2asn 文件后再加 `--output-as-info`，可以为每个地址标注其 AS。`blackrock` 最多支持 63 位的目标空间，数量等于地址数乘以端口数——扫描 IPv6 时要记住这一点。

上面的选项会传给默认的 `blackrock` 生成模块。`ip-list`、`addr-list`、`ip-stream` 和 `addr-stream` 生成模块则从文件或 stdin 读取目标，改用它们**自己的**子参数（`-gen-arg "-ip-file list.txt"`）；它们只支持一个发送线程。细节见[模块](./modules.md)。

## 另见

- [扫描模式](./scanning-modes.md) - 哪个模块消费哪些端口和载荷
- [输出](./output.md) - 保存结果
- [上手](./getting-started.md) - 构建、权限、第一次扫描
- [根 README](../../README.zh-CN.md) - 功能概览与论文
