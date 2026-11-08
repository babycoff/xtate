#include "i18n.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#endif

typedef struct I18nEntry {
    const char *en;
    const char *zh_cn;
} I18nEntry;

/*
 * Catalog policy
 * --------------
 * Keys are the exact English source strings used by help code. Only
 * human-facing text belongs here; parameter names, module names and result
 * values stay stable across languages.
 *
 * Adding a translation is intentionally a one-line change. If a string has no
 * entry (or the language is English), i18n_tr() returns the English source.
 * This keeps a partial translation safe and makes review of help changes local.
 */
static const I18nEntry i18n_catalog[] = {
    /* Global chrome */
    {"Welcome to Xtate!", "欢迎使用 Xtate！"},
    {"A modular all-stack network scanner for next-generation internet "
     "surveys.",
     "面向下一代互联网测量的模块化全栈网络扫描器。"},
    {"Author : ", "作者    ："},
    {"Github : ", "GitHub  ："},
    {"Contact: ", "联系方式："},

    /* Banner/usage */
    {"typical format for scanning with specified module:\n",
     "指定模块扫描的典型格式：\n"},
    {"enter interactive mode:", "进入交互模式："},
    {"check basic usage examples:", "查看基础用法示例："},
    {"detailed help of global params:", "查看全局参数详细帮助："},
    {"basic use examples of Xtate:\n", "Xtate 基础用法示例：\n"},
    {"basic use examples of xtate:\n", "Xtate 基础用法示例：\n"},
    {"use TcpSyn ScanModule to scan web ports on 10.x.x.x at 10kpps.\n",
     "使用 TcpSyn 扫描模块以 10kpps 扫描 10.x.x.x 的 Web 端口。\n"},
    {"use UdpProbe ScanModule to scan UDP 80 port with echo ProbeModule and "
     "also show info results.\n",
     "使用 UdpProbe 扫描模块和 echo 探测模块扫描 UDP 80 端口，并显示 info "
     "结果。\n"},
    {"use IcmpEcho ScanModule to do ping scan and record TTL.\n",
     "使用 IcmpEcho 扫描模块做 ping 扫描并记录 TTL。\n"},
    {"use ZBanner ScanModule to grab http banners with http ProbeModule and "
     "ScanModule-specific param.\n",
     "使用 ZBanner 扫描模块和 http 探测模块抓取 HTTP "
     "banner，并传入扫描模块参数。\n"},
    {"use SctpInit ScanModule to scan SCTP 38412(36412) port and show fail "
     "results.\n",
     "使用 SctpInit 扫描模块扫描 SCTP 38412(36412) 端口并显示 fail 结果。\n"},
    {"do ARP scan with LAN mode in local network.\n",
     "在本地网络中使用 LAN 模式做 ARP 扫描。\n"},
    {"do NDP NS scan with a link-local source IP in local network.\n",
     "在本地网络中使用链路本地源 IP 做 NDP NS 扫描。\n"},
    {"list all ScanModules and other types of module are the same.\n",
     "列出全部扫描模块；其它类型模块的用法相同。\n"},
    {"see help of TcpSyn ScanModule in detail.\n",
     "查看 TcpSyn 扫描模块的详细帮助。\n"},
    {"set params and do scanning in an user-friendly interactive mode.\n",
     "在交互模式中设置参数并执行扫描。\n"},
    {"print version and compilation info.\n", "打印版本和编译信息。\n"},
    {"show the design and architecture of Xtate.\n",
     "展示 Xtate 的设计与架构。\n"},
    {"display this usage text of using examples.\n", "显示这份用法示例。\n"},
    {"display detailed help text of all parameters.\n",
     "显示全部参数的详细帮助。\n"},

    /* Help page */
    {"Here are detailed help text of all parameters of Xtate. I hope these "
     "will help you a lot. If any problem or advice, please contact me.\n",
     "以下是 Xtate "
     "全部参数的详细帮助。希望对你有所帮助；\n如有问题或建议，欢迎联系作者。"
     "\n"},
    {"BASIC PARAMITERS", "基础参数"},
    {"TARGET SETTINGS", "目标设置"},
    {"INTERFACE ADJUSTMENT", "网卡调整"},
    {"OPERATION SELECTION", "操作选择"},
    {"SCAN MODULES CONFIG", "扫描模块配置"},
    {"PROBE MODULES CONFIG", "探测模块配置"},
    {"OUTPUT MODULES CONFIG", "输出模块配置"},
    {"GENERATE MODULES CONFIG", "生成模块配置"},
    {"STATUS PRINTING", "状态显示"},
    {"PACKET ATTRIBUTES", "数据包属性"},
    {"TRANSMITTING WAYS", "发送方式"},
    {"MISCELLANEOUS", "其他"},

    /* Intro */
    {"This is how Xtate working internally:\n", "Xtate 内部工作流程如下：\n"},
    {"This is what ScanModules and ProbeModules mean:\n",
     "ScanModules 与 ProbeModules 的关系如下：\n"},

    /* Module help labels */
    {"Name of ScanModule:  ", "扫描模块名称：  "},
    {"Probe Type Required: ", "所需探测类型："},
    {"Default BPF Filter:\n", "默认 BPF 过滤器：\n"},
    {"Description:\n", "描述：\n"},
    {"ProbeModule Name: ", "探测模块名称："},
    {"ProbeModule Type: ", "探测模块类型："},
    {"Slot count: ", "Slot 数量："},
    {"Slot trigger: ", "Slot 触发方式："},
    {"Hello wait second: ", "问候等待秒数："},
    {"Name of OutputModule: ", "输出模块名称："},
    {"Need to Specify file: ", "是否需要指定文件："},
    {"GenerateModule Name: ", "生成模块名称："},
    {"SCAN MODULES:\n", "扫描模块：\n"},
    {"PROBE MODULES:\n", "探测模块：\n"},
    {"OUTPUT MODULES:\n", "输出模块：\n"},
    {"GENERATE MODULES:\n", "生成模块：\n"},

    /* Language parameter */
    {"Set the language of human-facing help text: en or zh-CN. Untranslated "
     "strings fall back to English.",
     "设置人类可读帮助文本的语言：en 或 zh-CN。未翻译的字符串回退到英文。"},
    {"Set help language.", "设置帮助语言。"},
    {"Commands:\n", "命令：\n"},
    {"Type `help` for commands, <TAB> for completion.\n",
     "输入 `help` 查看命令，<TAB> 补全。\n"},
    {"Use `set` to configure, `run` to scan, `quit` to exit.\n",
     "用 `set` 配置，`run` 扫描，`quit` 退出。\n"},
};

static I18nLanguage i18n_language = I18N_EN;

static char *i18n_lower_trim(const char *src, char *buf, size_t size) {
    size_t n = 0;
    while (src && *src && n + 1 < size) {
        unsigned char c = (unsigned char)*src++;
        if (c == '-' || c == '_' || c == ' ')
            continue;
        buf[n++] = (char)tolower(c);
    }
    buf[n] = '\0';
    return buf;
}

void i18n_init(void) {
    const char *env = getenv("XTATE_LANG");
    if (env && env[0])
        i18n_set_language(env);
}

bool i18n_set_language(const char *code) {
    char buf[32];

    if (!code || !code[0])
        return false;

    i18n_lower_trim(code, buf, sizeof(buf));

    if (strcmp(buf, "en") == 0 || strcmp(buf, "english") == 0) {
        i18n_language = I18N_EN;
        return true;
    }

    if (strcmp(buf, "zh") == 0 || strcmp(buf, "zhcn") == 0 ||
        strcmp(buf, "cn") == 0 || strcmp(buf, "chinese") == 0) {
        i18n_language = I18N_ZH_CN;
        return true;
    }

    return false;
}

I18nLanguage i18n_get_language(void) { return i18n_language; }

const char *i18n_language_name(void) {
    return i18n_language == I18N_ZH_CN ? "zh-CN" : "en";
}

const char *i18n_tr(const char *src) {
    if (!src || !src[0] || i18n_language == I18N_EN)
        return src;

    for (unsigned i = 0; i < sizeof(i18n_catalog) / sizeof(i18n_catalog[0]);
         i++) {
        if (strcmp(src, i18n_catalog[i].en) == 0)
            return i18n_catalog[i].zh_cn;
    }

    return src;
}


void i18n_write(const char *data, size_t len) {
    if (!data || len == 0)
        return;

#if defined(_WIN32)
    /* The console code page is process-global. Never change it; write Unicode
     * directly when attached to a console, and keep UTF-8 for pipes/files. */
    if (i18n_language == I18N_ZH_CN && _isatty(_fileno(stdout))) {
        int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data,
                                       (int)len, NULL, 0);
        if (wlen > 0) {
            wchar_t *wide = (wchar_t *)malloc(((size_t)wlen + 1) * sizeof(wchar_t));
            if (wide) {
                MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data,
                                    (int)len, wide, wlen);
                /* Keep ordering with raw stdio output (crossline prompts and
                 * completion menus use printf). */
                fflush(stdout);
                DWORD written = 0;
                WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), wide,
                              (DWORD)wlen, &written, NULL);
                free(wide);
                return;
            }
        }
    }
#endif

    fwrite(data, 1, len, stdout);
}

void i18n_printf(const char *fmt, ...) {
    va_list ap;

#if defined(_WIN32)
    if (i18n_language == I18N_ZH_CN && _isatty(_fileno(stdout))) {
        va_start(ap, fmt);
        int n = vsnprintf(NULL, 0, fmt, ap);
        va_end(ap);
        if (n >= 0) {
            char *buf = (char *)malloc((size_t)n + 1);
            if (buf) {
                va_start(ap, fmt);
                vsnprintf(buf, (size_t)n + 1, fmt, ap);
                va_end(ap);
                i18n_write(buf, (size_t)n);
                free(buf);
                return;
            }
        }
    }
#endif

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

typedef struct I18nParamEntry {
    const char *name;
    const char *zh_cn;
} I18nParamEntry;

static const I18nParamEntry i18n_global_help[] = {
    {"seed", "设置目标/端口随机化和 cookie 生成的全局随机种子。可填整数；不同种子改变发送顺序。填 time 使用本地时间自动生成新顺序；不设置时默认 time。--echo 可保存配置以复现实验。"},
    {"rate", "设置所有发送线程共享的总发包速率（packets/second），支持小数（如 0.1）和很大值。日常 Windows 约 250k pps，较新的 Linux 约 2.5M pps；25M pps 需要 PF_RING。该值是总速率，不是每线程速率。"},
    {"wait", "所有发送线程结束后，继续接收和处理回包的秒数；默认 10 秒。调大可等待慢响应，但会延长进程退出时间。"},
    {"forever", "把 --wait 设为很大的值，用于持续接收/长期运行。"},
    {"shard", "用 x/y 把扫描空间分给多个实例：x 是当前实例编号（从 1 开始），y 是实例总数；例如 1/2 从索引 0 开始每隔一个发送，2/2 从索引 1 开始。仅默认 GenerateModule 实现该功能。"},
    {"tx-thread-count", "设置发送线程数；默认 4。线程数不超过 CPU 内核时，每个线程会尝试绑定到独立内核。多个发送线程共享一个接收线程。"},
    {"rx-handler-count", "设置接收处理线程数；必须为 2 的幂，默认 1。回包按 (dst_IP,dst_Port,src_IP,src_Port) 分发到 handler；Lua 探针强制为 1。"},
    {"d", "按 -d/-dd/-ddd 提高日志级别：0 输出 OUT/HINT/ERROR/WARN；1 增加 INFO；2 增加 DEBUG；3 增加 DETAIL。"},
    {"interactive-mode", "启动交互式配置/扫描模式。需要支持控制字符的现代终端；会自动写 recover.conf，Linux 下完成扫描后可用该配置重启。"},
    {"lang", "设置人类可读帮助语言：en 或 zh-CN。未翻译的字符串回退到英文。"},
    {"version", "打印版本和编译信息。"},
    {"usage", "打印基础用法和示例。"},
    {"help", "打印全部参数的详细帮助。"},
    {"introduction", "打印 Xtate 设计和工作流程介绍。"},
    {"target-ip", "指定静态 IPv4/IPv6 目标：单 IP、显式范围、CIDR 或分量范围（如 132.80-88.90.15、2001:db8:1-5::1）。单个 token 最多 4 个分量范围组成笛卡尔积，上限 1,048,576 个地址；多个目标用逗号分隔。至少需要一个目标。"},
    {"port", "指定要扫描的端口或范围，如 -p 80、-p 20-25、-p 80,20-25；UDP 用 U:161,u:1024-1100，SCTP 用 S:36412,s:38412；O: 表示 0..65535 的非端口数值。"},
    {"top-port", "从内置常用 TCP 端口列表中加入指定数量的端口。"},
    {"udp-top-port", "从内置常用 UDP 端口列表中加入指定数量的端口。"},
    {"include-file", "从文件读取目标范围列表，格式同 --target-ip；可包含大量地址。文件名 `-` 表示从 stdin 读取。"},
    {"exclude", "排除指定 IP/范围/CIDR；覆盖任何目标设置，保证这些地址不被扫描。"},
    {"exclude-port", "排除指定端口或端口范围；覆盖任何端口设置，保证这些端口不被扫描。格式与 --port 相同。"},
    {"exclude-file", "从文件读取要排除的目标范围，格式同 --target-ip。"},
    {"target-asn-v4", "按 IPv4 ASN 添加目标；AS 信息来自 --ip2asn-v4 文件。"},
    {"target-asn-v6", "按 IPv6 ASN 添加目标；AS 信息来自 --ip2asn-v6 文件。单个 IPv6 ASN 范围可能很大，通常需要再排除。"},
    {"exclude-asn-v4", "按 IPv4 ASN 排除目标；AS 信息来自 --ip2asn-v4 文件。"},
    {"exclude-asn-v6", "按 IPv6 ASN 排除目标；AS 信息来自 --ip2asn-v6 文件。"},
    {"adapter", "使用指定原始网卡接口（如 eth0、dna1）。未指定时选择第一个带默认网关的接口，或自动探测。"},
    {"source-ip", "设置发送报文的源 IP。可指定范围，但范围大小必须是 2 的幂（1/2/4/8/...）。IPv6 链路本地地址需要手动指定。"},
    {"source-port", "设置发送报文的源端口或范围（范围大小必须是 2 的幂）。未指定时在 40000-60000 随机。建议用防火墙过滤这些端口，避免主机协议栈干扰回包。"},
    {"source-mac", "设置发送报文的源 MAC；未指定时使用网卡绑定的第一个 MAC。"},
    {"router-ip", "设置 IPv4 路由器/网关 IP。"},
    {"router-mac", "设置发送报文的目标路由器 MAC；未指定时通过 ARP 获取网关 MAC。可用后缀分别设置 IPv4/IPv6 路由器 MAC。"},
    {"adapter-vlan", "设置发送报文的 802.1q VLAN ID。"},
    {"adapter-snaplen", "设置 pcap/PF_RING 的最大抓包长度，默认 65535，超过 65535 会被拒绝；会对报文造成截断，需注意与 --tcp-win、--max-packet-len 的相互影响。"},
    {"lan-mode", "把路由器 MAC 设为广播 ff-ff-ff-ff-ff-ff，以进行局域网二层扫描（如 ARP）。它不解析逐目标 MAC；普通 TCP/UDP 扫描通常不应开启，因为广播目标在路由/Docker/bridge/过滤环境可能失败。"},
    {"fake-router-mac", "把路由器 MAC 设为无效地址 01-02-03-04-05-06，跳过 ARP 解析。适合 ScanModule 会按目标动态指定 MAC 的场景（如 NDP NS）；配合 --infinite 可测试最高发送速率。"},
    {"bypass-os", "完全绕过操作系统协议栈：可设置本地子网内不与 OS 一致的 --source-ip/--source-mac，Xtate 会像真实成员一样响应 ARP/NDP。无需 Linux 防火墙规则，但也不能依赖 OS 的 TCP RST/ICMP unreachable；BPF 需匹配所需报文类型。"},
    {"init-ipv4-adapter", "手动决定是否初始化 IPv4 原始网卡；用于不能自动初始化的生成器。"},
    {"init-ipv6-adapter", "手动决定是否初始化 IPv6 原始网卡；用于不能自动初始化的生成器。"},
    {"echo", "不执行扫描，打印当前配置。--echo 只打印与默认值不同的项；--echo-all 打印所有显式值。可保存为配置文件再用 --config-file 加载。"},
    {"debug-if", "对网卡相关代码运行自检，用于排查接口无法工作的问题。"},
    {"benchmark", "运行关键单元的全局性能基准。"},
    {"selftest", "运行全局回归自检，检查代码改动是否健康。"},
    {"list-cidr", "把解析后的目标按 CIDR 形式列出。"},
    {"list-range", "把解析后的目标按范围形式列出。"},
    {"list-target", "列出最终解析的目标和端口，便于在真正扫描前检查生成/排除/分片结果；不发送报文。"},
    {"list-if", "列出可用的原始网卡接口。"},
    {"help-parameter", "按名称显示单个全局参数的帮助。"},
    {"search-parameter", "模糊搜索全局参数。"},
    {"search-module", "在扫描/探测/输出/生成四类模块中模糊搜索。"},
    {"list-nmap-probes", "列出内置/已加载的 nmap 探针。"},
    {"parse-bson-file", "把 BSON 结果文件解析为 JSON。"},
    {"store-json-file", "把 NDJSON 结果文件导入 MongoDB。需要同时指定 --mongodb-uri、数据库名和集合名；用于离线归档/重放。"},
    {"store-bson-file", "把 BSON 结果文件导入 MongoDB。"},
    {"mongodb-uri", "设置 MongoDB 连接 URI。"},
    {"mongodb-db-name", "设置导入 MongoDB 的数据库名。"},
    {"mongodb-col-name", "设置导入 MongoDB 的集合名。"},
    {"mongodb-app-name", "设置 MongoDB 应用名（profile log 跟踪）。"},
    {"scan-module", "选择 ScanModule；模块必须与 -probe 类型匹配。"},
    {"list-scan-modules", "列出全部扫描模块。"},
    {"help-scan-module", "显示指定扫描模块的详细帮助。"},
    {"scan-module-args", "向扫描模块传递参数（一个带引号的字符串）。"},
    {"probe-module", "选择 ProbeModule；ScanModule 要求时必需，且 probe 类型必须与 scan 类型匹配。模块参数用 --probe-arg 传入。"},
    {"list-probe-modules", "列出全部探测模块。"},
    {"help-probe-module", "显示指定探测模块的详细帮助。"},
    {"probe-module-args", "向探测模块传递参数（一个带引号的字符串）。"},
    {"output-module", "选择输出模块；默认 text。模块参数用 --output-arg 传入。"},
    {"list-output-modules", "列出全部输出模块。"},
    {"help-output-module", "显示指定输出模块的详细帮助。"},
    {"output-module-args", "向输出模块传递参数（一个带引号的字符串）。"},
    {"output-file", "设置输出文件名。MongoDB 输出时这里是连接 URI；部分模块用 `-` 表示 stdout。"},
    {"append-output", "以追加方式打开输出文件，而不是覆盖；不适用于 MongoDB 等非文件输出。"},
    {"output-screen", "同时把成功结果输出到屏幕。"},
    {"show-output", "选择要显示的结果级别（如 success/info/failure）。"},
    {"no-show-output", "关闭结果打印。"},
    {"no-escape-char", "关闭输出字符串的转义。可能产生非法 JSON/CSV；除非下游自行解析，否则不建议使用。"},
    {"output-as-info", "把 success 结果标记为 info 级别，便于只看 info/失败或调整输出过滤。"},
    {"generate-module", "选择目标生成模块；默认 blackrock。生成模块参数用 --gen-arg 传入。"},
    {"list-generate-modules", "列出全部生成模块。"},
    {"help-generate-module", "显示指定生成模块的详细帮助。"},
    {"generate-module-args", "向生成模块传递参数（一个带引号的字符串）。"},
    {"print-status", "启用实时状态栏，显示速率/进度等信息；非交互输出或日志采集时可用 --no-status 关闭。"},
    {"ndjson-status", "用 NDJSON 输出状态，便于机器读取。"},
    {"no-status", "关闭实时状态栏。"},
    {"packet-ttl", "设置发送报文的默认 IP TTL/Hop Limit。"},
    {"tcp-init-window", "设置初始 TCP 窗口大小（SYN 中的窗口字段）；影响对端发送节奏。"},
    {"tcp-window", "设置 TCP 接收窗口。HLTCP 默认窗口较小会产生许多小包；调大窗口并配合 --max-packet-len 可加速，但需要接收缓冲。"},
    {"tcp-wscale", "设置 TCP 窗口缩放因子；必须与窗口大小配合，且双方协商后生效。"},
    {"tcp-mss", "设置 TCP MSS 选项值；影响对端分段大小，需不超过路径 MTU。"},
    {"tcp-sackok", "启用/关闭 TCP SACK permitted 选项；影响丢包恢复行为。"},
    {"tcp-tsecho", "设置 TCP timestamp echo 选项；研究用途，错误值会影响握手/测量。"},
    {"packet-trace", "打印每个发送/接收报文的调试信息，可能非常耗时。"},
    {"bpf-filter", "设置自定义 BPF 过滤器，覆盖 ScanModule 默认过滤器；语法错误会导致启动失败。"},
    {"no-bpf-filter", "关闭 ScanModule 默认 BPF 过滤器；需要自行确保收到所需报文，否则会漏结果。"},
    {"max-packet-len", "设置接收报文的最大长度；需与 --tcp-win、--snaplen 配合。"},
    {"raw-socket", "使用原始套接字发送报文，绕过内核 TCP/UDP 发送路径。"},
    {"sendmmsg", "使用 Linux sendmmsg 批量发送报文，减少系统调用开销。"},
    {"sendmmsg-batch", "设置 sendmmsg 每批发送数量。"},
    {"sendmmsg-retries", "设置 sendmmsg 批处理重试次数。"},
    {"send-queue", "使用发送队列解耦发送与接收；可能增加内存占用并改变时序。"},
    {"send-queue-size", "设置发送队列容量；过大增加内存，过小可能阻塞。"},
    {"pfring", "使用 PF_RING 高速抓包/发送；需要 PF_RING 驱动和库。"},
    {"offline", "离线模式：不实际发包，只处理已有输入/输出，便于调试和回放。"},
    {"config-file", "从配置文件加载参数；通常由 --echo 生成。命令行参数可覆盖/补充配置。"},
    {"resume-index", "从指定扫描索引恢复扫描。"},
    {"no-resume-file", "不写 resume.conf，避免在磁盘留下可恢复配置。"},
    {"meta-filename", "设置扫描元信息输出文件。"},
    {"pcap-filename", "把收到的报文保存为 pcap 文件。"},
    {"no-ansi-control", "关闭 ANSI 控制字符，适合日志/非交互终端。"},
    {"no-dedup", "关闭接收去重。"},
    {"dedup-win", "设置接收去重窗口大小；越大能覆盖更多乱序/重复包，但消耗更多内存。"},
    {"stack-buf-count", "设置协议栈缓冲区数量；影响可同时处理的报文/连接缓冲。"},
    {"dispatch-buf-count", "设置接收分发队列大小；队列过小可能丢包，过大增加内存和延迟。"},
    {"infinite", "无限重复扫描，直到手动终止；适合压力/性能测试，会持续消耗带宽和目标资源。"},
    {"repeat", "设置重复扫描次数；每次重复使用同一目标/模块配置，适合稳定性测试或采样。"},
    {"static-seed", "使用固定随机种子（调试用）；会降低随机性。"},
    {"no-cpu-bind", "不把发送/接收线程绑定到 CPU 内核；便于调试或避免绑定冲突，但可能降低性能。"},
    {"ip2asn-v4-file", "指定 IPv4 ASN 数据库文件（ip2asn 格式）。"},
    {"ip2asn-v6-file", "指定 IPv6 ASN 数据库文件。"},
    {"no-back-trace", "崩溃时不打印调用栈。"},
};

const char *i18n_tr_global_param(const char *name, const char *english) {
    if (i18n_language != I18N_ZH_CN || !name)
        return i18n_tr(english);
    for (unsigned i = 0;
         i < sizeof(i18n_global_help) / sizeof(i18n_global_help[0]); i++) {
        if (strcmp(name, i18n_global_help[i].name) == 0)
            return i18n_global_help[i].zh_cn;
    }
    return i18n_tr(english);
}

typedef struct I18nModuleParamEntry {
    const char *name;
    const char *zh_cn;
} I18nModuleParamEntry;

static const I18nModuleParamEntry i18n_module_param_help[] = {
    {"send-rst", "收到 SYN-ACK 后主动发送 RST，结束目标连接；适合 bypass 模式或 Windows 下避免占用目标连接资源，但不再继续接收 banner。"},
    {"fail-zerowin", "把零窗口（zero-window）的 SYN-ACK 视为失败；默认视为成功/开放。"},
    {"record-ttl", "记录响应报文的 IPv4 TTL 或 IPv6 Hop Limit；不同 ScanModule 记录 SYN-ACK、RST、ICMP 或 SCTP 响应。"},
    {"record-ipid", "记录响应报文的 IPv4 IPID；IPv6 没有该字段。"},
    {"record-win", "记录响应报文的 TCP 窗口大小（SYN-ACK/RST；tcp-state 记录 SYN-ACK）。"},
    {"record-mss", "记录 SYN-ACK 中的 TCP MSS 选项值（如果存在）。"},
    {"record-seqno", "记录响应报文的 TCP sequence number。"},
    {"record-ackno", "记录响应报文的 TCP acknowledge number。"},
    {"syn-ttl", "为 SYN 报文单独设置 TTL，覆盖全局默认值。"},
    {"rst-ttl", "为 RST 报文单独设置 TTL，覆盖全局默认值。"},
    {"no-dedup-synack", "关闭 SYN-ACK 去重，研究用途；可能产生重复结果和重传。"},
    {"no-dedup-rst", "关闭 RST 去重，研究用途。"},
    {"repeat-synack", "允许重复的 SYN-ACK 结果，通常与 synack-limit/floor 配合。"},
    {"repeat-rst", "允许重复的 RST 结果。"},
    {"synack-limit", "使用 -send-rst 和 -repeat-synack 时，收到达到上限数量的 SYN-ACK 后发送 RST 停止重传；超过上限的 SYN-ACK 不记录。"},
    {"synack-floor", "使用 -repeat-synack 时，少于下限数量的 SYN-ACK 不作为结果记录。"},
    {"record-icmp-id", "记录 ICMP identifier 字段（Echo/Timestamp/port unreachable/TTL exceeded 等）。"},
    {"record-icmp-seqno", "记录 ICMP sequence number 字段。"},
    {"record-banner", "以转义文本记录 banner/响应内容；UDP 下 ICMP port unreachable 内部 IP 头和原始数据也算 banner。"},
    {"record-utf8", "以转义后的合法 UTF-8 形式记录 banner/响应内容。"},
    {"record-data", "以二进制字段记录原始响应/数据；UDP 下 ICMP port unreachable 的内部 IP 头和原始数据也有效。"},
    {"record-data-len", "记录响应 payload/数据的长度；UDP 下 ICMP 内嵌数据也计算。"},
    {"record-ack", "把没有 payload 的 ACK 作为 info 结果记录，用于观察握手/ACK 行为。"},
    {"port-success", "把端口开放结果（包括 zero-window SYN-ACK）标记为 success；默认是 info。"},
    {"port-failure", "把端口关闭结果标记为 failure；默认是 info。"},
    {"ack-success", "把没有 payload 的 ACK 结果标记为 success；默认是 info。"},
    {"with-ack", "收到非零窗口 SYN-ACK 后，先单独发送一个 ACK 完成标准三次握手，再发送带探测数据的段；会增加带宽，但兼容只接受完整握手的服务器，是 ZBanner 的早期模式。"},
    {"probe-zerowin", "零窗口 SYN-ACK 时仍发送探测 payload；结果仍标记为 fake-open/zerowin，仅用于研究 backlog 短暂为零的真实服务。"},
    {"no-rst", "收到 banner 后不发送 RST，研究用途。"},
    {"all-banner", "通过确认所有带数据的接收段（按数据长度去重）来尽量获取完整多段 banner，而不是收到首段后 RST 关闭；可能产生大量结果，需配合窗口/包长/snaplen 限制。"},
    {"all-banner-limit", "all-banner 模式下，收到达到上限数量的带数据 ACK 后发送 RST 关闭；超过上限的段不记录，也不触发 slot 扩展。"},
    {"all-banner-floor", "all-banner 模式下，少于下限数量的带数据 ACK 不记录，也不触发 slot 扩展。"},
    {"ack-ttl", "为三次握手阶段的 ACK 单独设置 TTL，覆盖全局默认值。"},
    {"probe-ttl", "为携带探测数据的 ACK 单独设置 TTL，覆盖全局默认值。"},
    {"ack-banner-ttl", "all-banner 模式下，为携带 banner 数据的 ACK 单独设置 TTL。"},
    {"no-dedup-banner", "关闭带 banner 报文的去重；适合研究目标在 TCP 建立后的重传。若同时关闭 RST，能观察重复数据，但全局 -nodedup 可能造成探测重传。"},
    {"no-dedup-ack", "关闭无 payload ACK 的去重，研究用途。"},
    {"repeat-banner", "允许重复的带 banner ACK 结果。"},
    {"repeat-ack", "允许重复的无数据 ACK 结果。"},
    {"record-icmp-ip-them", "记录 ICMP port unreachable 报文中的目标 IP；它有时不同于外层目标 IP。"},
    {"record-icmp-ip-me", "记录 ICMP port unreachable 报文中的源 IP；它有时不同于外层源 IP。"},
    {"no-port-unreachable", "忽略目标端口的 ICMP port unreachable；UDP 默认用目标范围预校验，极端情况下可能误判，因此提供此开关。"},
    {"no-pre-validate", "不使用目标范围包含关系做连接预校验；注意有些探针没有自己的验证逻辑，完全依赖该预校验。"},
    {"repeat-packets", "允许重复的 UDP 包结果。"},
    {"packet-limit", "使用 -repeat-packets 时，收到达到上限数量的包后停止处理；超过上限的包不记录，也不触发 slot 扩展。"},
    {"packet-floor", "使用 -repeat-packets 时，少于下限数量的包不记录；不会触发 slot 扩展。"},
    {"tcb-mem", "所有接收处理表共享的活跃 TCB 总内存预算（MiB，默认 128）；超过预算的新有状态连接会被丢弃，避免内存无界增长。"},
    {"conn-expire", "设置每条有状态连接的最大存活时间（秒）。"},
    {"record-all-ttl", "调试用途：记录所有段的 IPv4 TTL 或 IPv6 Hop Limit。"},
    {"record-all-ipid", "调试用途：记录所有段的 IPv4 IPID。"},
    {"record-all-win", "调试用途：记录所有段的 TCP 窗口大小。"},
    {"record-all-seqno", "调试用途：记录所有段的 TCP sequence number。"},
    {"record-all-ackno", "调试用途：记录所有段的 TCP acknowledge number。"},
    {"record-all-len", "调试用途：记录所有非 SYN-ACK 段的 TCP payload 长度。"},
    {"port", "Yarrp 通过 'o:' 端口类型指定 TTL 范围，例如 -p o:1-32；该值表示 TTL 范围而不是传统目标端口。注意路径中间设备压力，合理设置范围。"},
    {"init-target-port", "设置 TTL=1 时的初始 UDP 目标端口；实际端口随 TTL 递增。默认 33434。注意初始端口 + TTL 不能超过 65535。"},
    {"init-source-port", "设置 TTL=1 时的初始 UDP 源端口；实际源端口随 TTL 递减，用于判断响应归属。默认从 40000-60000 随机。注意初始端口 - TTL 不能下溢。"},
    {"fixed-source-port", "为所有 Yarrp UDP 包使用固定源端口；默认源端口随 TTL 变化，初始值从 40000-60000 随机。"},
    {"no-record-status", "不输出解析出的 HTTP status code、reason 和 HTTP 版本。"},
    {"no-record-headers", "不输出解析出的 HTTP 响应头；原始响应仍可按其它参数记录。"},
    {"record-body", "记录解析出的 HTTP body（受 --max-body 限制）；未开启时只输出长度/头部等元数据。"},
    {"max-body", "记录/保留 HTTP body 的最大字节数，默认 4096。"},
    {"method", "替换 HTTP 请求行中的默认 GET 方法。"},
    {"url", "替换 HTTP 请求行中的默认 / 路径。"},
    {"version", "替换 HTTP 请求行中的默认 HTTP/1.0 版本。"},
    {"host", "在 HTTP 请求头中添加 Host 字段。"},
    {"dynamic-host", "根据目标地址动态添加 Host（IPv4 为 IP，IPv6 加方括号），适合按 IP 扫描 vhost。"},
    {"user-agent", "替换 HTTP 请求头中的 User-Agent；HTTP/2 请求中表示 user-agent 头的值。"},
    {"payload", "在 HTTP 请求头后追加 payload，并自动添加匹配长度的 Content-Length；需要自行设置合适的 Content-Type，通常还应把 method 改为 POST。"},
    {"cookie", "添加 Cookie 请求头；即使已有 Cookie 字段也会追加。"},
    {"header", "以 name:value 形式替换已有 HTTP 请求头，或不存在时插入；不能替换请求行中的 method/url/version。示例：--header Accept:image/gif 或 --header[Accept] image/gif。"},
    {"remove", "删除第一个匹配的 HTTP 请求头；Cookie 等可重复字段可能需要多次删除。"},
    {"keyword", "设置响应关键字匹配：在选定范围（all/headers/body）内做字面量查找，匹配成功记为 success；与 --regex 互斥。关键字匹配不依赖 PCRE2。"},
    {"match-scope", "匹配范围：all（整个响应，默认）、headers（头部）或 body（响应体）。"},
    {"regex", "设置响应匹配正则：匹配成功记为 success，而不是报告所有协议结果。"},
    {"case-insensitive", "关键字/正则匹配是否忽略大小写。"},
    {"include-newlines", "正则中是否允许/匹配换行。"},
    {"banner-floor", "all-banner 模式下少于该数量的带 banner ACK 不记录，也不触发 slot 扩展。"},
    {"match-whole-response", "匹配到前一段内容后继续匹配整个响应，而不是立即关闭连接；通常配合 all-banner/whole-banner 使用。"},
    {"whole-page", "在连接超时前获取整个页面，而不只取第一段 banner。"},
    {"probe-index", "只发送指定的一个 JARM 探针（1..10）。这是调试用途：结果只有一个 part，不是完整 JARM 指纹。"},
    {"first-probe", "轮换十个 JARM 探针，使标准探针 N（1..10）最先发送；仍发送全部十个。首个 SYN 是 N，收到可接受回复后其余九个按 N+1..10,1..N-1 批量发送。jarm_slot 保留标准编号，因此聚合与发送顺序无关。默认 1；例如 --first-probe 7 的发送顺序是 7,8,9,10,1,2,3,4,5,6。"},
    {"starttls", "在 TLS 前完成明文 STARTTLS 升级：smtp（EHLO/STARTTLS）、imap（a001 STARTTLS）、pop3（STLS）或 ftp（AUTH TLS）。探针处理服务器问候、发送升级命令，升级成功后才开始 TLS；证书/cipher/版本和子探测都在升级后的 TLS 内运行。失败输出 starttls error。示例：-subprobe close-state --starttls smtp --dump-cert-details。"},
    {"subprobe", "必需的 state 子探测；只有 TLS 握手成功（以及 STARTTLS 升级成功）后才初始化，并在加密流内运行。只取证书时使用 close-state。"},
    {"after-tls", "在已经建立的 TLS/STARTTLS 流中运行子探测：跳过明文 greeting，直接发送协议能力命令或 StartupMessage。"},
    {"subprobe-arg", "向 state 子探测传递参数；字符串在 TLS 握手/STARTTLS 升级后由子探测自己的参数表解析。嵌套引号最容易出错，优先使用不含空格的单 token，例如 -subprobe-arg --path=/h2；只有值确实包含空格时才使用双/单引号。"},
    {"sni", "ClientHello 中发送的 TLS SNI 主机名。目标通常是 IP，因此这是对整个运行统一设置的单个主机名；留空则不发送 SNI。适合一批 IP 都属于同一 CDN/vhost 的场景。"},
    {"alpn", "逗号/空格分隔的 ALPN 协议列表，例如 h2,http/1.1；顺序保留，留空则不发送 ALPN 扩展。QUIC 探针默认使用 h3。"},
    {"ssl-keylog", "把 TLS 密钥日志（SSLKEYLOGFILE 格式）记录为 INFO，便于 Wireshark 解密。"},
    {"dump-version", "把协商的 SSL/TLS 版本记录为 INFO。"},
    {"dump-cipher", "把 SSL/TLS 协商的 cipher suite 记录为 INFO（输出协议编号）。"},
    {"dump-cert-details", "输出结构化证书与 TLS 字段：cert_subject、cert_issuer、cert_not_before、cert_not_after、cert_serial、cert_signature_algorithm、cert_public_key、cert_public_key_bits、cert_san、tls_version、tls_cipher、tls_alpn。需要握手成功；支持 --starttls 后的 TLS。只取证书可配合 -subprobe close-state。"},
    {"dump-cert", "把服务器 X.509 证书链按 base64 记录为 INFO；适合后续离线解析。"},
    {"dump-subject", "把 X.509 证书的 subject 记录为 INFO。"},
    {"fail-handshake", "把 TLS 握手失败输出为 FAILED；默认是 INFO。"},
    {"graceful-tls-close", "研究开关：子探测要求关闭时，先发送 TLS close_notify 再发 RST。会增加一个往返/报文，不适合普通扫描，默认仍是立即 RST。"},
    {"record-raw", "记录原始响应字节：QUIC 下是整个 UDP 响应，HTTP/2 下是服务器帧字节；Handshake 响应可能较大。"},
    {"req-name", "指定 DNS 查询名称，例如 www.google.com。"},
    {"req-type", "指定 DNS 查询类型，例如 A、AAAA、PTR。"},
    {"ptr-request", "按给定 IP 设置 PTR 查询类型和反向查询名，是 --req-type PTR 的便捷封装。"},
    {"recursive-desired", "设置 DNS RD（Recursion Desired）标志，要求目标 DNS 服务器递归解析。"},
    {"all-answer", "输出全部 answer 记录，而不是默认只输出第一条。"},
    {"all-authority", "输出全部 authority 记录，而不是默认只输出第一条。"},
    {"all-additional", "输出全部 additional 记录，而不是默认只输出第一条。"},
    {"script", "指定要加载的 Lua 探测脚本路径。"},
    {"string", "设置自定义 hello 字符串（发送前解码），会覆盖其他参数设置的 hello 数据。"},
    {"base64-string", "设置 Base64 编码的自定义 hello 数据，解码后发送，会覆盖其他 hello 参数。"},
    {"nmap-string", "设置 nmap 探针格式的字符串，解码后作为 hello 数据，会覆盖其他 hello 参数。"},
    {"file", "从文件读取 hello 数据，会覆盖其他 hello 参数。"},
    {"recog-xml", "指定 Recog XML 指纹文件作为匹配源。"},
    {"unprefix", "从所有 Recog 正则头部去掉 ^，用于无法精确截取匹配片段时匹配整个响应；正则可能因此变慢。"},
    {"unsuffix", "从所有 Recog 正则尾部去掉 $，用于无法精确截取匹配片段时匹配整个响应。"},
    {"support-tls13", "使用支持 TLS 1.3 的 ClientHello payload。默认 payload 支持 TLS 1.0-1.2，可从证书/域名做正则匹配，但不能测试 TLS 1.3；启用后若服务器回复加密的 TLS 1.3 ServerHello，则无法再做同样的证书/域名正则匹配。"},
    {"probe-file", "指定 nmap-service-probes 文件用于加载探针。"},
    {"probe-name", "指定 nmap-service-probes 文件中的探针名称，只发送该探针。"},
    {"softmatch", "传入目标端口已知的 softmatch 服务名，让 NmapProbe 选择更精确的探针并只做 hard match；这是无状态模式下对 Nmap 匹配策略的折中。"},
    {"alpn", "QUIC 握手的 ALPN 协议列表（逗号/空格分隔），当前取第一个 token；默认 h3。能力探针与有状态扫描器共用。"},
    {"sni", "QUIC/TLS ClientHello 的 SNI 主机名；目标为 IP 时对整个运行使用同一名字，留空则不发送。"},
    {"max-flows", "quic-state 同时跟踪的最大 flow 数；达到上限后新 flow 丢弃。默认 100000，需结合内存预算设置。"},
    {"flow-timeout", "单个 QUIC flow 的最大存活秒数；超时后释放状态。默认 30 秒。"},
    {"max-udp-payload", "QUIC 允许发送/接收的最大 UDP payload 字节数（1200..65527），默认 1200；同时写入 max_tx_udp_payload_size 和 transport parameter。"},
    {"handshake-timeout", "QUIC 握手总超时秒数（1..120），默认 10；不是单次重传超时。"},
    {"initial-rtt", "QUIC 丢包检测使用的初始 RTT（毫秒，1..60000），默认 100；这是定时器初值，不是测量结果。"},
    {"max-data", "通告的连接级流控上限（字节，1024..16777216），默认 1 MiB；限制对端可发送的数据量。"},
    {"max-stream-data", "通告的单 stream 流控上限（字节，1024..16777216），默认 128 KiB。"},
    {"max-streams", "通告的最大单向 stream 数（1..128），默认 3；HTTP/3 需要 control/QPACK stream，DoQ 通常只需一个。"},
    {"idle-timeout", "通告的 QUIC idle timeout（毫秒，100..3600000），默认 30000；与 flow-timeout 的扫描器回收独立。"},
    {"cc-algo", "QUIC 拥塞控制算法：reno、cubic、bbr 或 bbr2；默认 reno。扫描器仍受全局速率限制。"},
    {"no-cert", "不解析/输出对端证书字段；QUIC/TLS 握手、ALPN 和版本仍输出，减少大证书场景的开销。"},
    {"path", "HTTP/3 请求的 :path，默认 /。"},
    {"authority", "HTTP/3 请求的 :authority；留空时使用目标 IP（IPv6 加方括号）。"},
    {"method", "HTTP/3 请求方法；第一版仅支持 GET。"},
    {"max-body", "结果中保留的 HTTP/3 DATA 最大字节数，默认 4096。"},
    {"record-body", "是否输出保留的 HTTP/3 响应 body；默认开启。"},
    {"header", "附加 HTTP/3 请求头，格式 'name: value'，可重复；不会通过它添加伪头。"},
    {"content-type", "请求 content-type 头的值。"},
    {"data", "内联请求 body，最大 65536 字节；只适用于 POST/PUT/PATCH。"},
    {"data-file", "从文件读取请求 body，最大 65536 字节。"},
    {"max-headers", "保留为结构化字段的响应 header 数（1..32），默认 16；总数始终输出。"},
    {"record-headers", "是否输出结构化响应 header；默认开启。"},
    {"send-banner", "发送的 SSH identification string，必须包含结尾 CRLF；默认是明面 Xtate 标识 SSH-2.0-Xtate_1.0。"},
    {"no-banner", "不输出原始 SSH identification banner。"},
    {"no-software", "不输出 SSH banner 的 software/comment 部分。"},
    {"no-kex", "不解析服务器与 banner 合并发送的 SSH_MSG_KEXINIT。"},
    {"record-kexinit", "额外以二进制字段记录原始 KEXINIT payload。"},
    {"settings-hex", "客户端 SETTINGS 帧 payload 的十六进制（不含 9 字节帧头）；默认空。控制客户端设置，HTTP/2 preface 本身固定。"},
    {"ping-hex", "客户端 PING 帧 payload 的十六进制（最多 8 字节）；默认 Xtate/29，是明面且可关闭的指纹。"},
    {"no-ping", "不发送客户端 PING 帧。"},
    {"all-frames", "解析并报告当前响应中的全部服务器帧，而不只第一帧；h2c/h2 的默认值/上限不同。"},
    {"max-frames", "--all-frames 模式下最多解析的服务器帧数；h2c 默认 4，h2 默认 16。"},
    {"no-settings", "不记录原始 SETTINGS payload。"},
    {"path", "HTTP/2 请求的 :path，默认 /。"},
    {"authority", "HTTP/2 请求的 :authority；留空时使用目标 IP。"},
    {"no-user-agent", "不发送 HTTP/2 user-agent 头。"},
    {"max-data", "保留的 HTTP/2 DATA 最大字节数，默认 4096。"},
    {"no-decode-headers", "不 HPACK 解码响应 HEADERS，只报告原始 HEADERS。"},
    {"compact-mode", "把 time、IP proto、IP 地址和 level 记录为紧凑数字类型而不是字符串，减小结果文件。IPv4 存为 int32，IPv6 存为两个 int64；level 0/1/2 对应 information/failure/success。"},
    {"no-port", "只输出 IP 列表（UDP/SCTP 仍带协议标记）；不会对 IP 去重。"},
    {"database-name", "MongoDB 数据库名，默认 xtate。"},
    {"collection-name", "MongoDB 集合名；默认使用扫描开始时间戳。"},
    {"application-name", "MongoDB profile log 中注册的应用名；默认带版本号的 xtate。"},
    {"insert-bulk", "以批量方式写入 MongoDB，可提高插入性能。"},
    {"bulk-size", "MongoDB 批量插入的每批文档数，默认 200。"},
    {"retry-count", "MongoDB 写入失败后的重试次数，默认 3；0 表示禁用重试。"},
    {"retry-delay", "MongoDB 写入重试间隔（毫秒），默认 1000。"},
    {"rounds", "BlackRock 目标随机化轮数，默认 14；轮数越高分布越好但会增加开销。"},
    {"no-random", "按自然顺序生成目标，不使用 BlackRock 随机化。"},
    {"default-port", "输入流没有端口信息时使用的目标端口；支持 TCP、UDP 的 U:/u: 和 SCTP 的 S:/s:，也支持 O: 非端口范围。"},
    {"ip-file", "从指定文件读取 IP 输入流；默认 stdin。"},
    {"address-file", "从指定文件读取地址输入流；默认 stdin。"},
    {"splitter", "输入流中 IP 与端口范围的分隔字符串，默认空格。"},
};

typedef struct I18nModuleParamOverride {
    const char *module;
    const char *name;
    const char *zh_cn;
} I18nModuleParamOverride;

static const I18nModuleParamOverride i18n_module_param_overrides[] = {
    {"http-state", "all-banner", "连接超时前获取整个响应 banner，而不只第一段；与 ZBanner 的“确认所有段”实现不同。"},
    {"hello-state", "all-banner", "连接超时前获取整个响应 banner，而不只第一段；与 ZBanner 的“确认所有段”实现不同。"},
    {"recog-state", "all-banner", "连接超时前获取整个响应 banner，而不只第一段；与 ZBanner 的“确认所有段”实现不同。"},
    {"http-state", "all-banner-limit", "all-banner 模式下最多记录指定数量的带 banner ACK 段；超过上限的段不记录，也不触发 slot 扩展。"},
    {"hello-state", "all-banner-limit", "all-banner 模式下最多记录指定数量的带 banner ACK 段；超过上限的段不记录，也不触发 slot 扩展。"},
    {"recog-state", "all-banner-limit", "all-banner 模式下最多记录指定数量的带 banner ACK 段；超过上限的段不记录，也不触发 slot 扩展。"},
    {"http-state", "banner-floor", "all-banner 模式下少于该数量的带 banner ACK 段不记录，也不触发 slot 扩展。"},
    {"hello-state", "banner-floor", "all-banner 模式下少于该数量的带 banner ACK 段不记录，也不触发 slot 扩展。"},
    {"recog-state", "banner-floor", "all-banner 模式下少于该数量的带 banner ACK 段不记录，也不触发 slot 扩展。"},
    {"zbanner", "all-banner", "通过确认所有带数据的接收段（按数据长度去重）来尽量获取完整多段 banner，而不是收到首段后 RST 关闭；可能产生大量结果，需配合窗口/包长/snaplen 限制。输出中 banner seqno 是精确 TCP 序号；banner idx（别名 banner dedup_repeat）是该 banner flow 的近似零基去重重复计数，不是 TCP 段序号，排序请用 banner seqno。"},
    {"h2", "user-agent", "HTTP/2 请求的 user-agent 值；默认是带版本的明面 Xtate 标识，可用 --no-user-agent 关闭。"},
    {"h2", "max-frames", "最多解析的响应帧数，默认 16；通常配合 --all-frames。"},
    {"h2", "record-raw", "记录服务器 HTTP/2 原始帧字节（可能较大）。"},
    {"h2", "settings-hex", "客户端 SETTINGS 帧 payload 的十六进制（不含 9 字节帧头）；用于控制客户端设置。"},
    {"h2c", "max-frames", "使用 --all-frames 时最多解析的服务器帧数，默认 4。"},
    {"h2c", "record-raw", "记录服务器完整 HTTP/2 原始响应字节。"},
    {"h2c", "settings-hex", "客户端 SETTINGS 帧 payload 的十六进制（不含 9 字节帧头）；默认空，preface 本身固定。"},
    {"quic-state", "sni", "quic-state 的 TLS SNI 主机名；目标为 IP 时对整个运行使用同一名字，留空则不发送 SNI。"},
    {"quic-state", "alpn", "quic-state 握手的 ALPN 列表，取第一个逗号/空格分隔的协议；默认 h3。注意协商成功不代表已实现 HTTP/3。"},
    {"http3-state", "path", "HTTP/3 请求的 :path，默认 /；只影响应用层请求，不改变 QUIC 目标端口。"},
    {"http3-state", "authority", "HTTP/3 请求的 :authority；留空时使用目标 IP（IPv6 加方括号），与 SNI 独立。"},
    {"http3-state", "method", "HTTP/3 请求方法：GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS，默认 GET。"},
    {"http3-state", "keyword", "HTTP/3 响应关键字匹配（all/headers/body 由 --match-scope 选择）；与 --regex 互斥。"},
    {"http3-state", "match-scope", "HTTP/3 匹配范围：all、headers 或 body，默认 all。"},
    {"h2", "keyword", "HTTP/2 响应关键字匹配（all/headers/body 由 --match-scope 选择）；与 --regex 互斥。"},
    {"h2", "match-scope", "HTTP/2 匹配范围：all、headers 或 body，默认 all。"},
    {"http3-state", "max-body", "结果中保留的 HTTP/3 DATA 最大字节数，默认 4096；超出部分仍计数但不保留。"},
    {"http3-state", "record-body", "是否把保留的 HTTP/3 body 写入结果；默认开启，关闭后只输出长度。"},
    {"http3-state", "header", "附加 HTTP/3 请求头，格式 'name: value'，可重复；不接受伪头。"},
    {"http3-state", "content-type", "请求 content-type 头的值；会额外生成 content-type 字段。"},
    {"http3-state", "data", "内联请求 body，最大 65536 字节；仅 POST/PUT/PATCH 可用。"},
    {"http3-state", "data-file", "从文件读取请求 body，最大 65536 字节；与 --data 互斥。"},
    {"http3-state", "max-headers", "保留为结构化字段的响应 header 数（1..32），默认 16；总数始终输出。"},
    {"http3-state", "record-headers", "是否输出结构化响应 header；默认开启。"},
    {"quic", "sni", "QUIC ClientHello 中可选的 TLS SNI 主机名；目标为 IP 时对整个运行使用同一个名字。"},
    {"quic", "alpn", "QUIC ClientHello 的 ALPN 列表，默认 h3；该能力探针不观察协商后的 ALPN。"},
    {"quic", "record-raw", "记录完整 QUIC UDP 响应字节；Handshake 报文可能较大。"},
    {"tls-state", "sni", "TLS ClientHello 中发送的 SNI 主机名；目标为 IP 时对整个运行使用同一个名字，留空则不发送。"},
    {"tls-state", "alpn", "TLS ClientHello 的 ALPN 列表，例如 h2,http/1.1；顺序保留，留空则不发送。"},
    {"nmap", "softmatch", "目标端口已知的 softmatch 服务名；NmapProbe 用它选择更精确探针并只做 hard match。"},
    {"nmap-udp", "softmatch", "目标端口已知的 softmatch 服务名；NmapUdpProbe 用它选择更精确探针并只做 hard match。"},
    {"tls-hello", "regex", "设置响应匹配正则。TlsHello 只在收到 HANDSHAKE 类型 ServerHello 时匹配，通常用于从证书/域名中提取文本；TLS 1.3 的证书/域名已加密，默认 payload 或 support-tls13 的加密 ServerHello 都无法匹配这些内容。"},
};

const char *i18n_tr_module_param(const char *module, const char *name,
                                  const char *english) {
    if (i18n_language == I18N_ZH_CN && module && name) {
        for (unsigned i = 0;
             i < sizeof(i18n_module_param_overrides) /
                     sizeof(i18n_module_param_overrides[0]);
             i++) {
            if (strcmp(module, i18n_module_param_overrides[i].module) == 0 &&
                strcmp(name, i18n_module_param_overrides[i].name) == 0)
                return i18n_module_param_overrides[i].zh_cn;
        }
    }
    (void)module;
    if (i18n_language != I18N_ZH_CN || !name)
        return i18n_tr(english);
    for (unsigned i = 0;
         i < sizeof(i18n_module_param_help) /
                 sizeof(i18n_module_param_help[0]);
         i++) {
        if (strcmp(name, i18n_module_param_help[i].name) == 0)
            return i18n_module_param_help[i].zh_cn;
    }
    return i18n_tr(english);
}

typedef struct I18nModuleHelpDescEntry {
    const char *name;
    const char *zh_cn;
} I18nModuleHelpDescEntry;

static const I18nModuleHelpDescEntry i18n_module_help_desc[] = {
    {"tcp-syn", "发送 TCP SYN 判断端口状态：收到 SYN-ACK 视为开放，RST 视为关闭。可记录 TTL/Hop Limit、IPv4 IPID、窗口、MSS、序号/确认号，并控制 RST 发送、去重、重复结果、SYN/RST TTL、SYN-ACK 数量上下限。该模块不携带应用层 payload。"},
    {"icmp-echo", "向目标发送 ICMP Echo Request，收到 Echo Reply 视为存活。该模块按主机扫描，不应指定端口；可记录 TTL/IPID、ICMP identifier 和 sequence。"},
    {"icmp-time", "向 IPv4 目标发送 ICMP Timestamp 请求，收到 Timestamp Reply 视为存活。该模块只支持 IPv4，不应指定端口；可记录 IPID、ICMP identifier 和 sequence。"},
    {"arp-req", "在局域网内向广播 MAC 发送 ARP Request，查询目标 IPv4 的 MAC 并输出。IPv6 目标会被忽略，IPv6 邻居发现应使用 ndp-ns。必须使用 --lan-mode，或设置广播/路由器 MAC；该模块不应指定端口。"},
    {"ndp-ns", "向 IPv6 目标（实际是 solicited-node multicast）发送 ICMPv6 Neighbor Solicitation，收到 Neighbor Advertisement 视为存活。必须设置 IPv6 link-local 源地址；建议使用 --fake-router-mac 避免解析非链路本地路由器。该模块不应指定端口。"},
    {"sctp-init", "向目标端口发送 SCTP INIT chunk：收到 INIT-ACK 视为开放，ABORT 视为关闭。可记录 TTL/Hop Limit 和 IPv4 IPID；不建立 SCTP 关联。"},
    {"zbanner", "无状态 TCP banner 扫描：由 cookie 构造完整 TCP 连接，把指定 ProbeModule 的 payload 放在第三个 ACK 中，首个响应包交给该 Probe 解析。适合大规模 banner/服务识别；需要在防火墙中抑制本机 RST。支持记录 ACK/banner/data、all-banner、去重/重复、各类 TTL 和 slot 计划。慢速发送可能触发目标重传。"},
    {"udp", "单包 UDP 扫描：发送 ProbeModule 生成的 UDP payload，收到 UDP 响应视为开放，收到 ICMP port unreachable 视为关闭。无连接状态；默认用目标范围做预校验。支持重复包、数量上下限、ICMP 字段记录和 --no-pre-validate。注意本机可能回 ICMP unreachable，建议配置 firewall 规则。"},
    {"tcp-state", "使用 HLTCP 用户态轻量 TCP 栈建立有状态连接，可获取完整页面、进行多步交互和运行 state 探针，资源开销高于 ZBanner。需要防火墙抑制 RST；默认小窗口会产生较多小包，可调 --tcp-win/--max-pkt-len。TCP 栈是简化实现（少量状态、逐包 ACK），主要面向 TLS banner 等短交互；去重参数不适用。"},
    {"yarrp-echo", "类似 Yarrp 的无状态路由追踪：发送不同 TTL 的 ICMP Echo，接收 Echo Reply 或 TTL/Hop Limit Exceeded，离线重建路径。TTL 范围通过 O: 端口语法指定；所有 target/TTL 组合随机发送。注意路径中间设备压力和合理 TTL 范围。"},
    {"yarrp-udp", "类似 Yarrp 的无状态 UDP 路由追踪：发送不同 TTL 的 UDP 包，接收 ICMP Port Unreachable 或 TTL/Hop Limit Exceeded，离线重建路径。TTL 范围通过 O: 端口语法指定；注意路径设备压力和合理 TTL 范围。"},
    {"null", "不保存任何结果，适合调试和基准测试。"},
    {"http", "发送用户可配置的 HTTP 请求并保存响应。默认请求为 GET / HTTP/1.0，带 User-Agent 和 Accept: */*；可设置 method/url/version/header/cookie/payload/remove/dynamic-host，并用正则把匹配响应当作成功。依赖 PCRE2。"},
    {"http-state", "HttpProbe 的有状态版本，通过 HLTCP 发送可配置 HTTP 请求并保存响应，可运行在 TLS 之上。默认请求、参数和正则匹配与 http 相同；注意 HTTP/1 请求解析在 TLS 内运行。依赖 PCRE2。"},
    {"echo", "向目标 UDP 端口发送 4 字节随机数据，收到包含该数据的响应即视为有效。可用于发现 UDP echo 服务或通过 ICMP port unreachable 判断主机存活；不提供协议级验证。"},
    {"get-state", "发送最小 HTTP GET（GET / HTTP/1.0\\r\\n\\r\\n），快速取得 HTTP 响应；主要用于测试需要 state 类型探针的 ScanModule，不进行完整 HTTP 解析。"},
    {"jarm", "发送 10 个 Salesforce JARM 1.0 ClientHello 变体。默认第一个请求是标准探针 1（TLS 1.2、全 cipher 正序、全 ALPN、supported_versions 1.2、扩展逆序）；收到可接受 TLS 回复后，其余 9 个探针批量发送，不逐个等待响应。--first-probe N 轮换首个探针，发送顺序为 N,N+1..10,1..N-1；jarm_slot 始终保留标准探针编号，因此聚合与顺序无关。--probe-index 只发一个探针，是调试用途，不能得到完整 JARM 指纹。依赖 OpenSSL。"},
    {"tls-state", "基于 HLTCP 和 OpenSSL BIO 的 TLS 中间层，必须配合 tcp-state 和 state 类型子探测。支持直接 TLS，也支持 --starttls smtp/imap/pop3/ftp：先完成明文问候和升级命令，再在同一 TCP 连接上握手。握手成功后可输出版本、cipher、证书/证书细节、ALPN，并在 TLS 内初始化子探测；子探测看不到明文 STARTTLS 交换。只取证书时可用 close-state。TLS 1.0-1.3 兼容性设置不适用于现代证书验证。依赖 OpenSSL。"},
    {"quic", "发送一个合法 QUIC v1 Initial（至少 1200 字节），内含 TLS 1.3 ClientHello、X25519 key share、ALPN h3 和 QUIC transport parameters，并根据无状态 UDP cookie 派生唯一 client SCID。解析首个 long-header 响应，分类 Version Negotiation、Retry、Initial 或 Handshake，输出 QUIC 版本、CID、token 长度和 payload 长度。该探针只证明 QUIC transport 响应，不完成 QUIC/TLS 握手、不发送 HTTP/3 请求，不能标成 http3。依赖 OpenSSL。"},
    {"quic-state", "有状态 QUIC 传输扫描器：使用原始 IPv4/IPv6/UDP 报文和 ngtcp2/GnuTLS 完成 QUIC v1 握手，Xtate 仍控制源端口、IP/UDP 头、发送节奏、flow 表、超时和输出。握手成功后输出 QUIC 版本、TLS 版本、ALPN 和证书 subject/issuer/SHA256，并可把应用流交给 state 子探针；当前先提供 close-state 证书模式，HTTP/3 和 DoQ 应用探针在其上分层。可配置 ALPN、SNI、UDP payload、握手超时、初始 RTT、流控、idle timeout 和拥塞控制。可选构建：需要 ngtcp2 + GnuTLS。"},
    {"http3-state", "quic-state 之上的 HTTP/3 请求探针：打开 client control/QPACK 流，用 static/literal QPACK 发送一个请求，支持 Huffman 字符串和完整 QPACK static table，解析响应 HEADERS/DATA 并输出 status、结构化 header、body 和总长度。支持 GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS、请求 body、自定义 header，以及 --keyword/--regex 的 all/headers/body 匹配。仍不支持 dynamic QPACK、push、server-initiated stream 和 HTTP/3 CONNECT；必须与 -scan quic-state 一起使用。依赖 ngtcp2/GnuTLS。"},
    {"dns", "向目标 UDP 端口发送指定名称和类型的 DNS 查询并解析回复，适合一次扫描多个 DNS 服务器。支持 A/AAAA/PTR 等类型和递归查询；可输出全部 answer/authority/additional 记录。若未抑制本机 ICMP port unreachable，可能看到重复回复且每次答案不同。"},
    {"lua-tcp", "加载 Lua 脚本作为 TCP 类型探针，便于快速实现/验证想法。脚本需设置 ProbeName、ProbeType、ProbeDesc，并实现 Make_payload、Get_payload_length、Handle_response。属于实验功能，目前对多 tx/rx 线程支持有限；仍必须保证回调线程安全。依赖 Lua 5.3/5.4。"},
    {"lua-udp", "加载 Lua 脚本作为 UDP 类型探针。脚本需设置 ProbeName、ProbeType、ProbeDesc，并实现 Make_payload、Validate_response、Handle_response。属于实验功能，多线程支持有限；依赖 Lua 5.3/5.4。"},
    {"snmp", "向目标 UDP 161 端口发送 SNMP v1/v2c 请求（默认 community public），尝试获取 sysName 和 sysDesc。可获取基本系统信息，但不能可靠证明端口就是 SNMP 服务。"},
    {"hello", "使用用户设置的静态 hello 数据（string/base64/nmap-string/file）发送并报告 banner，可用正则把匹配响应当作成功。未设置 hello 数据时只等待响应。适合快速验证 POC。依赖 PCRE2。"},
    {"hello-udp", "HelloProbe 的 UDP 版本：发送用户设置的静态 hello 数据，并要求响应匹配指定正则后才报告。必须同时设置 hello 数据和 regex；适合 UDP POC。依赖 PCRE2。"},
    {"hello-state", "HelloProbe 的 state 版本：在 HLTCP 上发送静态 hello 数据并报告响应，可工作于 TLS 之上。支持 string/base64/nmap-string/file、banner 记录、all-banner、正则匹配首段或整个响应。未设置 hello 数据时只等待首段响应。依赖 PCRE2。"},
    {"recog", "用用户设置的 hello 数据和 Recog XML 指纹匹配响应，做服务版本识别的概念验证。Recog 指纹常针对 HTML title、HTTP cookie 等局部字段；本探针不生成特定协议请求，因此可用 unprefix/unsuffix 去掉 ^/$ 后匹配整个响应。只输出第一个匹配，XML 中指纹顺序会影响结果。依赖 PCRE2 和 LibXml2。"},
    {"recog-udp", "RecogProbe 的 UDP 版本：发送用户设置的 hello 数据，用 Recog XML 指纹匹配响应，并报告所有匹配项，而不区分响应来源。UDP 无连接，响应归属和重复包需要自行判断；Recog 指纹常针对 HTML title、HTTP cookie 等局部字段，可用 unprefix/unsuffix 去掉 ^/$ 后匹配整个响应。依赖 PCRE2 和 LibXml2。"},
    {"recog-state", "RecogProbe 的 state 版本：在 HLTCP 上发送 hello 数据并用 Recog 指纹匹配响应，可运行于 TLS 之上。支持 all-banner 和 whole-response 匹配；只输出第一个匹配。依赖 PCRE2 和 LibXml2。"},
    {"close-state", "底层连接建立后不做任何交互，直接关闭。适合只关心底层模块（如 tls-state）输出、不需要应用层子探测的场景。"},
    {"tls-hello", "发送一个尽量兼容各 TLS/SSL 版本的 ClientHello，读取首个 ServerHello，识别是否 TLS 及版本，并可用正则匹配证书/域名等文本。单 payload、适合高速扫描；不完成握手。默认 payload 支持 TLS 1.0-1.2，不能验证 TLS 1.3；--support-tls13 使用 TLS 1.3 payload，但 TLS 1.3 的证书/域名已加密，无法做同样正则匹配。依赖 PCRE2。"},
    {"nmap", "加载 nmap-service-probes 文件中的一个探针，发送一次并匹配 TCP 服务/版本。可用 --probe-file 指定文件、--probe-name 指定探针；--softmatch 可传入已有服务提示以提高匹配准确度。它不是完整 Nmap 服务识别，只是研究用单探针匹配。可用 --list-nmap-probes 查看探针。依赖 PCRE2。"},
    {"nmap-udp", "加载 nmap-service-probes 文件中的一个探针，发送一次并匹配 UDP 服务/版本。参数和限制同 nmap；UDP 无连接，需考虑响应归属。依赖 PCRE2。"},
    {"ssh", "读取 SSH 服务器标识 banner，解析 protocol、software/comment，并在服务器把 KEXINIT 与 banner 合并发送时解析十个 KEXINIT name-list。可用 --send-banner 设置客户端标识（默认明面 Xtate），--no-banner/--no-software/--no-kex 控制输出，--record-kexinit 记录原始 KEXINIT。单 slot。"},
    {"h2c", "明文 HTTP/2 prior-knowledge 探针：发送 client preface、可配置 SETTINGS 和 PING，报告服务器帧头、SETTINGS 条目，可选原始帧。默认 PING 是明面 Xtate 指纹，可调整/关闭。它是能力/framing 探针，不是完整 HTTP/2 客户端，也不是 TLS 上的 HTTP/2。"},
    {"mysql", "等待并解析 MySQL 服务器 greeting（protocol/version/connection id/capabilities/charset/auth plugin）；无状态版本不发送任何客户端响应。"},
    {"mysql-state", "有状态 MySQL greeting 探针：读取服务器 greeting 并解析相同字段后关闭，不发送认证或查询。"},
    {"postgres", "发送 PostgreSQL SSLRequest，判断服务器支持/拒绝 TLS；不发送 StartupMessage 或凭据。"},
    {"postgres-state", "发送 SSLRequest；若拒绝 TLS，发送无密码 StartupMessage 并解析认证方式/错误，不发送密码或查询。"},
    {"mongodb", "发送未认证的 MongoDB OP_MSG `hello`，解析 BSON 中的 ok/maxWireVersion/version/primary 状态。"},
    {"smtp", "读取 SMTP 220 banner；不发送 EHLO、STARTTLS 或 AUTH。"},
    {"smtp-state", "读取 220 greeting，发送 EHLO，解析多行能力并报告 STARTTLS/AUTH；不认证、不发送邮件。"},
    {"imap", "读取 IMAP greeting；不发送 CAPABILITY 或登录。"},
    {"imap-state", "读取 IMAP greeting，发送 CAPABILITY，解析能力并报告 STARTTLS；不登录。"},
    {"pop3", "读取 POP3 +OK banner；不发送 CAPA 或认证。"},
    {"pop3-state", "读取 POP3 greeting，发送 CAPA，解析能力并报告 STLS；不发送 USER/PASS。"},
    {"ftp", "读取 FTP 220 banner；不发送 FEAT 或认证。"},
    {"ftp-state", "读取 FTP 220 greeting，发送 FEAT，解析能力并报告 AUTH TLS；不发送 USER/PASS。"},
    {"managesieve", "读取 ManageSieve capability greeting；不发送 STARTTLS 或认证。"},
    {"managesieve-state", "读取 ManageSieve capability greeting，解析 quoted 能力并报告 STARTTLS/SASL；不认证。"},
    {"ipp", "发送未认证 IPP Get-Printer-Attributes 请求，解析 HTTP/IPP 状态；不打印、不创建任务、不认证。"},
    {"ipp-state", "有状态 IPP 探测，可运行在 tcp-state 或 tls-state 上；不打印、不认证。"},
    {"amqp-state", "有状态 AMQP protocol header/Connection.Start 探测；不认证、不打开 channel。"},
    {"pptp-state", "有状态 PPTP 控制连接探测；不建 GRE、不认证。"},
    {"mongodb-state", "有状态 MongoDB OP_MSG hello/BSON 探测，可用于 tls-state 隐式 TLS；不认证、不写入。"},
    {"ipp-state", "有状态 IPP 探测，可运行在 tcp-state 或 tls-state 上；不打印、不认证。"},
    {"amqp", "发送 AMQP 0-9-1 protocol header，解析 Connection.Start 的版本；不认证、不打开 channel。"},
    {"amqp-state", "有状态 AMQP protocol header/Connection.Start 探测；不认证、不打开 channel。"},
    {"pptp", "发送 PPTP Start-Control-Connection-Request，解析 SCCRP 的 result/version；不建 GRE、不认证。"},
    {"pptp-state", "有状态 PPTP 控制连接探测；不建 GRE、不认证。"},
    {"h2", "有状态 HTTP/2 探针，必须通过 tcp-state + tls-state --alpn h2 -subprobe h2 使用。发送 HTTP/2 preface、SETTINGS 和最小 HPACK 请求，解析 SETTINGS、HEADERS（静态/literal HPACK，不支持 Huffman）和 DATA。它不是 h2c；明文 prior knowledge 请用 h2c。依赖 OpenSSL（tls-state）。"},
    {"redis", "发送只读 `INFO server` 请求识别 Redis，解析 redis_version、redis_mode、os 和 role；不发送会修改数据的命令。单 slot。"},
    {"memcached", "发送 `version` 请求识别 Memcached，解析服务器版本行；只读识别，单 slot。"},
    {"ntp", "发送 NTP v4 mode-3 客户端包，校验 originate timestamp，解析 leap/version/mode、stratum、poll/precision、refid 和 root delay/dispersion；不修改服务器时钟。单 slot UDP。"},
    {"mqtt", "发送最小 MQTT 3.1.1 CONNECT（clean session、client id xtate），解析 CONNACK 的 session-present 和 return-code；不发送 publish/subscribe 或凭据。单 slot。"},
    {"socks5", "发送 SOCKS5 no-auth greeting，解析服务器选择的方法；不执行 CONNECT，也不认证。state 探针。"},
    {"telnet", "等待服务器初始 Telnet 数据，输出版本 banner 和首批 IAC WILL/WONT/DO/DONT 选项；不回复终端协商。state 探针。"},
    {"slot-test", "在三个独立 TCP flow 上发送 `slot:<n>\\n`，报告 slot 编号和收到的字节。用于开发和测试 ProbeSlot_Always，不依赖外部库。"},
    {"slot-test-udp", "在三个独立 UDP flow 上发送 `slot:<n>\\n`，报告 slot 编号和收到的字节。用于开发和测试 ProbeSlot_Always，不依赖外部库。"},
    {"text", "把结果以人类可读的文本格式写入指定文件；包含分类、原因和字段，适合直接查看。"},
    {"ndjson", "把结果按 Newline-Delimited JSON（NDJSON/JSONL）写入指定文件。不会主动转换转义字符；部分模块的字段不是标准 JSON 字符串，使用 --no-escape-char 时需自行保证有效性。"},
    {"bson", "把结果按 BSON（Binary JSON）写入指定文件。BSON 可保留完整二进制字段；Xtate 可用 --parse-bson 转成 JSON，也可用 bsondump。依赖 libbson。"},
    {"csv", "把结果按逗号分隔值（CSV）写入指定文件。不会主动转换转义字符；字段中包含逗号/换行时需注意输出格式。"},
    {"list", "只输出 `IP port` 形式的结果，不包含其它字段，便于作为下一阶段输入。UDP/SCTP/其它端口分别带 u:/s:/o: 前缀；--no-port 只输出 IP。"},
    {"mongodb", "把结果写入 MongoDB。支持数据库名、集合名、应用名、批量插入、批量大小、紧凑模式、失败重试次数和重试间隔；写入失败达到上限会标记输出失败并停止扫描，避免静默丢结果。依赖 libmongoc。"},
    {"blackrock", "Masscan 风格的默认目标生成器：对 IP×端口空间做 BlackRock（DES 派生）置换并按分散顺序生成目标，降低目标网络压力。它是 IP 与端口的笛卡尔积，不保持两者的语义关联；--rounds 控制置换轮数，--no-random 使用自然顺序。"},
    {"ip-stream", "从 stdin 或文件流读取 IP 范围（每行不带端口），为每个 IP 范围用 BlackRock 随机选择端口。必须用 -p 指定端口范围，或使用 O:0。流读取会阻塞发送线程，但不会超过配置速率。"},
    {"addr-stream", "从 stdin 或文件流读取 IP/端口范围对（默认用空格分隔），为每一对用 BlackRock 随机选择目标。必须指定 --splitter 可改变分隔符；流读取会阻塞发送线程，但不会超过配置速率。"},
    {"ip-list", "从 stdin 或文件流读取 IP 列表（每行不带端口），为每个 IP 用 BlackRock 随机选择端口。必须指定端口范围或 O:0；流读取会阻塞发送线程，但不超过配置速率。"},
    {"addr-list", "从 stdin 或文件流读取 IP/端口对（默认空格分隔），按行生成目标。可用 --splitter 改变分隔符；流读取会阻塞发送线程，但不超过配置速率。"},
};

typedef struct I18nModuleDescEntry {
    const char *name;
    const char *zh_cn;
} I18nModuleDescEntry;

static const I18nModuleDescEntry i18n_module_desc_help[] = {
    {"tcp-syn", "TCP SYN 扫描，判断端口是否开放。"},
    {"icmp-echo", "ICMP Ping 存活主机发现。"},
    {"icmp-time", "ICMP 时间戳存活主机发现。"},
    {"arp-req", "局域网 ARP 扫描。"},
    {"ndp-ns", "局域网 NDP 邻居发现扫描。"},
    {"sctp-init", "SCTP INIT 端口扫描。"},
    {"zbanner", "使用指定探测模块的无状态 TCP banner 扫描。"},
    {"udp", "单包 UDP 扫描。"},
    {"tcp-state", "有状态 TCP 扫描。"},
    {"yarrp-echo", "无状态 ICMP 路由追踪。"},
    {"yarrp-udp", "无状态 UDP 路由追踪。"},
    {"null", "不发送数据，只等待响应。"},
    {"http", "无状态 HTTP 请求探测。"},
    {"http-state", "有状态 HTTP 请求探测。"},
    {"echo", "4 字节随机 UDP 探测。"},
    {"get-state", "有状态 HTTP GET 调试探测。"},
    {"jarm", "发送 Salesforce JARM 1.0 的 10 个 ClientHello 探针；默认首选探针 1，首个回复后其余探针批量发送。输出 jarm_part/jarm_slot，由 jarm_aggregate.py 聚合。"},
    {"tls-state", "基于 HLTCP 和 OpenSSL BIO 的 TLS 中间层探测；支持 smtp/imap/pop3/ftp STARTTLS，握手后可输出证书/cipher/版本，并在 TLS 内运行 state 子探测。"},
    {"dns", "DNS 记录查询。"},
    {"lua-tcp", "自定义 Lua 无状态 TCP 探测。"},
    {"lua-udp", "自定义 Lua UDP 探测。"},
    {"snmp", "SNMP 扫描并获取主机信息。"},
    {"hello", "无状态自定义 payload 探测。"},
    {"hello-udp", "UDP 自定义 payload 探测。"},
    {"hello-state", "有状态自定义 payload 探测。"},
    {"recog", "无状态 Recog 指纹匹配。"},
    {"recog-udp", "UDP Recog 指纹匹配。"},
    {"recog-state", "有状态 Recog 指纹匹配。"},
    {"close-state", "有状态探测后关闭底层连接。"},
    {"tls-hello", "TLS ServerHello 版本识别与正则匹配。"},
    {"nmap", "使用 nmap 探针识别 TCP 服务。"},
    {"nmap-udp", "使用 nmap 探针识别 UDP 服务。"},
    {"ssh", "读取 SSH 服务标识 banner（单 slot）。"},
    {"h2c", "发送 cleartext h2c preface 并解析帧；不是 TLS 上的 HTTP/2。"},
    {"h2", "基于 HLTCP/TLS ALPN h2 的有状态 HTTP/2 探针。"},
    {"ipp", "IPP Get-Printer-Attributes 识别。"},
    {"ipp-state", "有状态 IPP。"},
    {"amqp-state", "有状态 AMQP。"},
    {"pptp-state", "有状态 PPTP。"},
    {"mongodb-state", "有状态 MongoDB hello/BSON。"},
    {"ipp-state", "有状态 IPP。"},
    {"amqp", "AMQP 0-9-1 Connection.Start 识别。"},
    {"amqp-state", "有状态 AMQP。"},
    {"pptp", "PPTP SCCRQ/SCCRP 识别。"},
    {"pptp-state", "有状态 PPTP。"},

    {"mysql", "读取 MySQL greeting（无状态）。"},
    {"mysql-state", "有状态 MySQL greeting。"},
    {"postgres", "PostgreSQL SSLRequest 能力检查。"},
    {"postgres-state", "PostgreSQL SSL/认证边界。"},
    {"mongodb", "MongoDB OP_MSG hello/BSON 识别。"},
    {"smtp", "读取 SMTP banner（无状态）。"},
    {"smtp-state", "SMTP EHLO 能力探测。"},
    {"imap", "读取 IMAP banner（无状态）。"},
    {"imap-state", "IMAP CAPABILITY 探测。"},
    {"pop3", "读取 POP3 banner（无状态）。"},
    {"pop3-state", "POP3 CAPA 探测。"},
    {"ftp", "读取 FTP banner（无状态）。"},
    {"ftp-state", "FTP FEAT 能力探测。"},
    {"managesieve", "读取 ManageSieve banner。"},
    {"managesieve-state", "ManageSieve 能力探测。"},

    {"redis", "只读 INFO 识别 Redis。"},
    {"memcached", "version 命令识别 Memcached。"},
    {"ntp", "NTP mode-3 请求与结构化响应。"},
    {"mqtt", "MQTT CONNECT/CONNACK 识别。"},
    {"socks5", "SOCKS5 greeting 方法选择。"},
    {"telnet", "读取 Telnet banner 和 IAC 协商。"},
    {"quic", "发送 QUIC v1 Initial，识别 Version Negotiation/Retry/Initial/Handshake；只证明 QUIC transport 响应，不完成 QUIC 握手，也不声称 HTTP/3。"},
    {"quic-state", "原始 UDP + ngtcp2/GnuTLS 的有状态 QUIC 握手与证书扫描。"},
    {"http3-state", "quic-state 上的 HTTP/3 请求；支持 Huffman QPACK、方法和 body。"},
    {"slot-test", "三 slot TCP ProbeSlot_Always 示例。"},
    {"slot-test-udp", "三 slot UDP ProbeSlot_Always 示例。"},
    {"text", "把结果以人类可读的文本格式写入指定文件；包含分类、原因和字段，适合直接查看。"},
    {"ndjson", "以 NDJSON 格式保存结果。"},
    {"bson", "以 BSON 二进制 JSON 格式保存结果。"},
    {"csv", "以 CSV 格式保存结果。"},
    {"list", "保存 IP/端口结果列表。"},
    {"mongodb", "保存结果到 MongoDB。"},
    {"null", "丢弃所有结果，便于调试。"},
    {"blackrock", "默认目标随机化生成器（IP 和端口）。"},
    {"ip-stream", "从 IP 范围流生成目标。"},
    {"addr-stream", "从 IP/端口范围对流生成目标。"},
    {"ip-list", "从 IP 列表生成目标。"},
    {"addr-list", "从 IP/端口对列表生成目标。"},
};

const char *i18n_tr_module_desc(const char *module, const char *english) {
    if (i18n_language != I18N_ZH_CN || !module)
        return i18n_tr(english);
    if (strcmp(module, "null") == 0) {
        if (english && strstr(english, "NullOutput"))
            return "丢弃所有结果，便于调试。";
        return "不发送数据，只等待响应。";
    }
    for (unsigned i = 0;
         i < sizeof(i18n_module_desc_help) / sizeof(i18n_module_desc_help[0]);
         i++) {
        if (strcmp(module, i18n_module_desc_help[i].name) == 0)
            return i18n_module_desc_help[i].zh_cn;
    }
    return i18n_tr(english);
}

const char *i18n_tr_module_help_desc(const char *module, const char *english) {
    if (i18n_language != I18N_ZH_CN || !module)
        return i18n_tr(english);
    if (strcmp(module, "null") == 0) {
        if (english && strstr(english, "NullOutput"))
            return "不保存任何结果，适合调试和基准测试。";
        return "不向目标发送任何数据，只等待服务器 banner；这是无状态模式下成本最低的探测方式。";
    }
    for (unsigned i = 0;
         i < sizeof(i18n_module_help_desc) /
                 sizeof(i18n_module_help_desc[0]);
         i++) {
        if (strcmp(module, i18n_module_help_desc[i].name) == 0)
            return i18n_module_help_desc[i].zh_cn;
    }
    return i18n_tr(english);
}

typedef struct I18nInteractiveCmdEntry {
    const char *name;
    const char *zh_cn;
} I18nInteractiveCmdEntry;

static const I18nInteractiveCmdEntry i18n_interactive_cmds[] = {
    {"run", "使用当前配置执行扫描。"},
    {"set", "设置全局参数，例如 `set key = value`。"},
    {"set-scan", "选择扫描模块。"},
    {"set-probe", "选择探测模块。"},
    {"set-out", "选择输出模块。"},
    {"set-gen", "选择生成模块。"},
    {"echo", "打印当前配置。"},
    {"echo-all", "打印包含默认值的全部配置。"},
    {"show", "打印当前配置（echo 的别名）。"},
    {"clear", "恢复默认配置，保留 seed。"},
    {"update-seed", "更新全局随机种子。"},
    {"unset-scan", "取消当前扫描模块及其参数。"},
    {"unset-probe", "取消当前探测模块及其参数。"},
    {"unset-out", "取消当前输出模块及其参数。"},
    {"unset-gen", "取消当前生成模块及其参数。"},
    {"list-param", "列出全部全局参数及帮助。"},
    {"list-scan", "列出全部扫描模块。"},
    {"list-probe", "列出全部探测模块。"},
    {"list-out", "列出全部输出模块。"},
    {"list-gen", "列出全部生成模块。"},
    {"help-param", "显示指定全局参数的详细帮助。"},
    {"help-scan", "显示指定扫描模块的帮助。"},
    {"help-probe", "显示指定探测模块的帮助。"},
    {"help-out", "显示指定输出模块的帮助。"},
    {"help-gen", "显示指定生成模块的帮助。"},
    {"search-param", "模糊搜索全局参数。"},
    {"search-module", "模糊搜索模块。"},
    {"conf-save", "保存当前配置到指定文件。"},
    {"conf-read", "从指定文件读取配置。"},
    {"conf-recover", "从 recover.conf 读取配置。"},
    {"version", "显示版本信息。"},
    {"help", "显示交互式命令帮助。"},
    {"quit", "保存配置并退出。"},
    {"exit", "不保存配置直接退出。"},
};

const char *i18n_tr_interactive_cmd(const char *cmd, const char *english) {
    if (i18n_language != I18N_ZH_CN || !cmd)
        return english;
    for (unsigned i = 0;
         i < sizeof(i18n_interactive_cmds) / sizeof(i18n_interactive_cmds[0]);
         i++) {
        if (strcmp(cmd, i18n_interactive_cmds[i].name) == 0)
            return i18n_interactive_cmds[i].zh_cn;
    }
    return english;
}

const char *i18n_interactive_help(void) {
    if (i18n_language == I18N_ZH_CN) {
        return "Xtate 交互模式可以逐项设置参数并执行扫描。\n"
               "使用 `set key = value` 设置全局参数，`set-scan`/`set-probe` 等"
               "选择模块。\n"
               "按 <TAB> 查看命令、参数和模块补全；`help-param`/`help-scan` "
               "等查看详细帮助。\n"
               "`run` 执行扫描，`quit` 保存并退出，`exit` 不保存直接退出。\n"
               "配置会自动保存到 `recover.conf`，交互历史会保存在用户目录。\n";
    }
    return "Xtate"
           "'s interactive mode lets you set parameters one by one and run "
           "scans.\n"
           "Use `set key = value` for global params and "
           "`set-scan`/`set-probe`/... for modules.\n"
           "Press <TAB> for commands, params and modules; use "
           "`help-param`/`help-scan`/... for details.\n"
           "`run` starts scanning, `quit` saves and exits, `exit` exits "
           "without saving.\n"
           "Configuration is saved to `recover.conf`; history is kept in your "
           "home directory.\n";
}
