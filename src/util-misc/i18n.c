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
    {"Multi-probe mode: ", "多探测模式："},
    {"Multi-probe count: ", "多探测数量："},
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
    {"seed", "设置目标/端口随机化以及 cookie 生成的全局随机种子。"},
    {"rate", "设置所有发送线程共享的总发包速率（每秒包数）。"},
    {"wait", "发送结束后等待接收回包的秒数，默认 10 秒。"},
    {"forever", "把 --wait 设为很大的值，用于持续接收。"},
    {"shard", "按 x/y 把扫描空间分给多个实例，x 是当前实例编号。"},
    {"tx-thread-count", "设置发送线程数量。"},
    {"rx-handler-count", "设置接收处理线程数量；必须是 2 的幂。"},
    {"d", "用 -d/-dd/-ddd 提高日志级别。"},
    {"interactive-mode", "进入交互式配置和扫描模式。"},
    {"lang", "设置人类可读帮助文本的语言：en 或 zh-CN。"},
    {"version", "打印版本和编译信息。"},
    {"usage", "显示基础用法和示例。"},
    {"help", "显示全部参数的详细帮助。"},
    {"introduction", "显示 Xtate 的设计和工作流程介绍。"},
    {"target-ip", "指定静态 IPv4/IPv6 目标、范围或 CIDR。"},
    {"port", "指定要扫描的 TCP/UDP/SCTP 端口或端口范围。"},
    {"top-port", "从内置常用 TCP 端口列表中加入若干端口。"},
    {"udp-top-port", "从内置常用 UDP 端口列表中加入若干端口。"},
    {"include-file", "从文件读取目标范围列表。"},
    {"exclude", "排除指定的 IP 地址、范围或 CIDR。"},
    {"exclude-port", "排除指定端口或端口范围。"},
    {"exclude-file", "从文件读取要排除的目标范围。"},
    {"target-asn-v4", "按 IPv4 ASN 添加目标。"},
    {"target-asn-v6", "按 IPv6 ASN 添加目标。"},
    {"exclude-asn-v4", "按 IPv4 ASN 排除目标。"},
    {"exclude-asn-v6", "按 IPv6 ASN 排除目标。"},
    {"adapter", "指定用于收发的网卡接口。"},
    {"source-ip", "指定发送报文使用的源 IP。"},
    {"source-port", "指定发送报文使用的源端口或端口范围。"},
    {"source-mac", "指定发送报文使用的源 MAC 地址。"},
    {"router-ip", "指定 IPv4 网关地址。"},
    {"router-mac", "指定网关 MAC 地址。"},
    {"adapter-vlan", "设置发送报文的 VLAN 标签。"},
    {"adapter-snaplen", "设置抓包/接收的 snapshot 长度。"},
    {"lan-mode", "启用局域网模式（ARP/NDP 等链路层扫描）。"},
    {"fake-router-mac", "使用无效的假网关 MAC，跳过 ARP 解析。"},
    {"bypass-os", "绕过本机协议栈，直接收发原始报文。"},
    {"init-ipv4-adapter", "显式初始化 IPv4 原始套接字。"},
    {"init-ipv6-adapter", "显式初始化 IPv6 原始套接字。"},
    {"echo", "把解析后的配置回显到文件或 stdout。"},
    {"debug-if", "打印网卡调试信息。"},
    {"benchmark", "运行目标生成/扫描性能基准。"},
    {"selftest", "运行内置回归自检。"},
    {"list-cidr", "列出 CIDR 形式的扫描目标。"},
    {"list-range", "列出范围形式的目标。"},
    {"list-target", "列出最终解析的目标和端口。"},
    {"list-if", "列出可用的原始网卡接口。"},
    {"help-parameter", "按名称显示单个全局参数的帮助。"},
    {"search-parameter", "模糊搜索全局参数。"},
    {"search-module", "模糊搜索模块。"},
    {"list-nmap-probes", "列出内置的 nmap 探针。"},
    {"parse-bson-file", "把 BSON 结果文件解析成 JSON。"},
    {"store-json-file", "把 NDJSON 结果导入 MongoDB。"},
    {"store-bson-file", "把 BSON 结果导入 MongoDB。"},
    {"mongodb-uri", "设置 MongoDB 连接 URI。"},
    {"mongodb-db-name", "设置 MongoDB 数据库名。"},
    {"mongodb-col-name", "设置 MongoDB 集合名。"},
    {"mongodb-app-name", "设置 MongoDB 应用名。"},
    {"scan-module", "选择扫描模块。"},
    {"list-scan-modules", "列出全部扫描模块。"},
    {"help-scan-module", "显示指定扫描模块的帮助。"},
    {"scan-module-args", "向扫描模块传递参数。"},
    {"probe-module", "选择探测模块。"},
    {"list-probe-modules", "列出全部探测模块。"},
    {"help-probe-module", "显示指定探测模块的帮助。"},
    {"probe-module-args", "向探测模块传递参数。"},
    {"output-module", "选择输出模块。"},
    {"list-output-modules", "列出全部输出模块。"},
    {"help-output-module", "显示指定输出模块的帮助。"},
    {"output-module-args", "向输出模块传递参数。"},
    {"output-file", "设置输出文件名（MongoDB 时为 URI）。"},
    {"append-output", "以追加方式打开输出文件。"},
    {"output-screen", "把成功结果输出到屏幕。"},
    {"show-output", "选择要显示的结果级别。"},
    {"no-show-output", "关闭结果打印。"},
    {"no-escape-char", "关闭输出字符串转义（JSON/CSV 用）。"},
    {"output-as-info", "把成功结果标记为 info 级别。"},
    {"generate-module", "选择目标生成模块。"},
    {"list-generate-modules", "列出全部生成模块。"},
    {"help-generate-module", "显示指定生成模块的帮助。"},
    {"generate-module-args", "向生成模块传递参数。"},
    {"print-status", "启用实时状态栏。"},
    {"ndjson-status", "用 NDJSON 输出状态。"},
    {"no-status", "关闭实时状态栏。"},
    {"packet-ttl", "设置发送报文的 IP TTL。"},
    {"tcp-init-window", "设置初始 TCP 窗口大小。"},
    {"tcp-window", "设置 TCP 接收窗口大小。"},
    {"tcp-wscale", "设置 TCP 窗口缩放因子。"},
    {"tcp-mss", "设置 TCP MSS 值。"},
    {"tcp-sackok", "启用/关闭 TCP SACK 选项。"},
    {"tcp-tsecho", "设置 TCP 时间戳回显选项。"},
    {"packet-trace", "打印每个发送/接收报文的调试信息。"},
    {"bpf-filter", "设置自定义 BPF 过滤器。"},
    {"no-bpf-filter", "关闭模块默认 BPF 过滤器。"},
    {"max-packet-len", "设置接收报文的最大长度。"},
    {"raw-socket", "使用原始套接字发送。"},
    {"sendmmsg", "使用 sendmmsg 批量发送。"},
    {"sendmmsg-batch", "设置 sendmmsg 每批发送数量。"},
    {"sendmmsg-retries", "设置 sendmmsg 重试次数。"},
    {"send-queue", "使用发送队列模式。"},
    {"send-queue-size", "设置发送队列大小。"},
    {"pfring", "使用 PF_RING 高速抓包/发送（Linux）。"},
    {"offline", "离线模式，不实际发送报文。"},
    {"config-file", "从配置文件加载参数。"},
    {"resume-index", "从指定扫描索引恢复。"},
    {"no-resume-file", "不写 resume.conf。"},
    {"meta-filename", "设置扫描元信息输出文件。"},
    {"pcap-filename", "把收到的报文保存为 pcap。"},
    {"no-ansi-control", "关闭 ANSI 控制字符。"},
    {"no-dedup", "关闭接收去重。"},
    {"dedup-win", "设置去重窗口大小。"},
    {"stack-buf-count", "设置协议栈缓冲区数量。"},
    {"dispatch-buf-count", "设置接收分发队列大小。"},
    {"infinite", "无限重复扫描。"},
    {"repeat", "重复扫描次数。"},
    {"static-seed", "使用固定种子（调试用）。"},
    {"no-cpu-bind", "不把线程绑定到 CPU。"},
    {"ip2asn-v4-file", "指定 IPv4 ASN 数据库文件。"},
    {"ip2asn-v6-file", "指定 IPv6 ASN 数据库文件。"},
    {"no-back-trace", "关闭崩溃时的调用栈。"},
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

const char *i18n_tr_module_param(const char *module, const char *name,
                                  const char *english) {
    (void)module;
    (void)name;
    /* Module parameter translations are added in the next catalog batch. */
    return i18n_tr(english);
}
