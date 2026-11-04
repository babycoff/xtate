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
    {"target-ip", "指定静态 IPv4/IPv6 目标、范围、CIDR 或分量范围；单个 token 最多 4 个范围组成笛卡尔积，上限 1,048,576 个地址。"},
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

typedef struct I18nModuleParamEntry {
    const char *name;
    const char *zh_cn;
} I18nModuleParamEntry;

static const I18nModuleParamEntry i18n_module_param_help[] = {
    {"ack-banner-ttl", "设置携带 banner 的 ACK 报文 TTL。"},
    {"ack-success", "把收到 ACK 视为成功并记录。"},
    {"ack-ttl", "设置发送 ACK 的 TTL。"},
    {"address-file", "从文件读取地址目标列表。"},
    {"all-additional", "记录 DNS 响应的全部 additional 记录。"},
    {"all-answer", "记录 DNS 响应的全部 answer 记录。"},
    {"all-authority", "记录 DNS 响应的全部 authority 记录。"},
    {"all-banner", "允许接收多段 banner，而不是只取第一段。"},
    {"all-banner-floor", "设置多段 banner 的最小段数。"},
    {"all-banner-limit", "设置多段 banner 的最大段数。"},
    {"alpn", "设置 TLS ALPN 协议列表。"},
    {"path", "设置 HTTP/2 请求的 :path。"},
    {"authority", "设置 HTTP/2 请求的 :authority；留空使用目标 IP。"},
    {"user-agent", "设置 HTTP/2 user-agent（默认 Xtate 版本，明面指纹）。"},
    {"no-user-agent", "不发送 HTTP/2 user-agent。"},
    {"max-data", "设置保留的 HTTP/2 DATA 最大字节数。"},
    {"no-decode-headers", "不解析 HPACK 响应 HEADERS，只保留原始内容。"},
    {"send-banner", "设置要发送的 SSH 标识字符串（需包含 CRLF）。"},
    {"no-record-status", "不输出解析出的 HTTP status/reason/version。"},
    {"no-record-headers", "不输出解析出的 HTTP 响应头。"},
    {"record-body", "记录解析出的 HTTP body（受 --max-body 限制）。"},
    {"max-body", "设置记录的 HTTP body 最大字节数。"},
    {"no-banner", "不输出 SSH 标识 banner。"},
    {"no-software", "不输出 SSH 软件/注释部分。"},
    {"no-kex", "不解析合并报文中的 KEXINIT。"},
    {"record-kexinit", "额外记录原始 KEXINIT payload。"},
    {"settings-hex", "设置 HTTP/2 SETTINGS 帧的十六进制 payload。"},
    {"ping-hex", "设置 HTTP/2 PING 帧的十六进制 payload（默认 Xtate/29）。"},
    {"no-ping", "不发送 HTTP/2 PING 帧。"},
    {"all-frames", "解析并输出响应中的全部 HTTP/2 帧。"},
    {"max-frames", "设置最多解析的 HTTP/2 帧数。"},
    {"no-settings", "不记录原始 HTTP/2 SETTINGS payload。"},
    {"record-raw", "记录完整 HTTP/2 原始响应。"},
    {"application-name", "设置 MongoDB 应用名。"},
    {"banner-floor", "设置需要接收的 banner 最小数量。"},
    {"base64-string", "使用 Base64 编码的自定义探测字符串。"},
    {"bulk-size", "设置 MongoDB 批量写入大小。"},
    {"case-insensitive", "正则匹配时忽略大小写。"},
    {"collection-name", "设置 MongoDB 集合名。"},
    {"compact-mode", "使用紧凑的 BSON/MongoDB 字段格式。"},
    {"tcb-mem", "设置所有接收线程共用的活跃 TCB 总内存预算（MiB）。"},
    {"conn-expire", "设置 TCP 状态连接的过期秒数。"},
    {"cookie", "设置 HTTP Cookie 头。"},
    {"database-name", "设置 MongoDB 数据库名。"},
    {"default-port", "设置默认目标端口。"},
    {"dump-cert", "输出 TLS 证书信息。"},
    {"dump-cert-details", "输出结构化证书与 TLS 字段：cert_subject、cert_issuer、cert_not_before、cert_not_after、cert_serial、cert_signature_algorithm、cert_public_key、cert_public_key_bits、cert_san、tls_version、tls_cipher、tls_alpn。需要握手成功；支持 --starttls 后的 TLS。只取证书可配合 -subprobe close-state。"},
    {"dump-cipher", "输出 TLS 协商的加密套件。"},
    {"dump-subject", "输出 TLS 证书主题。"},
    {"dump-version", "输出 TLS 协议版本。"},
    {"dynamic-host", "根据目标动态生成 HTTP Host 头。"},
    {"fail-handshake", "把 TLS 握手失败标记为失败结果。"},
    {"fail-zerowin", "把零窗口 SYN-ACK 视为失败。"},
    {"file", "从文件读取探测字符串。"},
    {"fixed-source-port", "使用固定源端口。"},
    {"graceful-tls-close", "发送 TLS close_notify 后再关闭连接。"},
    {"header", "添加或覆盖 HTTP 头。"},
    {"host", "设置 HTTP Host 头。"},
    {"include-newlines", "允许探测字符串包含换行。"},
    {"init-source-port", "设置初始源端口。"},
    {"init-target-port", "设置初始目标端口。"},
    {"insert-bulk", "使用 MongoDB 批量插入。"},
    {"ip-file", "从文件读取 IP 目标列表。"},
    {"match-whole-response", "对整个响应做匹配，而不只匹配 banner。"},
    {"method", "设置 HTTP 请求方法。"},
    {"nmap-string", "使用 nmap 风格的自定义探测字符串。"},
    {"no-dedup-ack", "关闭 ACK 去重。"},
    {"no-dedup-banner", "关闭 banner 去重。"},
    {"no-dedup-rst", "关闭 RST 去重。"},
    {"no-dedup-synack", "关闭 SYN-ACK 去重。"},
    {"no-port", "输出中隐藏端口。"},
    {"no-port-unreachable", "忽略 ICMP 端口不可达。"},
    {"no-pre-validate", "跳过探测前校验。"},
    {"no-random", "关闭目标/端口随机化。"},
    {"no-rst", "不主动发送 RST。"},
    {"packet-floor", "设置每轮最少发包数量。"},
    {"packet-limit", "设置每轮最多发包数量。"},
    {"payload", "设置自定义 HTTP/探测 payload。"},
    {"port-failure", "把指定端口结果标记为失败。"},
    {"port-success", "把指定端口结果标记为成功。"},
    {"probe-file", "指定 nmap 探针文件。"},
    {"probe-index", "只发送指定的一个 JARM 探针（1..10）。这是调试用途，结果只有一个 part，不是完整 JARM 指纹。"},
    {"probe-name", "只使用指定名称的 nmap 探针。"},
    {"probe-ttl", "设置探测报文 TTL。"},
    {"probe-zerowin", "把零窗口探测响应视为有效。"},
    {"ptr-request", "把 DNS 请求作为 PTR 反向查询。"},
    {"recog-xml", "指定 Recog XML 指纹文件。"},
    {"record-ack", "记录 ACK 标志。"},
    {"record-ackno", "记录 TCP ACK 序号。"},
    {"record-all-ackno", "记录全部 ACK 序号。"},
    {"record-all-ipid", "记录全部 IPID。"},
    {"record-all-len", "记录全部报文长度。"},
    {"record-all-seqno", "记录全部 TCP 序号。"},
    {"record-all-ttl", "记录全部 TTL。"},
    {"record-all-win", "记录全部 TCP 窗口。"},
    {"record-banner", "记录 banner 内容。"},
    {"record-data", "记录原始响应数据。"},
    {"record-data-len", "记录响应数据长度。"},
    {"record-icmp-id", "记录 ICMP ID。"},
    {"record-icmp-ip-me", "记录 ICMP 报文中的本端 IP。"},
    {"record-icmp-ip-them", "记录 ICMP 报文中的对端 IP。"},
    {"record-icmp-seqno", "记录 ICMP 序列号。"},
    {"record-ipid", "记录 IPv4 IPID。"},
    {"record-mss", "记录 TCP MSS 选项。"},
    {"record-seqno", "记录 TCP 序号。"},
    {"record-ttl", "记录 TTL 或 IPv6 Hop Limit。"},
    {"record-utf8", "按 UTF-8 记录 banner。"},
    {"record-win", "记录 TCP 窗口大小。"},
    {"recursive-desired", "设置 DNS RD（递归请求）标志。"},
    {"regex", "设置响应匹配正则。"},
    {"remove", "删除匹配的 HTTP 头。"},
    {"repeat-ack", "允许重复 ACK 结果。"},
    {"repeat-banner", "允许重复 banner 结果。"},
    {"repeat-packets", "设置 UDP 重发包次数。"},
    {"repeat-rst", "允许重复 RST 结果。"},
    {"repeat-synack", "允许重复 SYN-ACK 结果。"},
    {"req-name", "设置 DNS 查询名。"},
    {"req-type", "设置 DNS 查询类型。"},
    {"retry-count", "设置 MongoDB 写入重试次数。"},
    {"retry-delay", "设置 MongoDB 写入重试间隔（毫秒）。"},
    {"rounds", "设置生成模块的轮数。"},
    {"rst-ttl", "设置 RST 报文 TTL。"},
    {"script", "指定 Lua 探测脚本。"},
    {"send-rst", "收到 SYN-ACK 后主动发送 RST。"},
    {"sni", "设置 TLS SNI 主机名。"},
    {"softmatch", "使用 nmap softmatch 规则。"},
    {"splitter", "设置地址列表分隔符。"},
    {"ssl-keylog", "导出 TLS 密钥日志。"},
    {"string", "设置自定义探测字符串。"},
    {"starttls", "在 TLS 前完成明文 STARTTLS 升级：smtp（EHLO/STARTTLS）、imap（a001 STARTTLS）、pop3（STLS）或 ftp（AUTH TLS）。探针处理问候、发送升级命令，升级成功后才开始 TLS；证书/cipher/版本和子探测都在升级后的 TLS 内运行。失败输出 starttls error。示例：-subprobe close-state --starttls smtp --dump-cert-details。"},
    {"first-probe", "轮换十个 JARM 探针，使标准探针 N（1..10）最先发送；仍发送全部十个。首个 SYN 是 N，收到可接受回复后其余九个按 N+1..10,1..N-1 批量发送。jarm_slot 保留标准编号，因此聚合与发送顺序无关。默认 1；例如 --first-probe 7 的发送顺序是 7,8,9,10,1,2,3,4,5,6。"},
    {"subprobe", "必需的 state 子探测；只有 TLS 握手成功（以及 STARTTLS 升级成功）后才初始化，并在加密流内运行。只取证书时使用 close-state。"},
    {"subprobe-arg", "向 state 子探测传递参数；字符串在 TLS 握手/STARTTLS 升级后由子探测自己的参数表解析。嵌套引号最容易出错，优先使用不含空格的单 token，例如 -subprobe-arg --path=/h2；只有值确实包含空格时才使用双/单引号。"},
    {"support-tls13", "声明支持 TLS 1.3。"},
    {"syn-ttl", "设置 SYN 报文 TTL。"},
    {"synack-floor", "设置 SYN-ACK 最少重复次数。"},
    {"synack-limit", "设置 SYN-ACK 最大重复次数。"},
    {"unprefix", "从匹配结果中去掉前缀。"},
    {"unsuffix", "从匹配结果中去掉后缀。"},
    {"url", "设置 HTTP 请求路径/URL。"},
    {"user-agent", "设置 HTTP User-Agent。"},
    {"version", "设置 HTTP 协议版本。"},
    {"whole-page", "记录整个页面而不是单段 banner。"},
    {"with-ack", "在探测中携带 ACK。"},
};

const char *i18n_tr_module_param(const char *module, const char *name,
                                  const char *english) {
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
    {"slot-test", "三 slot TCP ProbeSlot_Always 示例。"},
    {"slot-test-udp", "三 slot UDP ProbeSlot_Always 示例。"},
    {"text", "以文本格式保存结果。"},
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
    for (unsigned i = 0;
         i < sizeof(i18n_module_desc_help) / sizeof(i18n_module_desc_help[0]);
         i++) {
        if (strcmp(module, i18n_module_desc_help[i].name) == 0)
            return i18n_module_desc_help[i].zh_cn;
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
