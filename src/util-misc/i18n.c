#include "i18n.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
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
#if defined(_WIN32)
        /* Narrow literals are UTF-8; make the Windows console agree. */
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
#endif
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
