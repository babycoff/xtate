#include "xcmd.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xconf.h"
#include "util-misc/i18n.h"
#include "version.h"
#include "crossline/crossline.h"
#include "target/target-cookie.h"
#include "scan-modules/scan-modules.h"
#include "generate-modules/generate-modules.h"

#include "util-out/logger.h"
#include "util-out/xprint.h"
#include "util-data/safe-string.h"
#include "util-data/fine-malloc.h"

#ifndef _WIN32
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <io.h>
#include <windows.h>
#endif

#define READLINE_SIZE 65535

static bool _should_recover = false;
static bool _interactive_tty = false;
static bool _interactive_save_on_exit = true;
static bool _interactive_wants_scan = false;
static char _exe_path[256];

static unsigned xcmd_terminal_width(void) {
    unsigned width = 80;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        width = (unsigned)(info.srWindow.Right - info.srWindow.Left + 1);
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        width = ws.ws_col;
#endif
    if (width < 40)
        width = 40;
    if (width > 120)
        width = 120;
    return width;
}

extern ConfParam  config_parameters[];
extern Scanner   *scan_modules_list[];
extern Probe     *probe_modules_list[];
extern Output    *output_modules_list[];
extern Generator *generate_modules_list[];

typedef enum Action_Res {
    ActRes_Next,   /*handle next readline*/
    ActRes_Prefix, /*continue to handle param after prefix*/
    ActRes_Finish, /*let xcmd to exit of readline*/
} ActRes;

/**
 * Do actions for a command.
 * @return false if need to exit interactive cmd mode.
 */
typedef ActRes (*xcmd_action)(void *conf);

typedef struct {
    char       *cmd;
    char       *hint; /*short help*/
    xcmd_action action;
} XCmd;

static ActRes ACT_run(void *conf) {
    XConf *xconf = conf;

    /*Just do scanning while running in interactive mode*/
    xconf->op = Op_Scan;
    _interactive_wants_scan = true;

    return ActRes_Finish;
}

static ActRes ACT_exit(void *conf) {
    char line[128];
    (void)conf;

    if (!_interactive_tty) {
        _interactive_save_on_exit = false;
        return ActRes_Finish;
    }

    printf("Are you sure to exit " XTATE_NAME " without saving conf? [y/N]: ");

    if (NULL == fgets(line, 128, stdin)) {
        LOG(LEVEL_ERROR, "(%s) failed input.\n", __func__);
        return ActRes_Next;
    }

    if ((line[0] == 'y' || line[0] == 'Y') && line[1] == '\n') {
        _interactive_save_on_exit = false;
        return ActRes_Finish;
    }

    return ActRes_Next;
}

static ActRes ACT_conf_recover(void *conf) {
    XConf *xconf = conf;

    int err = xconf_read_conf(xconf, XCONF_DFT_RECOVER_FILENAME);
    if (err) {
        LOG(LEVEL_ERROR, "failed to read configuration from %s.\n",
            XCONF_DFT_RECOVER_FILENAME);
    } else {
        LOG(LEVEL_HINT, "read and load configuration successfully!\n");
    }

    return ActRes_Next;
}

static ActRes ACT_quit(void *conf) {
    char line[128];
    (void)conf;

    if (!_interactive_tty) {
        _interactive_save_on_exit = true;
        return ActRes_Finish;
    }

    printf("Are you sure to save conf and quit " XTATE_NAME "? [y/N]: ");

    if (NULL == fgets(line, 128, stdin)) {
        LOG(LEVEL_ERROR, "(%s) failed input.\n", __func__);
        return ActRes_Next;
    }

    if ((line[0] == 'y' || line[0] == 'Y') && line[1] == '\n') {
        _interactive_save_on_exit = true;
        return ActRes_Finish;
    }

    return ActRes_Next;
}

static ActRes ACT_clear(void *conf) {
    XConf *xconf = conf;
    char   line[128];

    if (!_interactive_tty) {
        xconf_global_refresh(xconf);
        return ActRes_Next;
    }

    printf("Are you sure to clear configuration of " XTATE_NAME "? [y/N]: ");

    if (NULL == fgets(line, 128, stdin)) {
        LOG(LEVEL_ERROR, "(%s) failed input.\n", __func__);
        return ActRes_Next;
    }

    if ((line[0] == 'y' || line[0] == 'Y') && line[1] == '\n') {
        xconf_global_refresh(xconf);
        LOG(LEVEL_HINT, "configuration cleared!\n");
    }

    return ActRes_Next;
}

static ActRes ACT_version(void *conf) {
    xconf_print_version();
    return ActRes_Next;
}

static ActRes ACT_echo(void *conf) {
    XConf *xconf = conf;
    xconf_echo(xconf, stdout);
    return ActRes_Next;
}

static ActRes ACT_echo_all(void *conf) {
    XConf *xconf    = conf;
    xconf->echo_all = 1;
    xconf_echo(xconf, stdout);
    return ActRes_Next;
}


static ActRes ACT_update_seed(void *conf) {
    XConf *xconf = conf;

    uint64_t old = xconf->seed;
    xconf->seed  = get_one_entropy();
    LOG(LEVEL_HINT, "updated seed from %" PRIu64 " to %" PRIu64 "\n", old,
        xconf->seed);
    return ActRes_Next;
}

static ActRes ACT_list_param(void *conf) {
    xconf_print_help();
    return ActRes_Next;
}

static ActRes ACT_list_scan(void *conf) {
    list_all_scan_modules();
    return ActRes_Next;
}

static ActRes ACT_list_probe(void *conf) {
    list_all_probe_modules();
    return ActRes_Next;
}

static ActRes ACT_list_out(void *conf) {
    list_all_output_modules();
    return ActRes_Next;
}

static ActRes ACT_list_gen(void *conf) {
    list_all_generate_modules();
    return ActRes_Next;
}

static ActRes ACT_unset_scan(void *conf) {
    XConf *xconf = conf;

    xconf->scanner = NULL;
    FREE(xconf->scanner_args);
    LOG(LEVEL_HINT, "previous scan module and its args were unsetted.\n");

    return ActRes_Next;
}

static ActRes ACT_unset_probe(void *conf) {
    XConf *xconf = conf;

    xconf->probe = NULL;
    FREE(xconf->probe_args);
    LOG(LEVEL_HINT, "previous probe module and its args were unsetted.\n");
    return ActRes_Next;
}

static ActRes ACT_unset_out(void *conf) {
    XConf *xconf = conf;

    xconf->out_conf.output_module = NULL;
    FREE(xconf->out_conf.output_args);
    LOG(LEVEL_HINT, "previous output module and its args were unsetted.\n");
    return ActRes_Next;
}

static ActRes ACT_unset_gen(void *conf) {
    XConf *xconf = conf;

    xconf->generator = NULL;
    FREE(xconf->generator_args);
    LOG(LEVEL_HINT, "previous generate module and its args were unsetted.\n");
    return ActRes_Next;
}

static ActRes ACT_prefix(void *conf) { return ActRes_Prefix; }

#define PRE_SET_PARAM     "set"
#define PRE_SET_SCAN      "set-scan"
#define PRE_SET_PROBE     "set-probe"
#define PRE_SET_OUT       "set-out"
#define PRE_SET_GEN       "set-gen"
#define PRE_HELP_PARAM    "help-param"
#define PRE_HELP_SCAN     "help-scan"
#define PRE_HELP_PROBE    "help-probe"
#define PRE_HELP_OUT      "help-out"
#define PRE_HELP_GEN      "help-gen"
#define PRE_SEARCH_PARAM  "search-param"
#define PRE_SEARCH_MODULE "search-module"
#define PRE_CONF_SAVE     "conf-save"
#define PRE_CONF_READ     "conf-read"
#define PRE_CONF_RECOVER  "conf-recover"

static ActRes ACT_help(void *conf);

static const XCmd config_cmd[] = {
    {"run", "Do scanning with configured parmas.", ACT_run},
    {PRE_SET_PARAM, "Set a global param of like `set key = value`.",
     ACT_prefix},
    {PRE_SET_SCAN, "Choose a scan module.", ACT_prefix},
    {PRE_SET_PROBE, "Choose a probe module.", ACT_prefix},
    {PRE_SET_OUT, "Choose an output module.", ACT_prefix},
    {PRE_SET_GEN, "Choose a generate module.", ACT_prefix},
    {"echo", "Print current configuration.", ACT_echo},
    {"show", "Print current configuration (alias of echo).", ACT_echo},
    {"echo-all", "Print all configuration includes default settings.",
     ACT_echo_all},
    {"clear", "Refresh configuration to default except `seed`.", ACT_clear},
    {"update-seed", "Update the global seed to a new rand number.",
     ACT_update_seed},
    {"unset-scan", "Unset previous scan module and its args.", ACT_unset_scan},
    {"unset-probe", "Unset previous probe module and its args.",
     ACT_unset_probe},
    {"unset-out", "Unset previous output module and its args.", ACT_unset_out},
    {"unset-gen", "Unset previous generate module and its args.",
     ACT_unset_gen},
    {"list-param", "List all global params and detailed help.", ACT_list_param},
    {"list-scan", "List all scan modules.", ACT_list_scan},
    {"list-probe", "List all probe modules.", ACT_list_probe},
    {"list-out", "List all output modules.", ACT_list_out},
    {"list-gen", "List all generate modules.", ACT_list_gen},
    {PRE_HELP_PARAM, "Print detailed help of a specified global param.",
     ACT_prefix},
    {PRE_HELP_SCAN, "Print detailed help of a specified Scan Module.",
     ACT_prefix},
    {PRE_HELP_PROBE, "Print detailed help of a specified Probe Module.",
     ACT_prefix},
    {PRE_HELP_OUT, "Print detailed help of a specified Output Module.",
     ACT_prefix},
    {PRE_HELP_GEN, "Print detailed help of a specified Generate Module.",
     ACT_prefix},
    {PRE_SEARCH_PARAM,
     "Fuzzy search in all global params of " XTATE_NAME_TITLE_CASE ".",
     ACT_prefix},
    {PRE_SEARCH_MODULE,
     "Fuzzy search in all modules of " XTATE_NAME_TITLE_CASE ".", ACT_prefix},
    {PRE_CONF_SAVE, "Save current configuration to specified file.",
     ACT_prefix},
    {PRE_CONF_READ, "Read and load configuration from specified file.",
     ACT_prefix},
    {PRE_CONF_RECOVER,
     "Read and load configuration from " XCONF_DFT_RECOVER_FILENAME ".",
     ACT_conf_recover},
    {"version", "Print version info of " XTATE_NAME_TITLE_CASE, ACT_version},
    {"help", "Print help information for interactive command mode.", ACT_help},
    {"quit",
     "Quit " XTATE_NAME_TITLE_CASE
     " after saving configurations to " XCONF_DFT_RECOVER_FILENAME ".",
     ACT_quit},
    {"exit", "Exit " XTATE_NAME_TITLE_CASE " directly.", ACT_exit},

    {0}};

static ActRes ACT_help(void *conf) {
    (void)conf;

    xprint(i18n_interactive_help(), 4, xcmd_terminal_width());
    printf("\n%s\n", i18n_tr("Commands:\n"));
    for (unsigned i = 0; config_cmd[i].cmd; i++) {
        printf("  %-16s %s\n", config_cmd[i].cmd,
               i18n_tr_interactive_cmd(config_cmd[i].cmd, config_cmd[i].hint));
    }
    printf("\n");
    return ActRes_Next;
}


/**
 * Handle subcommand for prefix command
 * @return false if need to exit interactive cmd mode.
 */
typedef void (*xcmd_handle)(void *conf, char *subcmd);

typedef struct {
    char                         *prefix;
    xcmd_handle                   handle;
    crossline_completion_callback completion;
} XPrefix;

static void HDL_set(void *conf, char *subcmd) {
    XConf *xconf = conf;
    int    err;
    err = xconf_set_parameter_in_kv(xconf, subcmd, strlen(subcmd));
    if (err == -1) {
        LOG(LEVEL_ERROR, "failed to set the param.\n");
    } else if (err == 1) {
        LOG(LEVEL_HINT, "input was not a command or param conf.\n");
        LOG(LEVEL_HINT, "please set param in \"set key = value\" format.\n");
    } else if (err == 2) {
        LOG(LEVEL_HINT, "invalid param conf format.\n");
        LOG(LEVEL_HINT, "please set param like \"set key = "
                        "value\".\n");
    } else {
        LOG(LEVEL_HINT, "set param successfully.\n");
    }
}

static void HDL_set_scan(void *conf, char *subcmd) {
    XConf *xconf = conf;

    Scanner *scan = get_scan_module_by_name(subcmd);
    if (!scan) {
        LOG(LEVEL_ERROR, "no such scan module named %s\n", subcmd);
        return;
    }

    xconf->scanner = scan;

    LOG(LEVEL_HINT, "set scan module successfully.\n");
}

static void HDL_set_probe(void *conf, char *subcmd) {
    XConf *xconf = conf;

    Probe *probe = get_probe_module_by_name(subcmd);
    if (!probe) {
        LOG(LEVEL_ERROR, "no such probe module named %s\n", subcmd);
        return;
    }

    xconf->probe = probe;

    LOG(LEVEL_HINT, "set probe module successfully.\n");
}

static void HDL_set_out(void *conf, char *subcmd) {
    XConf *xconf = conf;

    Output *out = get_output_module_by_name(subcmd);
    if (!out) {
        LOG(LEVEL_ERROR, "no such output module named %s\n", subcmd);
        return;
    }

    xconf->out_conf.output_module = out;

    LOG(LEVEL_HINT, "set output module successfully.\n");
}

static void HDL_set_gen(void *conf, char *subcmd) {
    XConf *xconf = conf;

    Generator *gen = get_generate_module_by_name(subcmd);
    if (!gen) {
        LOG(LEVEL_ERROR, "no such generate module named %s\n", subcmd);
        return;
    }

    xconf->generator = gen;

    LOG(LEVEL_HINT, "set generate module successfully.\n");
}

static void HDL_help_param(void *conf, char *subcmd) {
    xconf_help_param(subcmd);
}

static void HDL_help_scan(void *conf, char *subcmd) {
    Scanner *scan = get_scan_module_by_name(subcmd);
    if (!scan) {
        LOG(LEVEL_ERROR, "no such scan module named %s\n", subcmd);
        return;
    }

    help_scan_module(scan);
}

static void HDL_help_probe(void *conf, char *subcmd) {
    Probe *probe = get_probe_module_by_name(subcmd);
    if (!probe) {
        LOG(LEVEL_ERROR, "no such probe module named %s\n", subcmd);
        return;
    }

    help_probe_module(probe);
}

static void HDL_help_out(void *conf, char *subcmd) {
    Output *output = get_output_module_by_name(subcmd);
    if (!output) {
        LOG(LEVEL_ERROR, "no such output module named %s\n", subcmd);
        return;
    }

    help_output_module(output);
}

static void HDL_help_gen(void *conf, char *subcmd) {
    Generator *gen = get_generate_module_by_name(subcmd);
    if (!gen) {
        LOG(LEVEL_ERROR, "no such generate module named %s\n", subcmd);
        return;
    }

    help_generate_module(gen);
}

static void HDL_search_param(void *conf, char *subcmd) {
    xconf_search_param(subcmd);
}

static void HDL_search_module(void *conf, char *subcmd) {
    xconf_search_module(subcmd);
}

static void HDL_conf_save(void *conf, char *subcmd) {
    XConf *xconf = conf;

    int err = xconf_save_conf(xconf, subcmd);
    if (err) {
        LOG(LEVEL_ERROR, "failed to save configuration to %s.\n", subcmd);
    } else {
        LOG(LEVEL_HINT, "save configuration successfully!\n");
    }
}

static void HDL_conf_read(void *conf, char *subcmd) {
    XConf *xconf = conf;

    int err = xconf_read_conf(xconf, subcmd);
    if (err) {
        LOG(LEVEL_ERROR, "failed to read configuration from %s.\n", subcmd);
    } else {
        LOG(LEVEL_HINT, "read and load configuration successfully!\n");
    }
}

static void CPL_scan_module(const char              *cmd,
                            crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_GREEN |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; scan_modules_list[i]; i++) {
        if (!strncasecmp(scan_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, scan_modules_list[i]->name, cmd_color,
                i18n_tr_module_desc(
                    scan_modules_list[i]->name,
                    scan_modules_list[i]->short_desc
                        ? scan_modules_list[i]->short_desc
                        : scan_modules_list[i]->desc),
                help_color);
        }
    }
}

static void CPL_probe_module(const char              *cmd,
                             crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_GREEN |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; probe_modules_list[i]; i++) {
        if (!strncasecmp(probe_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, probe_modules_list[i]->name, cmd_color,
                i18n_tr_module_desc(
                    probe_modules_list[i]->name,
                    probe_modules_list[i]->short_desc
                        ? probe_modules_list[i]->short_desc
                        : probe_modules_list[i]->desc),
                help_color);
        }
    }
}

static void CPL_output_module(const char              *cmd,
                              crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_GREEN |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; output_modules_list[i]; i++) {
        if (!strncasecmp(output_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, output_modules_list[i]->name, cmd_color,
                i18n_tr_module_desc(
                    output_modules_list[i]->name,
                    output_modules_list[i]->short_desc
                        ? output_modules_list[i]->short_desc
                        : output_modules_list[i]->desc),
                help_color);
        }
    }
}

static void CPL_generate_module(const char              *cmd,
                                crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_GREEN |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; generate_modules_list[i]; i++) {
        if (!strncasecmp(generate_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, generate_modules_list[i]->name, cmd_color,
                i18n_tr_module_desc(
                    generate_modules_list[i]->name,
                    generate_modules_list[i]->short_desc
                        ? generate_modules_list[i]->short_desc
                        : generate_modules_list[i]->desc),
                help_color);
        }
    }
}

static void CPL_add(const char *word, const char *help,
                     crossline_completions_t *p_completion) {
    crossline_completion_add_color(
        p_completion, word,
        CROSSLINE_FGCOLOR_GREEN | CROSSLINE_FGCOLOR_BRIGHT |
            CROSSLINE_BGCOLOR_DEFAULT,
        help ? help : "", CROSSLINE_COLOR_DEFAULT);
}

static void CPL_path(const char *cmd, crossline_completions_t *p_completion) {
    char token[1024];
    char dir[512];
    const char *base;

    snprintf(token, sizeof(token), "%s", cmd ? cmd : "");
    safe_trim(token, sizeof(token));

    const char *slash = strrchr(token, '/');
    if (!slash)
        slash = strrchr(token, '\\');
    if (slash) {
        size_t n = (size_t)(slash - token) + 1;
        if (n >= sizeof(dir))
            n = sizeof(dir) - 1;
        memcpy(dir, token, n);
        dir[n] = 0;
        base   = token + n;
    } else {
        dir[0] = 0;
        base   = token;
    }

#ifdef _WIN32
    char pattern[1024];
    if (dir[0])
        snprintf(pattern, sizeof(pattern), "%s*", dir);
    else
        snprintf(pattern, sizeof(pattern), "*");

    WIN32_FIND_DATAA fd;
    HANDLE           h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 ||
                strcmp(fd.cFileName, "..") == 0)
                continue;
            if (base[0] && strncasecmp(fd.cFileName, base, strlen(base)) != 0)
                continue;
            char full[1024];
            const char *sep = (dir[0] && dir[strlen(dir) - 1] != '\\') ? "\\" : "";
            snprintf(full, sizeof(full), "%s%s%s", dir, sep, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                size_t used = strlen(full);
                if (used + 2 < sizeof(full)) {
                    full[used]     = '\\';
                    full[used + 1] = 0;
                }
            }
            CPL_add(full, "", p_completion);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    const char *open_dir = dir[0] ? dir : ".";
    DIR        *d        = opendir(open_dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            if (base[0] && strncasecmp(e->d_name, base, strlen(base)) != 0)
                continue;
            char full[2048];
            snprintf(full, sizeof(full), "%s%s", dir, e->d_name);
            struct stat st;
            if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
                size_t used = strlen(full);
                if (used + 2 < sizeof(full)) {
                    full[used]     = '/';
                    full[used + 1] = 0;
                }
            }
            CPL_add(full, "", p_completion);
        }
        closedir(d);
    }
#endif
}

static void CPL_value_add(const char *prefix, const char *word,
                          crossline_completions_t *p_completion) {
    if (!prefix[0] || strncasecmp(word, prefix, strlen(prefix)) == 0)
        CPL_add(word, "", p_completion);
}

static void CPL_value(const char *cmd, crossline_completions_t *p_completion) {
    const char *eq = strchr(cmd, '=');
    if (!eq)
        return;

    char name[128];
    char value[512];
    size_t name_len = (size_t)(eq - cmd);
    if (name_len >= sizeof(name))
        name_len = sizeof(name) - 1;
    memcpy(name, cmd, name_len);
    name[name_len] = 0;
    safe_trim(name, sizeof(name));
    snprintf(value, sizeof(value), "%s", eq + 1);
    safe_trim(value, sizeof(value));

    static const struct {
        const char *name;
        const char *values;
    } table[] = {
        {"lang", "en zh-CN"},
        {"show-output", "failed info success"},
        {"no-show-output", "failed info success"},
        {"scan-module", NULL},
        {"probe-module", NULL},
        {"output-module", NULL},
        {"generate-module", NULL},
        {NULL, NULL}};

    for (unsigned i = 0; table[i].name; i++) {
        if (strcasecmp(name, table[i].name) != 0)
            continue;
        if (!table[i].values) {
            const char *names[128];
            unsigned   count = 0;
            if (strcasecmp(name, "scan-module") == 0) {
                for (unsigned j = 0; scan_modules_list[j] && count < 128; j++)
                    names[count++] = scan_modules_list[j]->name;
            } else if (strcasecmp(name, "probe-module") == 0) {
                for (unsigned j = 0; probe_modules_list[j] && count < 128; j++)
                    names[count++] = probe_modules_list[j]->name;
            } else if (strcasecmp(name, "output-module") == 0) {
                for (unsigned j = 0; output_modules_list[j] && count < 128; j++)
                    names[count++] = output_modules_list[j]->name;
            } else {
                for (unsigned j = 0; generate_modules_list[j] && count < 128; j++)
                    names[count++] = generate_modules_list[j]->name;
            }
            for (unsigned j = 0; j < count; j++)
                CPL_value_add(value, names[j], p_completion);
            return;
        }
        const char *p = table[i].values;
        while (*p) {
            char word[64];
            size_t n = 0;
            while (*p && *p != ' ' && n + 1 < sizeof(word))
                word[n++] = *p++;
            word[n] = 0;
            while (*p == ' ')
                p++;
            CPL_value_add(value, word, p_completion);
        }
        return;
    }

    if (strstr(name, "file") || strcmp(name, "output-file") == 0 ||
        strcmp(name, "include-file") == 0 ||
        strcmp(name, "config-file") == 0 ||
        strcmp(name, "meta-filename") == 0 ||
        strcmp(name, "pcap-filename") == 0 ||
        strcmp(name, "ip2asn-v4-file") == 0 ||
        strcmp(name, "ip2asn-v6-file") == 0) {
        CPL_path(value, p_completion);
        return;
    }

    for (unsigned i = 0; config_parameters[i].name; i++) {
        if (strcasecmp(name, config_parameters[i].name) == 0) {
            if (config_parameters[i].type == Type_FLAG) {
                CPL_value_add(value, "true", p_completion);
                CPL_value_add(value, "false", p_completion);
            }
            return;
        }
    }
}

static void CPL_global_conf(const char              *cmd,
                            crossline_completions_t *p_completion) {
    char              help_buf[2048];
    size_t            help_mas  = sizeof(help_buf);
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_GREEN |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;

    if (strchr(cmd, '=')) {
        CPL_value(cmd, p_completion);
        return;
    }

    for (unsigned i = 0; config_parameters[i].name; i++) {
        bool     matched      = false;
        bool     name_matched = false;
        unsigned j            = 0;

        if (!config_parameters[i].help_text) {
            continue;
        }

        if (!strncasecmp(config_parameters[i].name, cmd, strlen(cmd))) {
            matched      = true;
            name_matched = true;
        } else {
            for (j = 0; config_parameters[i].alt_names[j]; j++) {
                if (!strncasecmp(config_parameters[i].alt_names[j], cmd,
                                 strlen(cmd))) {
                    matched = true;
                    break;
                }
            }
        }

        if (matched) {
            int count = 0;

            if (!name_matched) {
                count += snprintf(&help_buf[count], help_mas - count,
                                  "alias: %s", config_parameters[i].name);
            }

            for (unsigned k = 0; config_parameters[i].alt_names[k]; k++) {

                if (!name_matched && j == k)
                    continue;

                /*first printed param in help */
                if (count == 0) {
                    count += snprintf(&help_buf[count], help_mas - count,
                                      "alias: %s",
                                      config_parameters[i].alt_names[k]);
                } else {
                    count +=
                        snprintf(&help_buf[count], help_mas - count, ", %s",
                                 config_parameters[i].alt_names[k]);
                }

                if (count <= 0)
                    break;
            }

            // if (count > 0) {
            //     count += snprintf(&alias_buf[count], alias_max - count, ".");
            // }
            snprintf(&help_buf[count], help_mas - count, "\n    %s\n",
                     i18n_tr_global_param(
                         config_parameters[i].name,
                         config_parameters[i].short_hint
                             ? config_parameters[i].short_hint
                             : config_parameters[i].help_text));

            /**
             * print alias info as help text
             */
            if (name_matched) {
                crossline_completion_add_color(p_completion,
                                               config_parameters[i].name,
                                               cmd_color, help_buf, help_color);
            } else {
                crossline_completion_add_color(
                    p_completion, config_parameters[i].alt_names[j], cmd_color,
                    help_buf, help_color);
            }
        }
    }
}

static void HDL_help_cmd(void *conf, char *subcmd) {
    (void)conf;
    for (unsigned i = 0; config_cmd[i].cmd; i++) {
        if (strcasecmp(config_cmd[i].cmd, subcmd) == 0) {
            printf("  %-16s %s\n", config_cmd[i].cmd,
                   i18n_tr_interactive_cmd(config_cmd[i].cmd,
                                           config_cmd[i].hint));
            return;
        }
    }
    LOG(LEVEL_ERROR, "no such interactive command: %s\n", subcmd);
}

static void HDL_list_param_filter(void *conf, char *subcmd) {
    (void)conf;
    xconf_print_help_filter(subcmd);
}

static const XPrefix config_prefix[] = {
    {"help", HDL_help_cmd, NULL},
    {"list-param", HDL_list_param_filter, NULL},
    {PRE_SET_PARAM, HDL_set, CPL_global_conf},
    {PRE_SET_SCAN, HDL_set_scan, CPL_scan_module},
    {PRE_SET_PROBE, HDL_set_probe, CPL_probe_module},
    {PRE_SET_OUT, HDL_set_out, CPL_output_module},
    {PRE_SET_GEN, HDL_set_gen, CPL_generate_module},
    {PRE_HELP_PARAM, HDL_help_param, CPL_global_conf},
    {PRE_HELP_SCAN, HDL_help_scan, CPL_scan_module},
    {PRE_HELP_PROBE, HDL_help_probe, CPL_probe_module},
    {PRE_HELP_OUT, HDL_help_out, CPL_output_module},
    {PRE_HELP_GEN, HDL_help_gen, CPL_generate_module},
    {PRE_SEARCH_PARAM, HDL_search_param, NULL},
    {PRE_SEARCH_MODULE, HDL_search_module, NULL},
    {PRE_CONF_SAVE, HDL_conf_save, CPL_path},
    {PRE_CONF_READ, HDL_conf_read, CPL_path},

    {0}};

static void _completion_hook(const char              *cmd,
                             crossline_completions_t *p_completion) {
    /**
     * NOTE: the cmd is original and not trimed.
     */

    unsigned i;
    unsigned prefix_i;
    size_t   cmd_len;
    size_t   prefix_len;
    bool     cmd_matched    = false;
    bool     prefix_matched = false;

    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color =
        CROSSLINE_FGCOLOR_WHITE | CROSSLINE_BGCOLOR_DEFAULT;

    /**
     * Command
     */
    for (i = 0; config_cmd[i].cmd; i++) {
        cmd_len = strlen(cmd);
        if (!strncasecmp(config_cmd[i].cmd, cmd, cmd_len)) {
            cmd_matched = true;
            crossline_completion_add_color(
                p_completion, config_cmd[i].cmd, cmd_color,
                i18n_tr_interactive_cmd(config_cmd[i].cmd, config_cmd[i].hint),
                help_color);
        }
    }

    if (cmd_matched)
        return;

    /**
     * Prefix: find the longest matched prefix cmd
     */
    prefix_len = 0;
    for (i = 0; config_prefix[i].prefix; i++) {
        size_t tmp_len = strlen(config_prefix[i].prefix);
        if (!strncasecmp(config_prefix[i].prefix, cmd, tmp_len) &&
            tmp_len >= prefix_len && cmd[tmp_len] == ' ') {
            prefix_matched = true;
            prefix_i       = i;
            prefix_len     = tmp_len;
        }
    }

    if (prefix_matched && config_prefix[prefix_i].completion) {
        config_prefix[prefix_i].completion(cmd + prefix_len + 1, p_completion);
    }
}

static void xcmd_suggest(const char *line) {
    const char *best      = NULL;
    int         best_dist = 3;

    for (unsigned i = 0; config_cmd[i].cmd; i++) {
        int d = conf_fuzzy_distance(config_cmd[i].cmd, line);
        if (d >= 0 && d < best_dist) {
            best_dist = d;
            best      = config_cmd[i].cmd;
        }
    }
    for (unsigned i = 0; config_prefix[i].prefix; i++) {
        int d = conf_fuzzy_distance(config_prefix[i].prefix, line);
        if (d >= 0 && d < best_dist) {
            best_dist = d;
            best      = config_prefix[i].prefix;
        }
    }
    if (best)
        LOG(LEVEL_HINT, "did you mean `%s`?\n", best);
}

static bool xcmd_handle_line(XConf *xconf, char *line) {
    unsigned i;
    unsigned prefix_idx;
    size_t   prefix_len;
    size_t   line_len;
    bool     cmd_matched;
    bool     prefix_matched;
    ActRes   act_res;

    safe_trim(line, READLINE_SIZE);
    if (line[0] == 0)
        return true;

    line_len = strlen(line);

    cmd_matched = false;
    for (i = 0; config_cmd[i].cmd; i++) {
        if (!strcasecmp(config_cmd[i].cmd, line)) {
            cmd_matched = true;
            break;
        }
    }

    if (cmd_matched) {
        act_res = config_cmd[i].action(xconf);
        if (act_res == ActRes_Finish)
            return false;
        if (act_res == ActRes_Next)
            return true;
        /* ActRes_Prefix: fall through to prefix command handling. */
    }

    prefix_idx     = 0;
    prefix_len     = 0;
    cmd_matched    = false;
    prefix_matched = false;

    for (i = 0; config_prefix[i].prefix; i++) {
        size_t len = strlen(config_prefix[i].prefix);
        if (!strncasecmp(config_prefix[i].prefix, line, len)) {
            prefix_matched = true;
            if (len > prefix_len) {
                prefix_len = len;
                prefix_idx = i;
            }
        }
    }

    if (prefix_matched) {
        if (line_len > prefix_len + 1 && line[prefix_len] == ' ') {
            config_prefix[prefix_idx].handle(xconf, line + prefix_len + 1);
        } else if (line_len == prefix_len) {
            LOG(LEVEL_ERROR,
                "(" XTATE_NAME
                ") need to specify a param for the command.\n");
        }
        return true;
    }

    LOG(LEVEL_ERROR, "(" XTATE_NAME
                     ") unknown input, use <TAB> to get valid commands.\n");
    xcmd_suggest(line);
    return true;
}

static void xcmd_history_path(char *buf, size_t size) {
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (appdata && appdata[0]) {
        snprintf(buf, size, "%s\\xtate_history", appdata);
        return;
    }
    snprintf(buf, size, ".xtate_history");
#else
    const char *home = getenv("HOME");
    if (home && home[0]) {
        snprintf(buf, size, "%s/.xtate_history", home);
        return;
    }
    snprintf(buf, size, ".xtate_history");
#endif
}

void xcmd_interactive_readline(XConf *xconf, const char *exe_path) {
    _interactive_tty = false;
#ifdef _WIN32
    _interactive_tty = _isatty(_fileno(stdin)) != 0;
#else
    _interactive_tty = isatty(fileno(stdin)) != 0;
#endif
    _should_recover        = _interactive_tty;
    _interactive_save_on_exit = _interactive_tty;
    safe_strcpy(_exe_path, 256, exe_path);

    if (_interactive_tty && xconf->have_read_conf) {
        LOG(LEVEL_HINT, "configuration has been recovered.\n");
    } else if (_interactive_tty) {
        printf("\n  %s %s interactive\n", XTATE_NAME_TITLE_CASE,
               XTATE_VERSION);
        xprint(i18n_tr("Type `help` for commands, <TAB> for completion.\n"), 2,
               xcmd_terminal_width());
        xprint(i18n_tr("Use `set` to configure, `run` to scan, `quit` to "
                       "exit.\n"),
               2, xcmd_terminal_width());
        printf("\n");
    }

    char *line = MALLOC(READLINE_SIZE * sizeof(char));
    char  history_path[512];

    if (_interactive_tty) {
        xcmd_history_path(history_path, sizeof(history_path));
        crossline_completion_register(_completion_hook);
        crossline_prompt_color_set(CROSSLINE_FGCOLOR_BRIGHT |
                                   CROSSLINE_FGCOLOR_CYAN |
                                   CROSSLINE_BGCOLOR_DEFAULT);
        crossline_history_load(history_path);
        while (NULL != crossline_readline(XTATE_NAME_ALL_CAPS "> ", line,
                                          READLINE_SIZE)) {
            if (!xcmd_handle_line(xconf, line))
                break;
        }
        crossline_history_save(history_path);
    } else {
        /* Deterministic script mode: no banner, no ANSI, no line editor,
         * no history and no automatic restart after the commands finish. */
        while (fgets(line, READLINE_SIZE, stdin)) {
            if (!xcmd_handle_line(xconf, line))
                break;
        }
    }

    if (_interactive_save_on_exit) {
        int err = xconf_save_conf(xconf, XCONF_DFT_RECOVER_FILENAME);
        if (err) {
            LOG(LEVEL_ERROR, "failed to save configuration to %s.\n",
                XCONF_DFT_RECOVER_FILENAME);
        } else {
            LOG(LEVEL_HINT, "configuration was saved to %s.\n",
                XCONF_DFT_RECOVER_FILENAME);
        }
    }

    FREE(line);

    /* `quit`/`exit`/EOF must leave the program; only `run` falls through to
     * the normal scan path. Without this, non-TTY scripts print the normal
     * startup banner after quitting interactive mode. */
    if (!_interactive_wants_scan)
        exit(0);
}

int xcmd_reboot_for_interact(const char *path, const char *conf) {

#ifdef _WIN32
    return 0;
#else

    if (path == NULL || path[0] == 0) {
        LOG(LEVEL_ERROR, "(%s) invalid executable path.\n", __func__);
        return 1;
    }

    char *path_cp = STRDUP(path);
    char *conf_cp = STRDUP(conf);

    /**
     * Complete command:
     * `[sudo] path -interact [-conf conf]`
     */
    char *args[6] = {0}; /*params with NULL*/

    unsigned i = 0;
    args[i]    = path_cp;
    i++;
    args[i] = "-interact";
    i++;

    if (conf) {
        args[i] = "-conf";
        i++;
        args[i] = conf_cp;
        i++;
    }

    if (execv(path, args)) {
        LOGPERROR("execv");
        FREE(path_cp);
        FREE(conf_cp);
        return -1;
    }

    return 0;

#endif
}

void xcmd_try_reboot() {
    if (_should_recover) {
        if (xcmd_reboot_for_interact(_exe_path, XCONF_DFT_RECOVER_FILENAME)) {
            LOG(LEVEL_ERROR, "failed to recover.\n");
        }
    }
}