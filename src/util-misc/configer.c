#include "configer.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "../xcmd.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

uint64_t conf_parse_int(const char *str) {
    uint64_t result = 0;

    while (*str && isdigit(*str & 0xFF)) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

bool conf_parse_int_checked(const char *str, uint64_t *out) {
    if (!str || !*str || !out)
        return false;
    uint64_t result = 0;
    for (const unsigned char *p = (const unsigned char *)str; *p; p++) {
        if (!isdigit(*p))
            return false;
        unsigned digit = (unsigned)(*p - '0');
        if (result > (UINT64_MAX - digit) / 10)
            return false;
        result = result * 10 + digit;
    }
    *out = result;
    return true;
}

/**
 * a stricter function for determining if something is boolean.
 */
static int conf_bool_value(const char *str) {
    if (str == NULL || str[0] == '\0')
        return 1; /* bare --flag */
    if (isdigit((unsigned char)str[0]))
        return strtoull(str, NULL, 0) == 0 ? 0 : 1;

    if (conf_equals(str, "enable") || conf_equals(str, "enabled") ||
        conf_equals(str, "true") || conf_equals(str, "on") ||
        conf_equals(str, "yes"))
        return 1;
    if (conf_equals(str, "disable") || conf_equals(str, "disabled") ||
        conf_equals(str, "false") || conf_equals(str, "off") ||
        conf_equals(str, "no"))
        return 0;
    return -1;
}

bool conf_is_bool(const char *str) { return conf_bool_value(str) >= 0; }

bool conf_parse_bool(const char *str) {
    int value = conf_bool_value(str);
    return value == 1;
}

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
uint64_t conf_parse_time(const char *value) {
    uint64_t num         = 0;
    unsigned is_negative = 0;

    while (*value == '-') {
        is_negative = 1;
        value++;
    }

    while (isdigit(value[0] & 0xFF)) {
        num = num * 10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
        case 's':
            num *= 1;
            break;
        case 'm':
            num *= 60;
            break;
        case 'h':
            num *= 60 * 60;
            break;
        case 'd':
            num *= 24 * 60 * 60;
            break;
        case 'w':
            num *= 24 * 60 * 60 * 7;
            break;
        default:
            LOG(LEVEL_ERROR, "unknown character\n");
            xcmd_try_reboot();
            exit(1);
    }
    if (num >= 24 * 60 * 60) {
        LOG(LEVEL_ERROR, "value is greater than 1 day\n");
        xcmd_try_reboot();
        exit(1);
    }
    if (is_negative)
        num = 24 * 60 * 60 - num;

    return num;
}

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga",
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
uint64_t conf_parse_size(const char *value) {
    uint64_t num = 0;

    while (isdigit(value[0] & 0xFF)) {
        num = num * 10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
        case 'k': /* kilobyte */
            num *= 1024ULL;
            break;
        case 'm': /* megabyte */
            num *= 1024ULL * 1024ULL;
            break;
        case 'g': /* gigabyte */
            num *= 1024ULL * 1024ULL * 1024ULL;
            break;
        case 't': /* terabyte, 'cause we roll that way */
            num *= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        case 'p': /* petabyte, 'cause we are awesome */
            num *= 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        case 'e': /* exabyte, now that's just silly */
            num *= 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            LOG(LEVEL_ERROR, "unknown character\n");
            xcmd_try_reboot();
            exit(1);
    }
    return num;
}

bool conf_parse_size_checked(const char *value, uint64_t *out) {
    if (!value || !out || !*value)
        return false;
    uint64_t num = 0;
    const char *p = value;
    while (isdigit((unsigned char)*p)) {
        unsigned d = (unsigned)(*p - '0');
        if (num > (UINT64_MAX - d) / 10)
            return false;
        num = num * 10 + d;
        p++;
    }
    while (ispunct((unsigned char)*p) || isspace((unsigned char)*p))
        p++;
    if (*p && num == 0)
        num = 1;
    uint64_t mul = 1;
    switch (tolower((unsigned char)*p)) {
        case '\0':
            break;
        case 'k':
            mul = 1024ULL;
            break;
        case 'm':
            mul = 1024ULL * 1024ULL;
            break;
        case 'g':
            mul = 1024ULL * 1024ULL * 1024ULL;
            break;
        case 't':
            mul = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        case 'p':
            mul = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        case 'e':
            mul = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            return false;
    }
    if (num > UINT64_MAX / mul)
        return false;
    *out = num * mul;
    return true;
}

bool conf_parse_time_checked(const char *value, uint64_t *out) {
    if (!value || !out || !*value)
        return false;
    uint64_t num = 0;
    unsigned negative = 0;
    const char *p = value;
    while (*p == '-') {
        negative = 1;
        p++;
    }
    if (!isdigit((unsigned char)*p))
        return false;
    while (isdigit((unsigned char)*p)) {
        unsigned d = (unsigned)(*p - '0');
        if (num > (UINT64_MAX - d) / 10)
            return false;
        num = num * 10 + d;
        p++;
    }
    while (ispunct((unsigned char)*p) || isspace((unsigned char)*p))
        p++;
    uint64_t mul = 1;
    switch (tolower((unsigned char)*p)) {
        case '\0':
            break;
        case 's':
            mul = 1;
            break;
        case 'm':
            mul = 60;
            break;
        case 'h':
            mul = 60 * 60;
            break;
        case 'd':
            mul = 24 * 60 * 60;
            break;
        case 'w':
            mul = 24 * 60 * 60 * 7;
            break;
        default:
            return false;
    }
    if (num > UINT64_MAX / mul)
        return false;
    num *= mul;
    if (num >= 24 * 60 * 60)
        return false;
    *out = negative ? 24 * 60 * 60 - num : num;
    return true;
}

unsigned conf_char2hex(char c) {
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

int conf_parse_mac(const char *text, macaddress_t *mac) {
    unsigned i;

    for (i = 0; i < 6; i++) {
        unsigned x;
        char     c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c & 0xFF))
            return -1;
        x = conf_char2hex(c) << 4;
        text++;

        c = *text;
        if (!isxdigit(c & 0xFF))
            return -1;
        x |= conf_char2hex(c);
        text++;

        mac->addr[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}

unsigned conf_parse_opt_int(const char *name) {
    const char *p = strchr(name, '[');
    if (p == NULL)
        return 0;
    else
        p++;
    return (unsigned)conf_parse_int(p);
}

char *conf_parse_opt_str(const char *name) {
    const char *p1 = strchr(name, '[');
    const char *p2 = strchr(name, ']');

    if (p1 == NULL || p2 == NULL || p2 <= p1 + 1)
        return NULL;

    char *ret = MALLOC(p2 - p1);
    memcpy(ret, p1 + 1, p2 - p1 - 1);
    ret[p2 - p1 - 1] = '\0';

    return ret;
}

/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 * @param lhs param name in config
 * @param rhs param name from user input
 ***************************************************************************/
bool conf_equals(const char *lhs, const char *rhs) {
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return true; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return false;
        if (*lhs == '\0')
            return true;
        lhs++;
        rhs++;
    }
}

/**
 * @param lhs param name in config
 * @param rhs param name from user input
 */
bool conf_equals_x(const char *lhs, const char *rhs, size_t rhs_length) {
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return true; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return false;
        if (*lhs == '\0')
            return true;
        lhs++;
        rhs++;
        if (--rhs_length == 0)
            return true;
    }
}

static int levenshtein_distance(const char *s1, const char *s2) {
    int   len1 = strlen(s1), len2 = strlen(s2);
    int **dp = MALLOC(sizeof(int *) * (len1 + 1));
    for (int i = 0; i <= len1; i++) {
        dp[i] = MALLOC(sizeof(int) * (len2 + 1));
    }

    for (int i = 0; i <= len1; i++) {
        dp[i][0] = i;
    }
    for (int j = 0; j <= len2; j++) {
        dp[0][j] = j;
    }

    for (int i = 1; i <= len1; i++) {
        for (int j = 1; j <= len2; j++) {
            int cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1);
            dp[i][j] = min(dp[i][j], dp[i - 1][j - 1] + cost);
        }
    }

    int distance = dp[len1][len2];
    for (int i = 0; i <= len1; i++) {
        FREE(dp[i]);
    }
    FREE(dp);
    return distance;
}

static void str2LowerCase(char *str) {
    while (*str) {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

static void rm_special_chars(char *str, const char *chars) {
    char *src = str, *dst = str;
    while (*src) {
        int isSpecial = 0;
        for (int i = 0; chars[i] != '\0'; i++) {
            if (*src == chars[i]) {
                isSpecial = 1;
                break;
            }
        }
        if (!isSpecial) {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

int conf_fuzzy_distance(const char *s1, const char *s2) {
    if (strlen(s1) > 99 || strlen(s2) > 99) {
        LOG(LEVEL_ERROR, "(%s) string length exceeded.\n", __func__);
        return -1;
    }

    char s1_cleaned[100] = {0};
    char s2_cleaned[100] = {0};
    strncpy(s1_cleaned, s1, 100);
    strncpy(s2_cleaned, s2, 100);
    rm_special_chars(s1_cleaned, "-_.");
    rm_special_chars(s2_cleaned, "-_.");
    str2LowerCase(s1_cleaned);
    str2LowerCase(s2_cleaned);

    if (strstr(s1_cleaned, s2_cleaned))
        return 0;

    int distance = levenshtein_distance(s1_cleaned, s2_cleaned);
    return distance;
}

unsigned conf_index_of(const char *str, char c) {
    unsigned i;
    for (i = 0; str[i] && str[i] != c; i++)
        ;
    return i;
}

bool conf_is_int(const char *value) {
    size_t i;

    if (value == NULL)
        return false;

    for (i = 0; value[i]; i++)
        if (!isdigit(value[i] & 0xFF))
            return false;
    return true;
}

bool conf_is_power_of_2(uint64_t x) {
    while ((x & 1) == 0)
        x >>= 1;
    return x == 1;
}

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
bool conf_is_parm_flag(const ConfParam *cp, const char *name) {
    for (size_t i = 0; cp[i].name; i++) {
        if (conf_equals(cp[i].name, name)) {
            return (cp[i].type & Type_FLAG) == Type_FLAG;
        } else {
            size_t j;
            for (j = 0; cp[i].alt_names[j]; j++) {
                if (conf_equals(cp[i].alt_names[j], name)) {
                    return (cp[i].type & Type_FLAG) == Type_FLAG;
                }
            }
        }
    }

    return false;
}

/**
 * @return non-zero if err
 */
int conf_set_one_param(void *conf, ConfParam *cp, const char *name,
                       const char *value) {
    size_t i;

    for (i = 0; cp[i].name; i++) {
        if (conf_equals(cp[i].name, name)) {
            if (Conf_ERR == cp[i].setter(conf, name, value))
                return -1;
            return 0;
        } else {
            size_t j;
            for (j = 0; cp[i].alt_names[j]; j++) {
                if (conf_equals(cp[i].alt_names[j], name)) {
                    if (Conf_ERR == cp[i].setter(conf, name, value))
                        return -1;
                    return 0;
                }
            }
        }
    }

    LOG(LEVEL_ERROR, "(CONF) unknown config option: %s=%s\n", name, value);
    return -1;
}

/**
 * argc and argv do not contain process file name
 * @return non-zero if err
 */
int conf_set_params_from_args(void *conf, ConfParam *cp, int argc,
                              char **argv) {
    int      i;
    unsigned name_length;

    for (i = 0; i < argc; i++) {
        /*
         * -(-)name=value
         * -(-)name:value
         * -(-)name value for Type_ARG
         */
        if (argv[i][0] == '-') {
            unsigned tmp_step = 1;
            /*true:double dashes, false:single dash*/
            if (argv[i][1] == '-')
                tmp_step++;

            const char *argname = argv[i] + tmp_step;
            char        name2[64];
            const char *value;

            value = strchr(&argv[i][2], '=');
            if (value == NULL)
                value = strchr(&argv[i][2], ':');
            if (value == NULL) {
                /*Type_FLAG doesn't carry args*/
                if (conf_is_parm_flag(cp, argname)) {
                    value = "";
                } else {
                    /* Check before incrementing: a trailing --arg has no value. */
                    if (i + 1 >= argc) {
                        LOG(LEVEL_ERROR, "%.*s: missing parameter value\n",
                            (int)strlen(argname), argname);
                        return -1;
                    }
                    value = argv[++i];
                }
                name_length = (unsigned)strlen(argname);
            } else {
                name_length = (unsigned)(value - argname);
                value++;
            }

            if (i >= argc) {
                LOG(LEVEL_ERROR, "%.*s: empty parameter\n", name_length,
                    argname);
                // break;
                return -1;
            }

            if (name_length > sizeof(name2) - 1) {
                LOG(LEVEL_ERROR, "%.*s: name too long\n", name_length, argname);
                return -1;
            }

            memcpy(name2, argname, name_length);
            name2[name_length] = '\0';

            if (conf_set_one_param(conf, cp, name2, value))
                return -1;

            continue;
        }

        if (!isdigit(argv[i][0]) && argv[i][0] != ':' && argv[i][0] != '[') {
            LOG(LEVEL_ERROR, "unknown parameter \"%s\"\n", argv[i]);
            return -1;
        }

        /* If parameter doesn't start with '-', assume it's an
         * IPv4 range
         */
        // xconf_set_parameter(xconf, "range", argv[i]);
    }

    return 0;
}

/**
 * Parse string and set parameters
 * It can handle quotes(ignore single quotes)
 * @param conf config to set params
 * @param cp params
 * @param string whole string contains all params
 * @return 0 if success
 */
int conf_set_params_from_str(void *conf, ConfParam *cp, char *string) {
    int    err = 0;
    int    sub_argc;
    char **sub_argv;

    sub_argv = safe_str_to_args(string, &sub_argc);
    if (!sub_argv) {
        return 1;
    }

    err = conf_set_params_from_args(conf, cp, sub_argc, sub_argv);
    free(sub_argv);
    return err;
}

/**
 * Parse string and set parameters
 * It can handle single quotes(ignore quotes)
 * @param conf config to set params
 * @param cp params
 * @param substring whole string contains all params
 * @return 0 if success
 */
int conf_set_params_from_substr(void *conf, ConfParam *cp, char *substring) {
    int    err = 0;
    int    sub_argc;
    char **sub_argv;

    sub_argv = safe_substr_to_args(substring, &sub_argc);
    if (!sub_argv) {
        return 1;
    }

    err = conf_set_params_from_args(conf, cp, sub_argc, sub_argv);
    free(sub_argv);
    return err;
}


struct ConfigerSelftestConf {
    char     path[64];
    unsigned flag;
    uint64_t number;
};

static ConfRes SET_configer_test_path(void *conf, const char *name,
                                      const char *value) {
    UNUSEDPARM(name);
    struct ConfigerSelftestConf *c = conf;
    if (!value || strlen(value) >= sizeof(c->path))
        return Conf_ERR;
    snprintf(c->path, sizeof(c->path), "%s", value);
    return Conf_OK;
}

static ConfRes SET_configer_test_flag(void *conf, const char *name,
                                      const char *value) {
    UNUSEDPARM(name);
    struct ConfigerSelftestConf *c = conf;
    c->flag = value[0] == '\0' ? 1 : (unsigned)conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_configer_test_number(void *conf, const char *name,
                                        const char *value) {
    UNUSEDPARM(name);
    struct ConfigerSelftestConf *c = conf;
    uint64_t n;
    if (!conf_parse_int_checked(value, &n))
        return Conf_ERR;
    c->number = n;
    return Conf_OK;
}

int configer_selftest(void) {
    int                    errors = 0;
    uint64_t               number = 0;
    struct ConfigerSelftestConf c = {0};
    ConfParam table[] = {
        {"path", SET_configer_test_path, Type_ARG, {0}, NULL, NULL},
        {"flag", SET_configer_test_flag, Type_FLAG, {0}, NULL, NULL},
        {"number", SET_configer_test_number, Type_ARG, {0}, NULL, NULL},
        {0}};

    if (!conf_parse_int_checked("42", &number) || number != 42)
        errors++;
    if (conf_parse_int_checked("4x", &number))
        errors++;
    if (conf_parse_int_checked("", &number))
        errors++;
    if (conf_parse_int_checked("18446744073709551616", &number))
        errors++;

    if (!conf_is_bool("yes") || conf_is_bool("elephant"))
        errors++;
    if (conf_parse_bool("false") || !conf_parse_bool("1"))
        errors++;

    {
        char args[] = "--path=/hello";
        if (conf_set_params_from_str(&c, table, args) != 0 ||
            strcmp(c.path, "/hello") != 0)
            errors++;
    }
    {
        char args[] = "--path";
        if (conf_set_params_from_args(&c, table, 1, (char *[]){args}) == 0)
            errors++;
    }
    {
        char *argv[] = {
            "--this-option-name-is-deliberately-longer-than-sixty-four-"
            "characters-aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "x"};
        if (conf_set_params_from_args(&c, table, 2, argv) == 0)
            errors++;
    }
    {
        if (conf_set_params_from_args(
                &c, table, 4,
                (char *[]){"--path", "/space", "--number", "7"}) != 0 ||
            strcmp(c.path, "/space") != 0 || c.number != 7)
            errors++;
    }
    {
        char  args[] = "--path '/quoted space'";
        int   argc = 0;
        char **argv = safe_substr_to_args(args, &argc);
        if (!argv || argc < 2 || strcmp(argv[1], "/quoted space") != 0) {
            errors++;
        }
        free(argv);
    }
    {
        char args[] = "--flag --number 9";
        if (conf_set_params_from_substr(&c, table, args) != 0 ||
            !c.flag || c.number != 9)
            errors++;
    }
    {
        char args[] = "--path /nested --number 8";
        if (conf_set_params_from_substr(&c, table, args) != 0 ||
            strcmp(c.path, "/nested") != 0 || c.number != 8)
            errors++;
    }
    {
        char *argv[] = {"--flag=false"};
        if (conf_set_params_from_args(&c, table, 1, argv) != 0 || c.flag)
            errors++;
    }
    {
        char *argv[] = {"--path:/colon"};
        if (conf_set_params_from_args(&c, table, 1, argv) != 0 ||
            strcmp(c.path, "/colon") != 0)
            errors++;
    }
    {
        char args[] = "--path=/h2 --max-frames 4";
        if (conf_set_params_from_substr(&c, table, args) == 0)
            errors++; /* max-frames is not in this table */
    }

    if (conf_parse_size("1k") != 1024 || conf_parse_time("2m") != 120)
        errors++;
    {
        uint64_t v = 0;
        if (!conf_parse_size_checked("1k", &v) || v != 1024)
            errors++;
        if (conf_parse_size_checked("12x", &v))
            errors++;
        if (!conf_parse_time_checked("2m", &v) || v != 120)
            errors++;
        if (!conf_parse_time_checked("120s", &v) || v != 120)
            errors++;
    }

    return errors;
}
