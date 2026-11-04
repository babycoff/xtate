/**
 * This was originally extracted from masscan's parm config workflow(a little
 * messy...). I updated  and abstracted it into a useful parm configer tool.
 * Some features:
 * - Single or double dash for parm name is valid: `-name` or `--name`
 * - Any dash within parm name is valid: `-na-me` or `--nam-e`
 * - Args can be carried in multiple ways: `-name arg`, `-name:arg`, `-name=arg`
 * - Parm name can carry sub str or int: `-name[2] arg` or `-name[hello] arg`,
 *   this should be further parsed by parse_opt_xxx funcs.
 *
 * Modified and Created by Alvin Chen 2024
 */
#ifndef CONFIGER_H
#define CONFIGER_H

#include <stdint.h>

#include "../target/target-ipaddress.h"

typedef enum Config_RES {
    Conf_OK,
    Conf_ERR,
} ConfRes;

typedef enum ConfigParam_TYPE {
    Type_ARG  = 0, /*may carry args like `--parm arg` or `--parm=arg`*/
    Type_FLAG = 1, /*only a single flag, even can be --parm=false*/
} ConfType;

/**
 * @param conf where parameters would be set
 * @param name param name
 * @param value param value
 * @return enum ConfigRes or 0 in echo mode.
 */
typedef ConfRes (*CONFIG_SET_PARAM)(void *conf, const char *name,
                                    const char *value);

typedef struct ConfigParam {
    const char      *name;
    CONFIG_SET_PARAM setter;
    ConfType         type;
    const char      *alt_names[8];
    const char      *help_text;  /*set NULL if it's not a normal prarameter*/
    const char      *short_hint; /*concise version of help, could be NULL*/
} ConfParam;

bool conf_is_bool(const char *str);
bool conf_is_int(const char *value);
bool conf_is_power_of_2(uint64_t x);

uint64_t conf_parse_time(const char *value);
uint64_t conf_parse_size(const char *value);
bool     conf_parse_time_checked(const char *value, uint64_t *out);
bool     conf_parse_size_checked(const char *value, uint64_t *out);
int      conf_parse_mac(const char *text, macaddress_t *mac);
uint64_t conf_parse_int(const char *str);
bool     conf_parse_int_checked(const char *str, uint64_t *out);
bool     conf_parse_bool(const char *str);

int configer_selftest(void);

unsigned conf_char2hex(char c);

unsigned conf_parse_opt_int(const char *name);
char    *conf_parse_opt_str(const char *name);

bool conf_is_parm_flag(const ConfParam *cp, const char *name);

bool     conf_equals(const char *lhs, const char *rhs);
bool     conf_equals_x(const char *lhs, const char *rhs, size_t rhs_length);
unsigned conf_index_of(const char *str, char c);

/**
 * Get the edit distance of two param name. Our edit distance will ignore
 * case and some special chars like "-", "_" and "."
 * Also, if s2 is substring, the distance will be zero.
 *
 * @param s1 param of config
 * @param s2 param by user inputing
 */
int conf_fuzzy_distance(const char *s1, const char *s2);

int conf_set_one_param(void *conf, ConfParam *cp, const char *name,
                       const char *value);
int conf_set_params_from_args(void *conf, ConfParam *cp, int argc, char **argv);
int conf_set_params_from_str(void *conf, ConfParam *cp, char *string);
int conf_set_params_from_substr(void *conf, ConfParam *cp, char *substring);

#endif