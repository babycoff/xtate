#ifndef I18N_H
#define I18N_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Help/output language for human-facing help text.
 *
 * The catalog is intentionally small and keyed by the English source string:
 * untranslated strings fall back to English. Command-line parameter names,
 * module names, output values and machine-readable fields are never translated.
 */
typedef enum I18nLanguage {
    I18N_EN    = 0,
    I18N_ZH_CN = 1,
} I18nLanguage;

void i18n_init(void);

/** Accepts en/english and zh/zh-CN/zh_CN/cn/chinese. */
bool i18n_set_language(const char *code);

I18nLanguage i18n_get_language(void);
const char  *i18n_language_name(void);

/** Exact-match lookup; returns src unchanged when untranslated or English. */
const char *i18n_tr(const char *src);

/**
 * Translate a global parameter's help by its stable parameter name. Module
 * parameters use i18n_tr_module_param() (module name + parameter name), so
 * descriptions can be added without copying long English sentences as keys.
 */
const char *i18n_tr_global_param(const char *name, const char *english);
const char *i18n_tr_module_param(const char *module, const char *name,
                                  const char *english);

/**
 * Help output helpers.
 *
 * On Windows, Chinese help is written with WriteConsoleW so the console code
 * page is never changed. Redirected output stays UTF-8 bytes.
 */
void i18n_write(const char *data, size_t len);
void i18n_printf(const char *fmt, ...);

#endif
