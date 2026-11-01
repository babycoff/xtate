#ifndef I18N_H
#define I18N_H

#include <stdbool.h>

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

#endif
