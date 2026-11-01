# Chinese help and the i18n framework

**English** · [中文](zh-CN/help-i18n.md)

Xtate has a small, dependency-free localization layer for **human-facing help
text**. It is intentionally not a full translation of the binary: command-line
parameter names, module names, result values and machine-readable output stay
in English so scripts and output schemas do not change with the UI language.

## Usage

```bash
xtate --lang zh --help
xtate --lang zh --help-scan tcp-syn
xtate --lang zh --usage
xtate --lang zh --intro
xtate --lang zh --list-scan
xtate --lang en --help
```

The environment variable is also accepted:

```bash
XTATE_LANG=zh ./xtate --usage
```

`--lang` / `--language` accepts `en`, `english`, `zh`, `zh-CN`, `zh_CN`, `cn`
or `chinese`. An unknown value is a command-line error, not a silent fallback,
so a typo cannot masquerade as a successful English run. The default is `en`.

## Design

- **English source strings are the canonical keys.** `i18n_tr()` performs an
  exact lookup in `src/util-misc/i18n.c`; if the string is not in the catalog,
  the English source is returned.
- **Translations cannot silently drift onto the wrong string.** There is no
  fuzzy matching for help text: a changed English sentence simply falls back to
  English until its catalog entry is updated.
- **Only human help text is translated.** Parameter names, module names,
  `classification`/`reason` values, JSON/CSV field names and scan results are
  language-invariant.
- **UTF-8-aware wrapping.** `xprint()` decodes UTF-8 and counts CJK/full-width
  characters as two terminal columns. It also avoids starting a line with
  common closing punctuation such as `。`, `，`, `）` and `！`.
- **Windows console.** On Windows the `zh-CN` path switches the console output
  code page to UTF-8; MSVC/clang-cl builds use `/utf-8` for source and execution
  charsets.

The catalog is deliberately partial. Untranslated parameter/module
descriptions remain English and are still usable; this is a framework for
incremental translation, not a claim that every string has been translated.

## Current coverage

Translated so far:

- welcome/description/author/GitHub/contact chrome;
- usage headings and the common example explanations;
- global help section headings;
- module help labels (`Name`, `Probe Type`, `Description`, …);
- list/search headings;
- the `--lang` parameter itself.

Falling back to English:

- most global and module parameter descriptions;
- module descriptions and short descriptions;
- error messages and log text.

## Adding a translation

Add one entry to `i18n_catalog[]` in `src/util-misc/i18n.c`:

```c
{"Set the language of human-facing help text: en or zh-CN. Untranslated strings fall back to English.",
 "设置人类可读帮助文本的语言：en 或 zh-CN。未翻译的字符串回退到英文。"},
```

The key must match the English source string exactly, including trailing
`\n`. Keep placeholders (`%s`, `%u`, `%d`) in the same order and do not
translate parameter names or result values.

After changing help code, rebuild and check both languages:

```bash
./build/xtate --lang en --help
./build/xtate --lang zh --help
./build/xtate --lang zh --help-scan tcp-syn
./build/xtate --lang zh --usage
./build/xtate --lang nope --version  # must fail

# deterministic checks included in the tree
XTATE_BIN=$PWD/build/xtate bash tests/i18n/test.sh
```

The Windows check should be run in a console that can display UTF-8; the binary
sets the code page itself, but the terminal font still needs CJK glyphs.

## Limitations

- No automatic locale detection; use `--lang` or `XTATE_LANG`.
- No right-to-left or pluralization framework yet.
- Output modules and status lines are not translated; they are part of the
  machine/operations interface.
- A partial catalog is expected. Missing entries are safe English fallbacks,
  not errors.
