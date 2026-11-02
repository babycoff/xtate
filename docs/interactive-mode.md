# Interactive mode

**English** · [中文](zh-CN/interactive-mode.md)

Start it with:

```bash
xtate -interactive
# or
xtate -interact
```

## TTY vs script mode

The same command parser is used in both modes.

- **TTY**: banner, line editing, history and `<TAB>` completion.
- **non-TTY** (pipe/file stdin): no banner, no ANSI, no line editor, no
  automatic restart. This is the deterministic mode for scripts and CI.

Example:

```bash
printf 'set rate = 1000\nset-scan tcp-syn\nset-probe null\nquit\n' |
  xtate -interactive
```

In script mode `quit` saves `recover.conf`; `exit` exits without saving.

## Commands

```text
help                 overview + command list
set key = value      set a global parameter
set-scan <module>    choose a scan module
set-probe <module>   choose a probe module
set-out <module>     choose an output module
set-gen <module>     choose a generate module
list-param [filter]  list global parameters, optionally by name token
list-scan/probe/out/gen  list modules
echo / show          print current configuration
show diff            only non-default settings
show all             include defaults
help <command>       help for one interactive command
help-param <name>    detailed global-parameter help
help-scan <module>   module help
run                  run the configured scan
quit                 save and exit
exit                 exit without saving
```

Use `<TAB>` to complete commands, parameter names and module names; the
completion menu also shows concise help. For `set <param> = ...` it completes
known values (`lang`, output levels, flags), module names and file paths
(including `conf-save`/`conf-read`). After selecting a module, the
`*-module-args` parameters complete that module's `--options`.

## History

In TTY mode command history is loaded/saved automatically:

- Linux/macOS: `$HOME/.xtate_history`
- Windows: `%APPDATA%\xtate_history`

History is disabled in non-TTY mode.

## Language

Interactive help follows the normal language setting:

```bash
xtate --lang zh -interactive
```

Command names and parameter names remain stable English identifiers; their
descriptions and hints are translated.

## Current limits

- `run` is foreground: the prompt returns after the scan stops.
- Windows TTY restart-after-scan is not implemented; start interactive mode
  again manually if needed. Linux re-executes with `recover.conf`.
- Completion covers command/module/parameter names, common values and file
  paths; module-argument value completion is still limited.
- `list-param <filter>` matches whole name tokens, not arbitrary substrings.
- In non-TTY mode a scan still needs a real target, privileges and libpcap/Npcap;
  script mode only removes the terminal UI, not the scan requirements.
