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
printf 'set rate = 100\nset-scan tcp-syn\nset-probe null\nquit\n' |
  xtate -interactive
```

In TTY mode `quit` saves `recover.conf` (and `exit` leaves without saving).
In script/non-TTY mode `quit` also writes `recover.conf`; `exit` does not.

## Commands

```text
help                 overview + command list
run                  run the configured scan
check                validate the current configuration without sending packets
set key = value      set a global parameter
set-scan <module>    choose a scan module
set-probe <module>   choose a probe module
set-subprobe <module> choose the nested probe (only with a subprobe-capable probe)
set-subprobe-arg <args> set the nested probe's arguments (single-quoted as one value)
history clear        delete the saved command history
set-out <module>     choose an output module
set-gen <module>     choose a generate module
echo                 print current configuration
show                 alias of echo
show diff            only non-default settings
show all             include defaults (same as echo-all)
echo-all             print all configuration including defaults
clear                reset configuration to defaults (keeps `seed`)
update-seed          replace the global seed with a new random value
unset-scan           unset the scan module and its args
unset-probe          unset the probe module and its args
unset-out            unset the output module and its args
unset-gen            unset the generate module and its args
list-param [filter]  list global parameters, optionally by name token
list-scan            list scan modules
list-probe           list probe modules
list-out             list output modules
list-gen             list generate modules
help <command>       help for one interactive command
help-param <name>    detailed help for one global parameter
help-scan <module>   scan-module help
help-probe <module>  probe-module help
help-out <module>    output-module help
help-gen <module>    generate-module help
search-param <text>  fuzzy search global parameters
search-module <text> fuzzy search all module registries
conf-save <file>     save the current configuration
conf-read <file>     load a configuration file
conf-recover         load `recover.conf`
version              print the Xtate version
quit                 save to `recover.conf` (TTY mode) and exit
exit                 exit without saving
```

Use `<TAB>` to complete commands, parameter names and module names; the
completion menu also shows concise help. For `set <param> = ...` it completes
known values (`lang`, output levels, flags), module names and file paths
(including `conf-save`/`conf-read`). After selecting a module, the
`*-module-args` parameters complete that module's `--options`.

## Scan/probe compatibility and check

`set-scan` clears an incompatible probe and prints a warning; `set-probe`
rejects a probe that the selected scan engine cannot carry. This mirrors the
CLI/MCP validation, including the `quic-state`/`tls-state` and
`tcp-state`/`http3-state` restrictions.

Run `check` before `run` to validate the selected modules, probe combination and
rate without sending packets. It prints a short configuration summary; target
and route checks still belong to the CLI `--check` / GUI preflight.

## Subprobes

`set-subprobe` and `set-subprobe-arg` are only useful when the selected probe
has a nested probe, currently `tls-state`. Both commands warn when used
otherwise. The subprobe must be a state probe; TCP/UDP probes, `tls-state`
itself and `http3-state` are rejected. The argument value is stored as one
single-quoted string, for example:

```text
set-scan tcp-state
set-probe tls-state
set-subprobe close-state
set-subprobe-arg --max-body=4096 --method=POST
```

This is equivalent to `-probe-arg "-subprobe close-state -subprobe-arg '--max-body=4096 --method=POST'"`.

## Rate

`set rate = <number>` accepts any positive floating-point value, including
fractions (`0.5` sends one packet every two seconds) and multi-million rates.
Zero, negatives and non-numeric values are rejected. The interactive mode has
no GUI-style rate cap. The browser GUI's 1–10000 limit is an interface safety
limit only.

## History

In TTY mode command history is loaded/saved automatically:

- Linux/macOS: `$HOME/.xtate_history`
- Windows: `%APPDATA%\xtate_history`

History is disabled in non-TTY mode. The line editor keeps the most recent 256
entries; `history clear` deletes the saved file and clears the in-memory list.

## Language

Interactive help follows the normal language setting:

```bash
xtate --lang zh -interactive
```

Command names and parameter names remain stable English identifiers; their
descriptions and hints are translated.

## Current limits

- `run` is foreground: the prompt returns after the scan stops.
- Windows TTY restart-after-scan is not supported. Xtate prints an explicit
  notice after the scan; start `xtate -interactive` again manually. Linux
  re-executes with `recover.conf`.
- Completion covers command/module/parameter names, common values and file
  paths; module-argument value completion is still limited.
- `list-param <filter>` matches whole name tokens, not arbitrary substrings.
- In non-TTY mode a scan still needs a real target, privileges and libpcap/Npcap;
  script mode only removes the terminal UI, not the scan requirements.
- Windows Chinese TTY output uses a scoped UTF-8 console code page and restores
  it on normal exit / Ctrl-C; redirected output remains UTF-8.
