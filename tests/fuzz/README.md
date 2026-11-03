# Parser fuzzing

Short libFuzzer smoke tests for the packet preprocessor and the CLI/file target
parser. They complement `--selftest` and the fixed target/parser tests.

## What is covered

| Harness | Target |
|:---|:---|
| `preprocess_fuzz` | `preprocess_frame()` with all supported link types (Ethernet, RAW, SLL, 802.11, radiotap, ...) |
| `target_parse_fuzz` | `target_parse_range()` with arbitrary target-range text |
| `targetset_fuzz` | `targetset_add_ip_str()` and `targetset_add_port_str()` |
| `targetfile_fuzz` | `targetset_parse_file()` line/file tokenizer |

The harnesses stub `LOG` and link only the parser objects. They do not need
Npcap/OpenSSL and do not open sockets or files.

## Requirements

- clang with libFuzzer (`-fsanitize=fuzzer`);
- Linux/macOS shell;
- the C compiler used by the project.

On Debian/Ubuntu:

```bash
sudo apt install clang
```

## Run

```bash
CC=clang bash tests/fuzz/run.sh
```

Optional duration and build/corpus directories:

```bash
FUZZ_SECONDS=60 \
FUZZ_BUILD=/tmp/xtate-fuzz \
FUZZ_WORK_CORPUS=/tmp/xtate-corpus \
CC=clang bash tests/fuzz/run.sh
```

The checked-in `corpus/` directories are seed inputs. Generated inputs go to
`corpus-working/` (ignored by git); the next run starts from both directories.
The Linux CI caches `tests/fuzz/corpus-working/` between runs and uses it as the
long-term corpus, so a later run does not restart from only the seed inputs.

For a longer campaign, set `FUZZ_SECONDS` to minutes and preserve the working
corpus directory. To shrink it periodically:

```bash
FUZZ_SECONDS=1 CC=clang bash tests/fuzz/run.sh   # build binaries
tests/fuzz/build/preprocess_fuzz -merge=1 \
  /tmp/corpus-minimized \
  tests/fuzz/corpus/preprocess tests/fuzz/corpus-working/preprocess
```

The run stops on the first sanitizer finding, writes the reproducer under
`tests/fuzz/artifacts/`, and exits non-zero. A normal run ends with:

```text
fuzz smoke passed
```

The Linux CI runs the 10-second smoke only in the Clang Release job.

## Notes

- This is a smoke fuzz, not a long-running fuzzing campaign.
- For a longer run, set `FUZZ_SECONDS` to minutes and keep the corpus.
- The target-parser harness stubs `targetset_add_ip_str` and `rangelist_sort`
  because `target-parse.c` also contains the file parser. The fuzzer calls only
  `target_parse_range()`.
- Found crashes should become fixed regression cases in `preprocess_selftest`
  or `target_parse_selftest`, not just committed corpus files.
