# ASan + UBSan smoke

Builds a clang Debug binary with AddressSanitizer and UndefinedBehaviorSanitizer,
runs `--selftest`, then the six offline pcap matrices through the sanitized
binary.

```bash
CC=clang SANITIZER_BUILD=/tmp/xtate-sanitize bash tests/sanitizers/run.sh
```

Leak detection is disabled for the selftest because the project's existing
selftest deliberately leaves some global allocations alive; ASan/UBSan memory
and undefined-behavior checks remain enabled.

Set `SANITIZER_SKIP_PCAP=1` to run only the build and selftest.
