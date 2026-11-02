## Summary

<!-- What changed and why? Link the issue with "Fixes #123" if applicable. -->

## Changes

- 

## Verification

<!-- Paste exact commands and results. Sanitize addresses/secrets. -->

```text
# Linux
cmake --build build -j
./build/xtate --selftest

# Windows (if applicable)
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Yes

# Relevant extras (large-batch replay, failure suite, sanitizer, pcap replay, ...)
```

## Compatibility

- [ ] Tier 0 on my platform: Linux GCC **or** Windows MSVC build + selftest
- [ ] Tier 1: affected checks I could run from `docs/testing.md`; unavailable environments are noted
- [ ] Relevant focused suite(s) run (`tests/i18n`, `tests/interactive`, `tests/interactive/tty`, `tests/large-batch`)
- [ ] Compile warnings did not increase
- [ ] Optional dependencies remain optional
- [ ] User-visible docs updated in `docs/` and `docs/zh-CN/`
- [ ] No new mandatory dependency
- [ ] No unrelated formatting/reformat churn
- [ ] No secrets, private keys, generated binaries or third-party scan data committed
- [ ] Security-sensitive change? If yes, describe the review and follow `SECURITY.md`

## Notes for reviewers

<!-- Known limitations, follow-ups, performance numbers, or areas needing particular scrutiny. -->
