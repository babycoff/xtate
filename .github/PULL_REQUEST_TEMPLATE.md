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

- [ ] Linux build/selftest
- [ ] Windows build/selftest (MSVC/ClangCL/MinGW), or not applicable
- [ ] User-visible docs updated in `docs/` and `docs/zh-CN/`
- [ ] No new mandatory dependency
- [ ] No unrelated formatting/reformat churn
- [ ] No secrets, private keys, generated binaries or third-party scan data committed
- [ ] Security-sensitive change? If yes, describe the review and follow `SECURITY.md`

## Notes for reviewers

<!-- Known limitations, follow-ups, performance numbers, or areas needing particular scrutiny. -->
