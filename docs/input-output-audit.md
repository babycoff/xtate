# Input/output module audit

**English** · [中文](zh-CN/input-output-audit.md)

This audit covers target/input parsing and the text, CSV, NDJSON, BSON and
MongoDB output paths. It is a correctness review, not a performance benchmark.

## Findings and fixes

| Area | Finding | Status |
|:---|:---|:---|
| NDJSON | String fields were written with `%s`, so quotes, backslashes and control characters could produce invalid JSON. | Fixed: names/values/classification/reason are JSON-escaped per line. |
| BSON input | A corrupt 4-byte length could request a multi-gigabyte allocation and the allocation result was not checked. | Fixed: 16 MiB document cap and allocation check in `--parse-bson` and Mongo import. |
| Target files | `fgets()` split lines longer than 65535 bytes into multiple lines; the parser could accept the fragments as separate targets. | Fixed: overlong lines are rejected and the rest of the line is discarded. |
| Target files | Read errors after `fgets()` were not checked. | Fixed: `ferror()` is reported. |
| Output filename | Long `--output-file` paths were silently truncated to 255 bytes. | Fixed: rejected with an error. |
| CSV append | The header was written on every append run. | Fixed: header only on a new file. |
| Output close | `fflush()`/`fclose()` failures were ignored. | Fixed: logged for text/CSV/NDJSON/BSON. |
| BSON output | `bson_new()` and `fwrite()` failures were ignored. | Fixed: allocation and write checks. |
| CSV | Classification/reason were unquoted; report strings were not CSV-escaped. | Fixed: every field is quoted, embedded quotes are doubled, and report JSON is CSV-safe. |
| BSON output | BSON append failures were ignored. | Fixed: UTF-8, date, int32/int64, double, bool, binary and OID appends are checked. |
| Mongo output | BSON import insert failures were logged but still counted as success; output document allocation was unchecked. | Fixed: failures return false, allocation is checked, bulk failures are counted. |
| Parser fuzzing | Output escaping and BSON documents had no fuzz target. | Added `json_escape_fuzz` and `bson_doc_fuzz`; both run in `tests/fuzz/run.sh`. |

## Verification performed

```text
pcap replay -> NDJSON: every line parsed by Python json
pcap replay -> CSV: 12 columns, standard csv reader, report columns parse as JSON
pcap replay with quoted/backslash header -> NDJSON and CSV preserve valid JSON
CSV append: one header only
corrupt BSON length 0x7fffffff: rejected before allocation, non-zero exit
target file line > 65535 bytes: rejected with line number
Linux build/selftest: PASS
MSVC build: PASS
json_escape_fuzz: 398k runs / 3s, fuzz smoke passed
bson_doc_fuzz: 3.3M runs / 3s, fuzz smoke passed
```

## Next steps

1. Add a CSV fixture with quotes/newlines in report values (the writer is now RFC4180-style).
2. Add a CSV fixture with raw control characters (JSON escaping fuzz already covers control bytes).
3. Add malformed-input fixtures for BSON and target files.
4. Extend fuzzing to BSON input/output (JSON escaping is covered).
