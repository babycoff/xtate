# JSON contract validation

```bash
python3 -m pip install jsonschema
python3 tests/schema/validate_schemas.py
```

Checks:

- Draft 2020-12 metaschema validity;
- positive fixtures accepted;
- negative fixtures rejected;
- real NDJSON result line accepted by `result.schema.json`.
