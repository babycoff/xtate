# MCP server (read-only first)

```bash
xtate --mcp --control-connect=<endpoint>
```

MCP stdio JSON-RPC. Current tools:

```text
job_list
job_status
job_result_manifest
job_cancel
```

Tool results are text JSON from the control plane. The MCP server does not carry
result data; clients fetch chunks via the result manifest.

Still planned: `list_modules`, `describe_probe`, `explain_target`, `check`,
`validate_config`, and controlled `start_scan`.
