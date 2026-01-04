Tools Catalog (index)

This file lists the categories and an index pointer to items. Each item should live under `tools/<category>/<tool>/` with a `README.md` describing the tool and a `metadata.yml`.

Example entry structure:

```
tools/redteam/example-tool/
  README.md        # description, safe usage, links
  metadata.yml     # name, category, license, tested_os, intended_use
  example/         # optional sanitized test data only
```

Initial categories
- redteam
- blueteam
- infra
- detection-rules
- playbooks
- automation

When adding tools: do not commit binaries or exploit payloads. Add references to upstream projects and reproduction instructions that use safe data.
