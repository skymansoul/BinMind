"""从ground_truth.json批量生成样本README.md."""
import json
from pathlib import Path

SAMPLE_DIR = Path(__file__).parent.parent / "tests" / "cve_samples" / "heap_overflow"
GT_PATH = SAMPLE_DIR / "ground_truth.json"

with open(GT_PATH, encoding="utf-8") as f:
    gt = json.load(f)

count = 0
for name, info in sorted(gt["samples"].items()):
    sample_dir = SAMPLE_DIR / name
    if not sample_dir.is_dir():
        continue
    cve = info.get("cve", "N/A")
    pattern = info.get("pattern", "")
    expected = info.get("expected_vuln", False)
    vtype = info.get("expected_type", "unknown")
    notes = info.get("notes", "")
    label = "VULNERABLE" if expected else "SAFE"

    readme = f"""# {name}

## CVE
{cve}

## Pattern
{pattern if pattern else "(see source code)"}

## Expected Verdict
{label} ({vtype})

## Trigger Condition
{notes}

## Build
```bash
make
```

## Run
```bash
./vuln.exe
```
"""
    readme_path = sample_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    count += 1

print(f"Generated {count} README.md files")
