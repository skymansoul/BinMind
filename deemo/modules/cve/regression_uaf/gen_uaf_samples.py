# UAF 样本集生成器.
#
# 决策逻辑:
#   为每个样本生成独立目录: vuln.c / Makefile / README.md,
#   并写出 samples_uaf/manifest.json 作为 ground truth.
#   样本分两类: vulnerable (真实 CVE 复现, 预期 CONFIRMED)
#   与 safe (误报挑战对照, 预期 benign).
#   元数据与模板分别位于 uaf_specs.py / uaf_templates.py.
#
# 创建: 2025-01-13

import json
from pathlib import Path

from uaf_specs import VULN, SAFE
from uaf_templates import MAKEFILE, README, TRIGGERS, select_template

SAMPLES_ROOT = Path(__file__).resolve().parent.parent / "samples_uaf"


def generate():
    """生成全部 UAF 样本目录与 manifest."""
    manifest = []
    SAMPLES_ROOT.mkdir(parents=True, exist_ok=True)

    for item in VULN + SAFE:
        sample_id, cve, pattern, expected, desc = item
        is_vuln = expected == "confirmed"
        tpl = select_template(pattern, is_vuln)
        c_code = tpl.format(
            cve=cve, sample=sample_id, desc=desc,
            vuln="恶意" if is_vuln else "安全")

        d = SAMPLES_ROOT / sample_id
        d.mkdir(parents=True, exist_ok=True)

        (d / "vuln.c").write_text(c_code, encoding="utf-8")
        (d / "Makefile").write_text(
            MAKEFILE.format(sample=sample_id), encoding="utf-8")
        (d / "README.md").write_text(README.format(
            sample=sample_id, cve=cve,
            type="use_after_free (vulnerable)" if is_vuln
            else "use_after_free (safe control)",
            pattern=pattern, expected=expected, desc=desc,
            vuln="恶意" if is_vuln else "安全",
            trigger=TRIGGERS.get(pattern, "构造超限输入")), encoding="utf-8")

        manifest.append({
            "sample_id": sample_id,
            "cve": cve,
            "type": "use_after_free",
            "ground_truth": "vulnerable" if is_vuln else "safe",
            "expected": expected,
            "pattern": pattern,
            "source": "vuln.c",
            "desc": desc,
        })

    manifest_path = SAMPLES_ROOT / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"generated {len(manifest)} UAF samples -> {SAMPLES_ROOT}")
    print(f"manifest -> {manifest_path}")
    return manifest


if __name__ == "__main__":
    generate()
