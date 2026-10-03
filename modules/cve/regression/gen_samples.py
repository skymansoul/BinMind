# 堆溢出 CVE 样本集生成器.
#
# 决策逻辑:
#   为每个样本生成独立目录: vuln.c / Makefile / README.md,
#   并写出 samples/manifest.json 作为 ground truth,
#   供回归套件与对比实验引用.
#   样本分两类: vulnerable (真实 CVE 漏洞模式复现, 预期 CONFIRMED)
#   与 safe (误报挑战对照, 预期 BENIGN 或 SUSPECTED).
#   alloc/write 支持常量或 "param" (来自 argv), 模板按 pattern 选型.
#

import json
from pathlib import Path

from sample_specs import VULN, SAFE
from sample_templates import MAKEFILE, README, TRIGGERS, select_template

SAMPLES_ROOT = Path(__file__).resolve().parent.parent / "samples"


def _alloc_str(a):
    return str(a)


def _select_template(pattern: str, is_vuln: bool):
    if not is_vuln:
        return _SAFE_TEMPLATES[pattern]
    return _VULN_TEMPLATES[pattern]


def generate():
    """生成全部样本目录与 manifest."""
    manifest = []
    SAMPLES_ROOT.mkdir(parents=True, exist_ok=True)

    for item in VULN + SAFE:
        sample_id, cve, pattern, alloc, write, expected, desc = item
        is_vuln = expected == "confirmed"
        tpl = select_template(pattern, is_vuln)
        c_code = tpl.format(
            cve=cve, sample=sample_id, desc=desc,
            alloc=_alloc_str(alloc), write=_alloc_str(write),
            vuln="恶意" if is_vuln else "正常")

        d = SAMPLES_ROOT / sample_id
        d.mkdir(parents=True, exist_ok=True)

        (d / "vuln.c").write_text(c_code, encoding="utf-8")
        (d / "Makefile").write_text(
            MAKEFILE.format(sample=sample_id), encoding="utf-8")
        (d / "README.md").write_text(README.format(
            sample=sample_id, cve=cve,
            type="heap_overflow (vulnerable)" if is_vuln
            else "heap_overflow (safe control)",
            pattern=pattern, expected=expected, desc=desc,
            vuln="恶意" if is_vuln else "安全",
            trigger=TRIGGERS.get(pattern, "构造超限输入")), encoding="utf-8")

        manifest.append({
            "sample_id": sample_id,
            "cve": cve,
            "type": "heap_overflow",
            "ground_truth": "vulnerable" if is_vuln else "safe",
            "expected": expected,
            "pattern": pattern,
            "alloc_size": alloc,
            "write_size": write,
            "source": "vuln.c",
            "desc": desc,
        })

    manifest_path = SAMPLES_ROOT / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"generated {len(manifest)} samples -> {SAMPLES_ROOT}")
    print(f"manifest -> {manifest_path}")
    return manifest


if __name__ == "__main__":
    generate()
