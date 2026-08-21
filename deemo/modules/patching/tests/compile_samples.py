# 编译模块 — 自动化编译CVE样本为可执行ELF

"""编译模块: 将tests/cve_samples下的C源码编译为可执行测试样本。

支持两种编译模式:
  - debug:    gcc -g -O0 (保留完整调试信息)
  - release:  gcc -O2 (模拟发布二进制，调试信息有限)

输出: 每个样本在对应目录下生成 vuln_debug 和 vuln_release 两个ELF。
"""

import os
import sys
import subprocess
import glob
import json

SAMPLE_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/cve_samples"

BUILD_CONFIGS = {
    "debug":   ["gcc", "-g", "-O0", "-o"],
    "release": ["gcc", "-O2", "-o"],
    "no_canary": ["gcc", "-g", "-fno-stack-protector", "-z", "execstack", "-o"],
}


def find_samples() -> list:
    """扫描所有包含vuln.c的样本目录。"""
    samples = []
    for d in sorted(os.listdir(SAMPLE_ROOT)):
        src_path = os.path.join(SAMPLE_ROOT, d, "vuln.c")
        if os.path.isfile(src_path):
            samples.append({"name": d, "src": src_path, "dir": os.path.dirname(src_path)})
    return samples


def compile_sample(sample: dict, config_name: str = "debug") -> tuple:
    """编译单个样本。返回 (success, output_path, stderr)。"""
    cc = BUILD_CONFIGS.get(config_name, BUILD_CONFIGS["debug"])
    out_name = f"vuln_{config_name}"
    out_path = os.path.join(sample["dir"], out_name)

    cmd = cc + [out_path, sample["src"]]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return True, out_path, ""
        else:
            return False, out_path, result.stderr
    except subprocess.TimeoutExpired:
        return False, out_path, "compilation timeout"
    except FileNotFoundError:
        return False, out_path, "gcc not found"


def compile_all(configs: list = None) -> dict:
    """编译所有样本的所有配置。返回编译报告。"""
    if configs is None:
        configs = ["debug"]

    samples = find_samples()
    report = {"total": len(samples), "results": []}

    for sample in samples:
        for cfg in configs:
            ok, path, err = compile_sample(sample, cfg)
            report["results"].append({
                "sample": sample["name"], "config": cfg,
                "success": ok, "binary": path, "error": err[:200] if err else ""
            })

    success_count = sum(1 for r in report["results"] if r["success"])
    report["success_rate"] = f"{success_count}/{len(report['results'])}"
    return report


if __name__ == "__main__":
    configs = sys.argv[1:] if len(sys.argv) > 1 else ["debug"]
    rpt = compile_all(configs)
    print(json.dumps(rpt, indent=2))
