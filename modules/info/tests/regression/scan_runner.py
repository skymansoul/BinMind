# scan_runner — CAIR检测器调度模块
# 对编译产物逐个调用 tiered_vuln_detector.detect_all_tiers(),
# 收集每个样本每层 Tier 的检出结果和耗时。

import os, sys, json, time, subprocess
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent.parent.parent  # deemo/
sys.path.insert(0, str(ROOT))

RESULTS_DIR = Path(__file__).parent / "scan_results"


def _run_cair_on_binary(binary_path: str, tier: int = 3) -> dict:
    """对单个 ELF 运行 CAIR 检测, 返回原始结果字典。"""
    try:
        # 用 radare2 提取导入表和字符串 (若可用, 否则回退到 info_collect)
        imports = {"all_imports": {}, "dangerous_functions": []}
        strings = []
        checksec = {}

        # 尝试 info_collect 的二进制解析
        try:
            from modules.info.info_collect import get_binary_info
            info = get_binary_info(binary_path)
            imports = info.get("imports", imports)
            strings = info.get("key_strings", info.get("strings", strings))
            checksec = info.get("checksec", checksec)
        except Exception:
            pass

        # 尝试 radare2 提取
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "ii", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                for line in proc.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        imports.setdefault("all_imports", {}).setdefault(
                            "imports", []).append(parts[-1])
            proc2 = subprocess.run(
                ["r2", "-q", "-c", "izz~password,secret,system,shell,flag", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if proc2.returncode == 0:
                strings.extend(proc2.stdout.strip().split("\n")[:50])
        except Exception:
            pass

        from modules.info.info_collection.src.tiered_vuln_detector import detect_all_tiers
        from modules.info.info_collection.src.import_reachability import build_reachability_graph
        from modules.info.info_collection.src._shared import extract_api_set

        t0 = time.time()
        api_set = extract_api_set(imports)
        reach = build_reachability_graph(imports)

        result = detect_all_tiers(
            api_set=api_set, imports=imports, strings=strings,
            checksec=checksec, arch="x64", binary_format="ELF",
            reachability_graph=reach, max_tier=tier,
        )
        elapsed = round(time.time() - t0, 3)

        return {"path": binary_path, "elapsed_sec": elapsed, "result": result,
                "error": None}
    except Exception as e:
        return {"path": binary_path, "elapsed_sec": 0.0, "result": None,
                "error": str(e)[:200]}


def scan_all_samples(build_log_path: str = None, tier: int = 3) -> dict:
    """扫描编译产物目录中所有 ELF 文件。"""
    samples_dir = Path(__file__).parent / "samples"
    results = {"scans": [], "summary": {}, "timestamp": datetime.now().isoformat()}

    for sample_dir in sorted(samples_dir.iterdir()):
        if not sample_dir.is_dir(): continue
        build_dir = sample_dir / "build"
        if not build_dir.exists(): continue

        for elf_file in sorted(build_dir.glob("*.elf")):
            print(f"[SCAN] {elf_file.name}")
            scan = _run_cair_on_binary(str(elf_file), tier)
            scan["sample_name"] = sample_dir.name
            results["scans"].append(scan)

    # Summary stats
    tiers = ["tier1", "tier2", "tier3"]
    for t in tiers:
        detections = sum(
            1 for s in results["scans"]
            if s["result"] and s["result"]["tier_comparison"].get(t, {}).get("total", 0) > 0
        )
        avg_time = sum(s.get("elapsed_sec", 0) for s in results["scans"]) / max(len(results["scans"]), 1)
        results["summary"][t] = {"detected_files": detections,
                                  "total_files": len(results["scans"]),
                                  "avg_scan_time_sec": round(avg_time, 3)}

    # Save
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nResults saved to {out}")
    return results


if __name__ == "__main__":
    scan_all_samples()
