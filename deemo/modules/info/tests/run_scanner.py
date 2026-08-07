# tests/run_scanner — 扫描调度模块
# 对每个编译好的样本运行检测器, 收集原始输出。
# 支持: AC3 v1 (info_collect.py) 和 PSVR-HLM v2 (heap_overflow_v2.py)。
# 每个样本记录: 检出项数、置信度分布、耗时、内存峰值。

import os, sys, json, time, tracemalloc
from pathlib import Path
from datetime import datetime

# 路径设置: 确保能访问 info_collection/src 和 analysis/
_PROJ = Path(__file__).parent.parent
_SRC = _PROJ / "info_collection" / "src"
_ANA = _PROJ / "analysis"
for p in (str(_SRC), str(_ANA), str(_PROJ)):
    if p not in sys.path:
        sys.path.insert(0, p)

SAMPLES_DIR = Path(__file__).parent / "regression" / "samples"
SCAN_LOG = Path(__file__).parent / "regression" / "scan_results.json"


def _find_elf(sample_dir: Path) -> Path:
    """在样本目录中找 ELF 文件。"""
    for name in ("vuln", "a.out"):
        p = sample_dir / name
        if p.exists() and os.access(str(p), os.X_OK):
            return p
    elfs = list(sample_dir.glob("*.elf"))
    return elfs[0] if elfs else None


def _extract_imports_from_elf(elf_path: Path) -> dict:
    """用 objdump/nm 提取导入表。"""
    imports = {"all_imports": {}}
    try:
        import subprocess
        proc = subprocess.run(
            ["objdump", "-T", str(elf_path)],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "*UND*" in line:
                    func = parts[-1]
                    dll = "libc.so.6"  # 简化: 默认 libc
                    if dll not in imports["all_imports"]:
                        imports["all_imports"][dll] = []
                    if func not in imports["all_imports"][dll]:
                        imports["all_imports"][dll].append(func)
    except Exception:
        pass
    return imports


def _extract_strings_from_elf(elf_path: Path) -> list:
    """用 strings 提取可打印字符串。"""
    try:
        import subprocess
        proc = subprocess.run(
            ["strings", str(elf_path)],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            return [(i, s) for i, s in enumerate(proc.stdout.splitlines()) if len(s) >= 3]
    except Exception:
        pass
    return []


def _get_checksec(elf_path: Path) -> dict:
    """用 readelf 获取基本安全特性。"""
    info = {"arch": "x86_64"}
    try:
        import subprocess
        proc = subprocess.run(
            ["readelf", "-h", str(elf_path)],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            if "Class:" in line and "ELF32" in line:
                info["arch"] = "i386"
            if "Class:" in line and "ELF64" in line:
                info["arch"] = "x86_64"
    except Exception:
        pass
    return info


def scan_sample_v1(sample_name: str, elf_path: Path) -> dict:
    """AC3 v1 扫描 (info_collect.py 的堆溢出检测)。"""
    start = time.time()
    tracemalloc.start()
    try:
        from heap_overflow_detector import detect_heap_overflow
        imports = _extract_imports_from_elf(elf_path)
        strings = _extract_strings_from_elf(elf_path)
        checksec = _get_checksec(elf_path)
        result = detect_heap_overflow(imports, strings, checksec)
    except Exception as e:
        result = {"error": str(e)}
    elapsed = time.time() - start
    mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"sample": sample_name, "method": "AC3-v1", "elapsed_ms": round(elapsed * 1000, 1),
            "peak_memory_kb": round(mem[1] / 1024, 1), "result": result}


def scan_sample_v2(sample_name: str, elf_path: Path) -> dict:
    """PSVR-HLM v2 扫描 (新算法)。"""
    start = time.time()
    tracemalloc.start()
    try:
        from heap_overflow_v2 import detect_heap_overflow_v2
        imports = _extract_imports_from_elf(elf_path)
        strings = _extract_strings_from_elf(elf_path)
        checksec = _get_checksec(elf_path)
        # 读取源码用于值范围分析
        src_dir = SAMPLES_DIR / sample_name
        code = ""
        src_file = src_dir / "vuln.c"
        if src_file.exists():
            code = src_file.read_text(encoding="utf-8", errors="replace")
        result = detect_heap_overflow_v2(code=code, imports=imports,
                                          strings=strings, checksec=checksec)
    except Exception as e:
        result = {"error": str(e)}
    elapsed = time.time() - start
    mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"sample": sample_name, "method": "PSVR-HLM-v2", "elapsed_ms": round(elapsed * 1000, 1),
            "peak_memory_kb": round(mem[1] / 1024, 1), "result": result}


def run_all(targets: list = None, methods: list = None) -> dict:
    """对全部样本运行全部检测方法。"""
    if methods is None:
        methods = ["v1", "v2"]

    all_dirs = sorted(
        d for d in SAMPLES_DIR.iterdir()
        if d.is_dir() and d.name != "tests"
    )
    results = []

    for d in all_dirs:
        if targets and d.name not in targets:
            continue
        elf = _find_elf(d)
        if not elf:
            print(f"[SCAN] SKIP: {d.name} — no ELF found")
            continue

        if "v1" in methods:
            results.append(scan_sample_v1(d.name, elf))
        if "v2" in methods:
            results.append(scan_sample_v2(d.name, elf))
        print(f"[SCAN] OK: {d.name} ({len(results)} scans)")

    scan_data = {
        "timestamp": datetime.now().isoformat(),
        "total_samples": len(all_dirs),
        "total_scans": len(results),
        "results": results,
    }
    SCAN_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(SCAN_LOG, "w") as f:
        json.dump(scan_data, f, indent=2, ensure_ascii=False, default=str)

    print(f"\nScan complete: {len(results)} scans across {len(all_dirs)} samples")
    return scan_data


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", choices=["v1", "v2", "all"], default="all")
    parser.add_argument("samples", nargs="*")
    args = parser.parse_args()
    methods = ["v1", "v2"] if args.method == "all" else [args.method]
    run_all(targets=args.samples or None, methods=methods)
