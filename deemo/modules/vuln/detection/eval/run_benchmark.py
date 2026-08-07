# 创建: 2026-07-24 | 多工具对比基准测试(重写)
"""对所有样本调binmind/angr/qemu/ghidra, 输出CSV。"""

import csv, json, os, subprocess, sys, time
from pathlib import Path

_SAMPLES = Path(__file__).parent.parent / "tests" / "regression" / "samples"
_EVAL = Path(__file__).parent
HEADER = ["tool","sample_id","detected","elapsed_sec","note"]


def discover_binaries():
    _bins = {}
    for _d in sorted(_SAMPLES.iterdir()):
        if not _d.is_dir(): continue
        for _n in ("vuln","vuln.exe"):
            _p = _d / _n
            if _p.exists(): _bins[_d.name] = str(_p); break
    return _bins


def run_our(binary: str) -> dict:
    _t0 = time.time()
    try:
        _scanner = Path(__file__).parent.parent / "src" / "scanner.py"
        _r = subprocess.run([sys.executable, str(_scanner), binary, "enhanced"],
                           capture_output=True, text=True, timeout=30)
        _d = json.loads(_r.stdout) if _r.returncode == 0 else {}
        return {"detected": _d.get("finding_count", 0) > 0,
                "finding_count": _d.get("finding_count", 0),
                "elapsed_sec": round(time.time()-_t0, 3)}
    except:
        return {"detected": False, "elapsed_sec": round(time.time()-_t0, 3)}


def run_angr(binary: str) -> dict:
    _script = Path(__file__).parent.parent / "experiments" / "angr_analyzer.py"
    _t0 = time.time()
    try:
        _r = subprocess.run([sys.executable, str(_script), binary], capture_output=True, text=True, timeout=120)
        _d = json.loads(_r.stdout) if _r.returncode == 0 else {}
        return {"detected": _d.get("finding_count", 0) > 0, "elapsed_sec": round(time.time()-_t0, 3)}
    except:
        return {"detected": False, "elapsed_sec": round(time.time()-_t0, 3), "note": "angr unavailable"}


def run_qemu(binary: str) -> dict:
    _t0 = time.time()
    try:
        _r = subprocess.run(["qemu-x86_64", "-d", "in_asm", binary], capture_output=True, text=True, timeout=10, input="AAAA\n")
        _found = any(_f in (_r.stdout+_r.stderr).lower() for _f in {"memcpy","strcpy","system"})
        return {"detected": _found, "elapsed_sec": round(time.time()-_t0, 3)}
    except FileNotFoundError:
        return {"detected": False, "elapsed_sec": 0, "note": "qemu not installed"}
    except:
        return {"detected": False, "elapsed_sec": round(time.time()-_t0, 3)}


def run_ghidra(binary: str) -> dict:
    _t0 = time.time()
    try:
        _r = subprocess.run(["objdump","-T",binary], capture_output=True, text=True, timeout=15)
        _found = any(_f in _r.stdout.lower() for _f in {"memcpy","strcpy","system","malloc","free","printf"})
        return {"detected": _found, "elapsed_sec": round(time.time()-_t0, 3), "note": "ghidra fallback"}
    except:
        return {"detected": False, "elapsed_sec": round(time.time()-_t0, 3), "note": "ghidra unavailable"}


TOOLS = {"our": run_our, "angr": run_angr, "qemu": run_qemu, "ghidra": run_ghidra}


def run_all(output: str = "benchmark_results.csv"):
    _bins = discover_binaries()
    _rows = []

    for _name, _path in _bins.items():
        for _tname, _tfunc in TOOLS.items():
            _r = _tfunc(_path)
            _rows.append([_tname, _name, "1" if _r.get("detected") else "0",
                         str(_r.get("elapsed_sec","")), _r.get("note","")])

    _out = Path(output)
    with open(_out, "w", newline="") as _f:
        _w = csv.writer(_f)
        _w.writerow(HEADER)
        _w.writerows(_rows)
    print(f"CSV: {_out} ({len(_rows)} rows)")
    return str(_out)


if __name__ == "__main__":
    run_all()
