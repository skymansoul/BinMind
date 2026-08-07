# 回归测试 - 扫描调度模块 (Windows 可用版)
# 对已编译二进制运行对应漏洞检测器, 输出检出结果.
# 修复 scan_runner.py 的桩实现: 原版 heap/uaf 检测器返回空列表,
# 本模块接入真实检测管线 (objdump + 检测器).
#
# 决策: 所有检测器基于 objdump 反汇编, 无需调试信息,
# 兼容 PE/ELF. 每个检测器按漏洞类型选择.
# 创建: 2026-07-08

import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"
PROJECT_ROOT = HERE.parents[3]  # regression → tests → analysis → modules → deemo

import sys
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary, \
    extract_func_name
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.format_string_detect import FormatStringDetector
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.integer_overflow_detect import IntegerOverflowDetector


def _disassemble(binary: str):
    """反汇编 + 计算用户函数范围."""
    ins, fmt, main, ranges = disassemble_binary(binary)
    return ins, fmt, main, ranges


def scan_heap_overflow(binary: str) -> dict:
    ins, fmt, main, ranges = _disassemble(binary)
    det = HeapOverflowDetector(AllocatorFamily.GLIBC,
                               use_win64_abi="pei" in fmt.lower())
    if main:
        det.set_min_user_addr(main)
    if ranges:
        det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    findings = det.finalize(ins)
    return {
        "detected": len(findings) > 0,
        "findings": [{
            "type": f.get("type", ""),
            "severity": f.get("severity", ""),
            "write_size": f.get("write_size", 0),
            "alloc_size": f.get("alloc_size", 0),
            "stage": f.get("fp_stage", ""),
        } for f in findings],
        "raw_count": len(det.raw_findings),
    }


def scan_format_string(binary: str) -> dict:
    ins, fmt, main, ranges = _disassemble(binary)
    det = FormatStringDetector()
    try:
        # PE (MinGW) 用 Win64 ABI (rcx/r8...), ELF 用 SysV (rdi/rsi...)
        is_win = "pei" in (fmt or "").lower()
        arg_regs = ["rcx", "rdx", "r8", "r9"] if is_win \
            else ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        # 用户代码范围: 排除 CRT 内部实现的 printf 调用 (避免误报)
        user_addrs = set()
        for lo, hi in ranges:
            for i in ins:
                if lo <= i.get("address", 0) < hi:
                    user_addrs.add(i.get("address", 0))
        calls = []
        for idx, i in enumerate(ins):
            if i.get("address", 0) not in user_addrs:
                continue
            ops = i.get("operands", [])
            if i.get("mnemonic", "").lower() != "call" or not ops:
                continue
            fn = extract_func_name(ops[0])
            if fn not in _PRINTF_FAMILY_NAMES:
                continue
            args = []
            for reg in arg_regs:
                args.append(_resolve_arg(ins, idx, reg))
            calls.append({
                "target": fn,
                "args": args,
                "fmt_source": "unknown",
                "address": i.get("address", 0),
            })
        findings = det.analyze_batch(calls)
        return {
            "detected": len(findings) > 0,
            "findings": [{
                "type": f.get("type", "format_string"),
                "verdict": f.get("severity", ""),
            } for f in findings],
            "raw_count": len(findings),
        }
    except Exception as e:
        return {"detected": False, "findings": [], "error": str(e)[:120],
                "raw_count": 0}


def _resolve_arg(ins: list, idx: int, reg: str) -> str:
    """多跳寄存器链回追实参: mov r8, rcx → lea rcx, [rip+...]."""
    src_reg = reg
    last_reg = None
    upper = idx
    for _ in range(4):
        located = None
        located_mnem = None
        located_j = None
        for j in range(upper - 1, max(0, upper - 20) - 1, -1):
            p = ins[j]
            if p.get("mnemonic", "").lower() not in ("mov", "lea",
                                                     "movabs"):
                continue
            p_ops = p.get("operands", [])
            if len(p_ops) < 2:
                continue
            dst = _norm_arg(p_ops[0])
            if dst == src_reg:
                located = p_ops[1]
                located_mnem = p.get("mnemonic", "").lower()
                located_j = j
                break
        if located is None:
            return last_reg or src_reg
        located_src = located.strip().lower().lstrip("%").split("#")[0].strip()
        if (located_mnem == "mov" and "[" not in located
                and located_src in ("rcx", "rdx", "r8", "r9",
                                    "rdi", "rsi", "rax", "rbx")):
            last_reg = located_src
            src_reg = located_src
            upper = located_j
            continue
        return located
    return last_reg or src_reg


_PRINTF_FAMILY_NAMES = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "vdprintf", "syslog", "vsyslog",
    "__mingw_printf", "__mingw_fprintf", "__mingw_sprintf",
    "__mingw_snprintf", "__mingw_vprintf", "__mingw_vfprintf",
    "__mingw_vsprintf", "__mingw_vsnprintf",
}


def _norm_arg(op: str) -> str:
    return op.strip().lower().lstrip("%").replace("qword ptr ", "") \
        .replace("dword ptr ", "").split("#")[0].strip()


def scan_uaf(binary: str) -> dict:
    ins, fmt, main, ranges = _disassemble(binary)
    det = UAFDetector(use_win64_abi="pei" in fmt.lower())
    if ranges:
        det.set_user_func_ranges(ranges)
    try:
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins) or det.findings
        return {
            "detected": len(findings) > 0,
            "findings": [{
                "type": "uaf",
                "verdict": str(getattr(f, "verdict", "")),
            } for f in findings],
            "raw_count": len(findings),
        }
    except Exception as e:
        return {"detected": False, "findings": [], "error": str(e)[:120],
                "raw_count": 0}


def scan_integer_overflow(binary: str) -> dict:
    ins, fmt, main, ranges = _disassemble(binary)
    det = IntegerOverflowDetector(
        use_win64_abi="pei" in (fmt or "").lower())
    det.set_instructions(ins)
    try:
        for i in ins:
            det.analyze(i)
        findings = det.findings
        return {
            "detected": len(findings) > 0,
            "findings": [{
                "type": f.get("type", "integer_overflow"),
                "verdict": f.get("severity", ""),
            } for f in findings],
            "raw_count": len(findings),
        }
    except Exception as e:
        return {"detected": False, "findings": [], "error": str(e)[:120],
                "raw_count": 0}


SCANNERS = {
    "heap_overflow": scan_heap_overflow,
    "format_string": scan_format_string,
    "uaf": scan_uaf,
    "integer_overflow": scan_integer_overflow,
}


def scan_all(manifest_path: Path = None) -> list:
    manifest_path = manifest_path or Path(
        HERE) / "build" / "manifest_compiled.json"
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    results = []
    for entry in manifest:
        binary = entry.get("binary", "")
        vtype = entry.get("type", "")
        if not binary or not Path(binary).exists():
            continue
        scanner = SCANNERS.get(vtype)
        if scanner is None:
            continue

        t0 = time.perf_counter()
        try:
            r = scanner(binary)
        except Exception as e:
            r = {"detected": False, "findings": [],
                 "error": f"{type(e).__name__}: {str(e)[:120]}"}
        r["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        r["cve"] = entry.get("cve", "unknown")
        r["type"] = vtype
        r["opt"] = entry.get("opt", "")
        r["binary"] = binary

        # 判定: 有检出且无错误 → 命中
        r["hit"] = r["detected"] and not r.get("error")
        results.append(r)
        status = "HIT" if r["hit"] else ("ERR" if r.get("error") else "MISS")
        print(f"  {r['cve']} [{vtype}-{r['opt']}]: {status} "
              f"{r.get('time_ms',0)}ms")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "scan_results_v2.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"results: {out}")
    return results


if __name__ == "__main__":
    scan_all()
