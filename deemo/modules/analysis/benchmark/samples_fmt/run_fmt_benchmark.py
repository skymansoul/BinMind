# 格式化字符串检测精度基准 - 安全样本误报控制验证
#
# 目标: 验证 fmt 检测器在安全样本 (字面量/常量/snprintf截断) 上
# 不产生误报, 在真实 CVE 样本上保持召回.
# 样本: deemo/tests/samples/format_string/ (31 个, 含 safe 类).
#
# 判定: 样本名含 safe/const/trunc → 安全 (检出=FP);
#       含 vuln/nested/offset/write/loop 等 → 漏洞 (检出=TP).

import json
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent  # samples_fmt
PROJECT_ROOT = SCRIPT_DIR.parents[3]  # samples_fmt → benchmark → analysis → modules → deemo
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary, \
    extract_func_name
from modules.analysis.static.format_string_detect import FormatStringDetector

FMT_ROOT = PROJECT_ROOT / "tests" / "samples" / "format_string"
RESULTS_DIR = SCRIPT_DIR.parents[1] / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# 安全类标记: 名字含这些关键字的目录判为安全样本
# 例外: fmt_double_percent 是 %% 全转义安全样本 (名字无safe标记);
#       fmt_snprintf_trunc 名字含trunc 但实际是"snprintf展开用户输入再
#       printf"的漏洞样本, 必须按漏洞处理.
_SAFE_MARKERS = ("safe", "const", "literal")
_SAFE_EXACT = {"fmt_double_percent"}
_VULN_EXACT = {"fmt_snprintf_trunc"}
# printf 族
_PRINTF = {"printf", "fprintf", "sprintf", "snprintf", "vprintf",
           "vfprintf", "vsprintf", "vsnprintf",
           "__mingw_printf", "__mingw_sprintf", "__mingw_snprintf",
           "__mingw_vprintf", "__mingw_vfprintf", "__mingw_vsprintf",
           "__mingw_vsnprintf"}


def is_safe_sample(name: str) -> bool:
    if name in _SAFE_EXACT:
        return True
    if name in _VULN_EXACT:
        return False
    return any(m in name.lower() for m in _SAFE_MARKERS)


def scan_fmt_binary(binary: str) -> bool:
    """扫描二进制的 printf 调用, 判断是否检出格式化字符串漏洞."""
    ins, fmt, main, ranges = disassemble_binary(binary)
    is_win = "pei" in (fmt or "").lower()
    arg_regs = ["rcx", "rdx", "r8", "r9"] if is_win \
        else ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    # 用户代码范围: 仅扫描用户函数内的调用, 排除 CRT 内部实现
    user_addrs = set()
    for lo, hi in ranges:
        for i in ins:
            if lo <= i.get("address", 0) < hi:
                user_addrs.add(i.get("address", 0))
    det = FormatStringDetector()
    calls = []
    for idx, i in enumerate(ins):
        if i.get("address", 0) not in user_addrs:
            continue
        ops = i.get("operands", [])
        if i.get("mnemonic", "").lower() != "call" or not ops:
            continue
        fn = extract_func_name(ops[0])
        if fn not in _PRINTF:
            continue
        args = []
        for reg in arg_regs:
            found = None
            src_reg = reg
            last_reg = None
            upper = idx  # 回追上界: call 点
            for _ in range(4):
                located = None
                located_mnem = None
                located_j = None
                for j in range(upper - 1, max(0, upper - 20) - 1, -1):
                    p = ins[j]
                    if p.get("mnemonic", "").lower() not in (
                            "mov", "lea", "movabs"):
                        continue
                    p_ops = p.get("operands", [])
                    if len(p_ops) < 2:
                        continue
                    dst = p_ops[0].strip().lower().lstrip("%")
                    if dst == src_reg:
                        located = p_ops[1]
                        located_mnem = p.get("mnemonic", "").lower()
                        located_j = j
                        break
                if located is None:
                    # 回追到函数顶部无定义 → 源是函数入口参数
                    found = last_reg or src_reg
                    break
                located_src = located.strip().lower().lstrip("%") \
                    .split("#")[0].strip()
                # 纯寄存器拷贝 → 继续回追, 上界收紧到该赋值点
                if (located_mnem == "mov" and "[" not in located
                        and located_src in ("rcx", "rdx", "r8", "r9",
                                            "rdi", "rsi", "rax", "rbx")):
                    last_reg = located_src
                    src_reg = located_src
                    upper = located_j
                    continue
                found = located
                break
            args.append(found or "")
        calls.append({"target": fn, "args": args,
                      "fmt_source": "unknown",
                      "address": i.get("address", 0)})
    findings = det.analyze_batch(calls)
    return len(findings) > 0


def main():
    if not FMT_ROOT.exists():
        print(f"no samples dir: {FMT_ROOT}")
        return
    dirs = sorted(d for d in FMT_ROOT.iterdir() if d.is_dir())
    rows = []
    print("=" * 60)
    print("Format String Precision Benchmark")
    print("=" * 60)
    for d in dirs:
        exe = next(d.glob("*.exe"), None)
        if exe is None:
            continue
        is_safe = is_safe_sample(d.name)
        t0 = time.perf_counter()
        detected = False
        try:
            detected = scan_fmt_binary(str(exe))
        except Exception:
            pass
        rows.append({
            "name": d.name, "is_safe": is_safe, "detected": detected,
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
        })
        verdict = "TN" if (is_safe and not detected) else \
            ("TP" if (not is_safe and detected) else
             ("FP!" if is_safe else "FN!"))
        print(f"  {d.name:<32} {'safe' if is_safe else 'vuln '} "
              f"detected={detected} -> {verdict}")

    tp = sum(1 for r in rows if not r["is_safe"] and r["detected"])
    fn = sum(1 for r in rows if not r["is_safe"] and not r["detected"])
    fp = sum(1 for r in rows if r["is_safe"] and r["detected"])
    tn = sum(1 for r in rows if r["is_safe"] and not r["detected"])
    recall = tp / max(tp + fn, 1)
    prec = tp / max(tp + fp, 1)
    fpr = fp / max(fp + tn, 1)
    print("=" * 60)
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  Recall={recall:.1%} Precision={prec:.1%} FPR={fpr:.1%}")
    print("=" * 60)
    (RESULTS_DIR / "fmt_precision.json").write_text(json.dumps({
        "summary": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                    "recall": round(recall, 4),
                    "precision": round(prec, 4),
                    "fpr": round(fpr, 4)},
        "rows": rows,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
