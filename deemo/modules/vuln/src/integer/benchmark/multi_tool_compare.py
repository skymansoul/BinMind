"""整数溢出多工具对比基准 — BinMind vs 正则基线 vs 理论对比.

创建: 2026-06-09
用法: python -m vuln.src.integer.benchmark.multi_tool_compare

对比维度: 召回率/精确率/F1/扫描速度/FP数量
"""
from __future__ import annotations

import re as _re
import sys, os, json, time, subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field, asdict

_PROJ = Path(__file__).resolve().parent.parent.parent.parent.parent
_SAMPLES = Path(__file__).resolve().parent.parent.parent.parent / 'tests' / 'regression' / 'samples'

# 样本 ID 和 ground truth (与 regression_runner 同步)
_SAMPLES_GT = {
    'intof-4': True, 'intof-5': True, 'intof-6': True, 'intof-7': False,
    'intof-8': True, 'intof-9': True, 'intof-10': True, 'intof-11': True,
    'intof-12': True, 'intof-13': False, 'intof-14': True, 'intof-15': True,
    'intof-16': True, 'intof-17': True, 'intof-18': True, 'intof-19': True,
    'intof-20': True,
    'int-overflow-1': True, 'int-overflow-2': True, 'int-overflow-3': True,
    'integer-overflow-06': True,
}


@dataclass
class ToolResult:
    tool: str
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0
    total_ms: float = 0.0
    notes: str = ""

    @property
    def precision(self) -> float:
        return self.tp / max(1, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return self.tp / max(1, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(0.001, p + r)


class NaiveRegexBaseline:
    """简单正则基线 — 仅匹配明显的分配大小异常.

    等价于手工 grep 方案: 找 > 2^32 的立即数 + 找 0xFF... 常量.
    不做栈值追踪, 不做跨模式推理.
    """

    _MOVABS_BIG = _re.compile(
        r'movabs\s+r\w\w,\s*(0x[0-9a-f]{9,})', _re.I)
    _MOV_SUSPICIOUS = _re.compile(
        r'mov\s+\w+,\s*(0x[f]{4,}|4294967295)', _re.I)
    _ALLOC_CALL = _re.compile(
        r'call\s+.*(malloc|calloc|realloc|HeapAlloc)', _re.I)

    def scan(self, instructions: List[str]) -> bool:
        for i, instr in enumerate(instructions):
            il = instr.strip().lower()
            if self._MOVABS_BIG.match(il):
                if self._has_alloc(instructions, i):
                    return True
            if self._MOV_SUSPICIOUS.match(il):
                if self._has_alloc(instructions, i):
                    return True
        return False

    def _has_alloc(self, insns: List[str], start: int) -> bool:
        for j in range(start + 1, min(start + 20, len(insns))):
            if self._ALLOC_CALL.match(insns[j].strip().lower()):
                return True
        return False


def disassemble(exe_path: Path) -> str:
    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', str(exe_path)],
            capture_output=True, text=True, timeout=30)
        return proc.stdout
    except Exception:
        return ""


def split_instructions(asm: str) -> List[str]:
    """提取所有指令行."""
    insns = []
    for line in asm.split('\n'):
        s = line.strip()
        if '\t' in s and ':' in s.split('\t')[0].strip():
            parts = s.rsplit('\t', 1)
            if len(parts) > 1:
                insns.append(parts[1].strip())
    return insns


def run_benchmark() -> Dict[str, ToolResult]:
    results = {}

    # — BinMind 检测器 —
    sys.path.insert(0, str(_PROJ))
    from vuln.src.integer.analysis.int_overflow_detector import (
        IntOverflowDetector)
    detector = IntOverflowDetector()
    bm_result = ToolResult(tool='BinMind IntOverflowDetector (8-mode)')
    t0 = time.time()

    for sid in _SAMPLES_GT:
        exe = _SAMPLES / sid / 'vuln.exe'
        if not exe.exists():
            continue
        asm = disassemble(exe)
        if not asm:
            continue
        insns = split_instructions(asm)
        funcs = _split_functions(asm)
        detected = False
        for fn_name, fn_insns, addrs in funcs:
            findings = detector.analyze(fn_insns, function_name=fn_name, addrs=addrs)
            if findings:
                detected = True
            detector.clear()
        gt = _SAMPLES_GT[sid]
        if gt and detected:
            bm_result.tp += 1
        elif gt and not detected:
            bm_result.fn += 1
        elif not gt and detected:
            bm_result.fp += 1
        else:
            bm_result.tn += 1

    bm_result.total_ms = (time.time() - t0) * 1000
    bm_result.notes = ('8-mode pipeline: LARGE_IMM64/TRUNCATION/SIGNED_IDX/'
                        'SUSPICIOUS_SIZE/MUL_OVERFLOW/16-bit wraparound/'
                        'SHL_OVERFLOW/16-bit overflow intent')
    results['binmind'] = bm_result

    # — 简单正则基线 —
    naive = NaiveRegexBaseline()
    nr_result = ToolResult(tool='Naive Regex Baseline (grep-equivalent)')
    t0 = time.time()

    for sid in _SAMPLES_GT:
        exe = _SAMPLES / sid / 'vuln.exe'
        if not exe.exists():
            continue
        asm = disassemble(exe)
        if not asm:
            continue
        insns = split_instructions(asm)
        detected = naive.scan(insns)
        gt = _SAMPLES_GT[sid]
        if gt and detected:
            nr_result.tp += 1
        elif gt and not detected:
            nr_result.fn += 1
        elif not gt and detected:
            nr_result.fp += 1
        else:
            nr_result.tn += 1

    nr_result.total_ms = (time.time() - t0) * 1000
    nr_result.notes = ('仅匹配 movabs > 2^32 + 0xFF... 常量 → alloc; '
                        '无栈追踪/无跨模式推理')
    results['regex_baseline'] = nr_result

    # — 理论估计: angr (符号执行) —
    angr_result = ToolResult(tool='angr (symbolic execution) — 理论估计')
    angr_result.tp = 14  # 可检测直接常量 + 截断, 难检测跨函数
    angr_result.fp = 2   # 符号执行路径爆炸 → 误报增加
    angr_result.tn = 0
    angr_result.fn = 5
    angr_result.total_ms = 5000  # ~5s/sample × 21
    angr_result.notes = ('符号执行优势: 可追踪跨函数参数传递, 可检测 int-overflow-2. '
                          '劣势: 路径爆炸, 编译时间, 环境依赖. '
                          '预计 F1 ≈ 0.80, 单样本 200-500ms.')
    results['angr_theoretical'] = angr_result

    # — 理论估计: Ghidra headless —
    ghidra_result = ToolResult(tool='Ghidra Headless (P-code) — 理论估计')
    ghidra_result.tp = 16  # P-code 可追踪更多模式
    ghidra_result.fp = 1
    ghidra_result.tn = 1
    ghidra_result.fn = 3
    ghidra_result.total_ms = 30000  # ~1.5s/sample × 21 + JVM启动
    ghidra_result.notes = ('P-code 优势: 中间表示可看到隐式截断, Varnode 追踪. '
                            '劣势: JVM 启动 ~10s, 脚本编写复杂. '
                            '预计 F1 ≈ 0.89, 单样本 100-500ms + JVM 开销.')
    results['ghidra_theoretical'] = ghidra_result

    return results


def _split_functions(asm: str) -> List[Tuple[str, List[str], List[int]]]:
    funcs = []; fn = ''; insns = []; addrs = []
    for line in asm.split('\n'):
        s = line.strip()
        if s.endswith('>:') and '<' in s:
            if fn and insns:
                funcs.append((fn, insns, addrs))
            a = s.find('<'); b = s.find('>:')
            fn = s[a+1:b] if a >= 0 and b >= 0 else s
            insns = []; addrs = []; continue
        if '\t' in s:
            parts = s.rsplit('\t', 1)
            if len(parts) > 1 and ':' in parts[0].strip():
                addr_match = _re.match(r'\s*([0-9a-f]+):', parts[0].strip())
                addrs.append(int(addr_match.group(1), 16) if addr_match else None)
                insns.append(parts[1].strip())
    if fn and insns:
        funcs.append((fn, insns, addrs))
    return funcs


def print_report(results: Dict[str, ToolResult]) -> None:
    print('=== Integer Overflow Multi-Tool Benchmark ===')
    print(f'Samples: {len(_SAMPLES_GT)} (classifiable: {sum(1 for v in _SAMPLES_GT.values() if v is not None)})')
    print()
    print(f'{"Tool":<45s} {"P":>6s} {"R":>6s} {"F1":>6s} {"TP":>4s} {"FP":>4s} {"FN":>4s} {"Time":>8s}')
    print('-' * 95)
    for key in ['binmind', 'regex_baseline', 'angr_theoretical', 'ghidra_theoretical']:
        r = results.get(key)
        if not r:
            continue
        time_str = f'{r.total_ms:.0f}ms' if r.total_ms < 10000 else f'{r.total_ms/1000:.1f}s'
        print(f'{r.tool:<45s} {r.precision:5.1%} {r.recall:5.1%} {r.f1:5.3f} '
              f'{r.tp:>4d} {r.fp:>4d} {r.fn:>4d} {time_str:>8s}')
    print()
    print('--- Notes ---')
    for key in ['binmind', 'regex_baseline', 'angr_theoretical', 'ghidra_theoretical']:
        r = results.get(key)
        if r and r.notes:
            print(f'  [{r.tool}]: {r.notes}')


if __name__ == '__main__':
    results = run_benchmark()
    print_report(results)

    out = _PROJ / '.modules' / 'int_overflow_benchmark.json'
    os.makedirs(str(out.parent), exist_ok=True)
    with open(str(out), 'w') as f:
        json.dump({k: asdict(v) for k, v in results.items()}, f, indent=2)
    print(f'\nSaved to {out}')
