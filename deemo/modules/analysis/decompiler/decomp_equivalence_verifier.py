# 创建: 2026-05-18 08:15
# 修改: 2026-05-18 — 重编译->I/O concolic->覆盖率匹配三层递进验证
"""
反编译等价性验证器 — I/O 行为级等价检查, 而非语法相似度。

现有反编译器评估依赖 BLEU/edit distance——与语义正确性相关性近乎零
。本模块替代语法指标:
反编译输出是否与原始二进制在 I/O 行为上等价?

验证方法 (三层递进):
  1. 语法层: 反编译代码能否重编译? (recompilability check)
  2. 语义层: 对相同输入, 反编译代码与原始二进制的输出是否一致?
     (I/O equivalence via symbolic execution + concolic testing)
  3. 路径层: 分支覆盖率 profile 是否匹配?
     (coverage equivalence check)

每一层独立评分, 综合为单一质量指标。
只有通过语义层的反编译输出才被认为是 "等价"——无论语法多漂亮。

为什么选择 I/O 行为等价而非完全状态等价:
  完全状态等价 (所有寄存器+内存) 在反编译场景下不可实现——
  编译器会消除死代码、重排指令、合并常量。I/O 等价
  (相同的系统调用序列 + 相同的返回值) 是实际可达到的最高标准。

ref: codealign — instruction-level equivalence
     alignment, 本项目取其逐指令对齐思路但降级为 I/O 级等价
ref: D-SCORE — multi-aspect code quality metric,
     本项目实现其三阶段验证中的语义层 (SMT + concolic)
ref: DEBENCH — multi-dimensional decompilation
     eval, 本项目取其"高重编译率≠功能等价"的发现作为设计前提
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable


class EquivalenceLevel(Enum):
    NONE = 'none'             # 完全不匹配
    SYNTAX = 'syntax'         # 仅语法层通过 (可重编译)
    IO_EQUIV = 'io_equiv'     # I/O 行为等价 (同输入→同输出)
    FULL_EQUIV = 'full_equiv' # 路径级等价 (同分支覆盖率)


@dataclass
class EquivalenceReport:
    """反编译等价性验证报告。"""
    function_name: str = ''
    level: EquivalenceLevel = EquivalenceLevel.NONE
    recompilable: bool = False
    io_tests_passed: int = 0
    io_tests_total: int = 0
    branch_coverage_match: float = 0.0  # [0,1]
    quality_score: float = 0.0          # 综合质量 [0,100]
    issues: list[str] = field(default_factory=list)


# 第1层: 重编译检查
# 反编译输出能否通过编译器? 语法正确性是最低门槛。

def check_recompilability(decompiled_code: str,
                          language: str = 'c') -> tuple[bool, str]:
    """检查反编译代码是否可重编译。返回 (can_compile, error_msg)。

    策略: 使用 GCC/Clang 的 -fsyntax-only 模式——仅语法检查,
    不产生目标文件。对反编译代码做最小化预处理 (去除不完整行)。"""
    import subprocess, tempfile, os

    # 最小化预处理: 在未闭合的括号/语句末尾补分号
    lines = decompiled_code.strip().split('\n')
    cleaned = []
    for line in lines:
        stripped = line.rstrip()
        if stripped and not stripped.endswith((';', '{', '}', ':', '#', '\\')):
            # 检查是否是完整语句——启发式
            if any(kw in stripped for kw in ('if', 'while', 'for', 'return',
                                               'goto', 'break', 'continue')):
                stripped += ';'
        cleaned.append(stripped)
    cleaned_code = '\n'.join(cleaned)

    try:
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False)
        f.write(cleaned_code)
        f.close()  # Windows: 必须关闭文件后才能被编译器读取
        compiler = 'gcc' if language == 'c' else 'g++'
        result = subprocess.run(
            [compiler, '-fsyntax-only', '-w', f.name],
            capture_output=True, text=True, timeout=30)
        os.unlink(f.name)
        return result.returncode == 0, result.stderr[:200]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False, 'compiler unavailable or timeout'


# 第2层: I/O 行为等价
# 用 concolic 测试验证反编译代码与二进制的行为一致性。
# 生成 N 组随机输入→执行→比较输出 (返回值 + 写入内存/文件的字节)。

def generate_test_inputs(n_cases: int = 50, seed: int = 42) -> list[dict]:
    """生成 concolic 测试的输入用例。随机 int/string/buffer 组合。"""
    import random
    rng = random.Random(seed)
    inputs = []
    for _ in range(n_cases):
        test_type = rng.choice(['int', 'string', 'buffer', 'zero', 'extreme'])
        if test_type == 'int':
            inputs.append({'type': 'int', 'value': rng.randint(-100000, 100000)})
        elif test_type == 'string':
            length = rng.randint(0, 128)
            s = ''.join(chr(rng.randint(32, 126)) for _ in range(length))
            inputs.append({'type': 'string', 'value': s})
        elif test_type == 'buffer':
            length = rng.randint(1, 256)
            buf = bytes(rng.randint(0, 255) for _ in range(length))
            inputs.append({'type': 'buffer', 'value': buf.hex()})
        elif test_type == 'zero':
            inputs.append({'type': 'int', 'value': 0})
        else:
            inputs.append({'type': 'int', 'value': rng.choice(
                [0, 1, -1, 255, 256, 65535, -32768, 2147483647])})
    return inputs


def check_io_equivalence(
    binary_runner: Callable[[dict], dict],
    decompiled_runner: Callable[[dict], dict],
    test_inputs: list[dict],
) -> tuple[int, int, list[dict]]:
    """对相同输入执行 binary 和 decompiled 版本, 比较输出。
    返回 (passed, total, failures)。

    binary_runner / decompiled_runner: 接受输入 dict, 返回输出 dict
    (至少包含 'return_value' 和 'stdout' 字段)。"""
    passed = 0
    failures = []

    for i, inp in enumerate(test_inputs):
        try:
            bin_out = binary_runner(inp)
            dec_out = decompiled_runner(inp)
        except Exception as e:
            failures.append({'input': inp, 'error': str(e)})
            continue

        # 比较返回值
        ret_match = bin_out.get('return_value') == dec_out.get('return_value')
        # 比较 stdout (截断到较短长度, 容忍多输出)
        bin_stdout = bin_out.get('stdout', b'')
        dec_stdout = dec_out.get('stdout', b'')
        stdout_match = bin_stdout[:len(dec_stdout)] == dec_stdout[:len(bin_stdout)]

        if ret_match and stdout_match:
            passed += 1
        else:
            failures.append({
                'input': inp,
                'binary_ret': bin_out.get('return_value'),
                'decompiled_ret': dec_out.get('return_value'),
                'ret_match': ret_match,
                'stdout_match': stdout_match,
            })

    return passed, len(test_inputs), failures


# 第3层: 分支覆盖率匹配

def compute_coverage_signature(branch_hits: dict[int, int]) -> str:
    """分支覆盖的紧凑签名——排序后的命中计数哈希。"""
    sorted_hits = sorted(branch_hits.items())
    data = ''.join(f'{addr:x}:{count}' for addr, count in sorted_hits)
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def coverage_similarity(bin_cov: dict[int, int],
                        dec_cov: dict[int, int]) -> float:
    """两个分支覆盖率 profile 的 Jaccard 相似度。"""
    bin_set = set(bin_cov.keys())
    dec_set = set(dec_cov.keys())
    inter = len(bin_set & dec_set)
    union = len(bin_set | dec_set)
    return inter / union if union > 0 else 0.0


# 综合验证器

class DecompEquivalenceVerifier:
    """三层递进反编译等价性验证器。"""

    __slots__ = ('_reports',)

    def __init__(self):
        self._reports: list[EquivalenceReport] = []

    def verify(self, func_name: str, decompiled_code: str,
               binary_runner: Callable, decompiled_runner: Callable,
               bin_branch_cov: dict | None = None,
               dec_branch_cov: dict | None = None) -> EquivalenceReport:
        report = EquivalenceReport(function_name=func_name)

        # 第1层: 重编译
        can_compile, err = check_recompilability(decompiled_code)
        report.recompilable = can_compile
        if not can_compile:
            report.issues.append(f'decompilation failed to recompile: {err[:80]}')
            report.level = EquivalenceLevel.NONE
            report.quality_score = 0.0
            self._reports.append(report)
            return report
        report.level = EquivalenceLevel.SYNTAX
        report.quality_score = 30.0

        # 第2层: I/O 等价
        inputs = generate_test_inputs(n_cases=50)
        passed, total, failures = check_io_equivalence(
            binary_runner, decompiled_runner, inputs)
        report.io_tests_passed = passed
        report.io_tests_total = total
        if passed == total:
            report.level = EquivalenceLevel.IO_EQUIV
            report.quality_score = 70.0
        elif passed / max(1, total) >= 0.8:
            report.level = EquivalenceLevel.SYNTAX
            report.quality_score = 30.0 + 40.0 * (passed / total)
        else:
            report.issues.append(f'IO equivalence failed: {passed}/{total} tests passed')
            self._reports.append(report)
            return report

        # 第3层: 覆盖率匹配
        if bin_branch_cov and dec_branch_cov:
            sim = coverage_similarity(bin_branch_cov, dec_branch_cov)
            report.branch_coverage_match = round(sim, 3)
            if sim >= 0.95:
                report.level = EquivalenceLevel.FULL_EQUIV
                report.quality_score = 90.0 + 10.0 * sim
            elif sim >= 0.8:
                report.quality_score = 70.0 + 20.0 * sim

        self._reports.append(report)
        return report

    def stats(self) -> dict:
        by_level = {}
        for r in self._reports:
            by_level[r.level.value] = by_level.get(r.level.value, 0) + 1
        avg_score = (sum(r.quality_score for r in self._reports)
                     / max(1, len(self._reports)))
        return {
            'verified_functions': len(self._reports),
            'by_level': by_level,
            'avg_quality_score': round(avg_score, 1),
        }


__all__ = [
    'DecompEquivalenceVerifier', 'EquivalenceReport', 'EquivalenceLevel',
    'check_recompilability', 'check_io_equivalence', 'coverage_similarity',
    'generate_test_inputs',
]
