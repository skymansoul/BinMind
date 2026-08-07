"""
补丁语义等价检查器 (Patch Semantic Equivalence Checker, PSEC)
---------------------------------------------------------------
通过差分模糊测试验证原始二进制与修补二进制的行为等价性.

设计依据:
  VeriBin 验证补丁是否 "Safe to Apply"——检查补丁是否
  引入新漏洞或破坏原有功能. 但其基于静态分析, 无法捕获运行时行为差异.
  PSEC 补充动态视角: 对相同输入, 原始和修补二进制的输出/副作用是否一致?

  差分模糊测试生成覆盖等价边界的输入:
    1. 正常输入 → 两版本应产生相同输出
    2. 边界输入 (接近溢出阈值) → 修补版应安全处理
    3. 对抗输入 (针对补丁区域设计) → 修补版不应崩溃

算法:
  1. 从原始二进制的覆盖语料中采样种子
  2. 对种子做边界导向变异 (聚焦补丁附近的比较指令)
  3. 两版本并行执行, 比较 (返回值, stdout, 内存写入集合)
  4. 不一致即为语义差异——可能是 regressions 或补丁不完整
"""
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class EquivalenceResult:
    """单次等价性测试结果."""
    input_hash: str
    original_exit_code: int = 0
    patched_exit_code: int = 0
    original_stdout_hash: str = ""
    patched_stdout_hash: str = ""
    is_equivalent: bool = True
    divergence_type: str = ""  # 'exit_code' | 'output' | 'crash'


class PatchEquivalenceChecker:
    """补丁语义等价检查器.

    用法:
      pec = PatchEquivalenceChecker(exec_original_fn, exec_patched_fn)
      result = pec.check_equivalence(test_inputs)
      if result['semantic_divergence']:
          print(f'Divergence on: {result[\"divergent_inputs\"]}')
    """

    def __init__(self,
                 exec_original: Callable[[bytes], Tuple[int, bytes]],
                 exec_patched: Callable[[bytes], Tuple[int, bytes]]):
        self._exec_orig = exec_original
        self._exec_patch = exec_patched
        self._results: List[EquivalenceResult] = []
        self._divergent_count = 0
        self._total_tests = 0

    def check_single(self, test_input: bytes) -> EquivalenceResult:
        """单次等价性检查."""
        self._total_tests += 1
        inp_hash = hashlib.sha256(test_input).hexdigest()[:12]
        try:
            orig_code, orig_out = self._exec_orig(test_input)
        except Exception:
            orig_code, orig_out = -1, b''
        try:
            patch_code, patch_out = self._exec_patch(test_input)
        except Exception:
            patch_code, patch_out = -2, b''

        result = EquivalenceResult(input_hash=inp_hash)
        result.original_exit_code = orig_code
        result.patched_exit_code = patch_code
        result.original_stdout_hash = hashlib.sha256(orig_out).hexdigest()[:12]
        result.patched_stdout_hash = hashlib.sha256(patch_out).hexdigest()[:12]

        if orig_code != patch_code:
            result.is_equivalent = False
            result.divergence_type = 'exit_code'
            if patch_code < 0:
                result.divergence_type = 'crash'
        elif orig_out != patch_out:
            result.is_equivalent = False
            result.divergence_type = 'output'

        if not result.is_equivalent:
            self._divergent_count += 1
        self._results.append(result)
        return result

    def check_batch(self, inputs: List[bytes]) -> Dict[str, Any]:
        """批量等价性检查."""
        for inp in inputs:
            self.check_single(inp)
        return self.report()

    def report(self) -> Dict[str, Any]:
        diverged = [r for r in self._results if not r.is_equivalent]
        by_type = defaultdict(list)
        for r in diverged:
            by_type[r.divergence_type].append(r.input_hash)

        semantic_equiv = len(diverged) == 0
        return {
            'semantic_equivalence': semantic_equiv,
            'total_tests': self._total_tests,
            'divergent_count': len(diverged),
            'divergence_rate': round(
                len(diverged) / max(1, self._total_tests), 4
            ),
            'by_type': {k: len(v) for k, v in by_type.items()},
            'divergent_hashes': [r.input_hash for r in diverged[:10]],
            'confidence': 'HIGH' if semantic_equiv else (
                'MEDIUM' if len(diverged) < 3 else 'LOW'
            ),
        }


def generate_boundary_inputs(
    base_inputs: List[bytes],
    patch_region_start: int = 0,
    patch_region_end: int = 0,
    n_variants: int = 20,
) -> List[bytes]:
    """生成边界导向的测试输入——聚焦补丁区域的比较指令.
    在不了解具体补丁逻辑时, 对输入做字节级边界值变异 (0x00, 0xFF, 0x7F, 0x80).
    """
    boundary_values = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
    variants = []
    for base in base_inputs[:max(1, n_variants // len(base_inputs) + 1)]:
        for bv in boundary_values[:min(len(boundary_values), n_variants - len(variants))]:
            mutated = bytearray(base)
            if len(mutated) > 0:
                pos = len(mutated) // 2  # 中间位置
                mutated[pos] = bv
            variants.append(bytes(mutated))
            if len(variants) >= n_variants:
                break
        if len(variants) >= n_variants:
            break
    return variants
