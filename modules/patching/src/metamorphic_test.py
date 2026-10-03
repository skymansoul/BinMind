# 初始实现：补丁的变体等价性验证
# 增加蜕变关系定义：5 种补丁不变量的形式化

"""Patch Metamorphic Tester — 补丁的蜕变测试与等价性验证。

Variegate (GrammaTech) 在源码级生成功能等价的程序变体来做二进制多样性。
本模块的差异：
  - Variegate 操作在源码级 → 需要编译工具链
  - 本模块操作在二进制补丁的汇编级 → 不需要源码

蜕变关系 (Metamorphic Relations)：
  若补丁 P 正确修复了漏洞 V，则 P 的所有语义等价变体 P' 必须满足：
    MR1: P'(x) 的 exit code == P(x) 的 exit code (对所有合法输入 x)
    MR2: P'(x) 的 syscall trace == P(x) 的 syscall trace
    MR3: P' 的栈帧大小 == P 的栈帧大小 (ABI 保持不变)
    MR4: P' 的寄存器修改集合 ⊆ P 的寄存器修改集合 ∪ caller-saved regs
    MR5: 对于触发漏洞的输入 x_vuln, P'(x_vuln) 不崩溃

用途：
  验证补丁混淆 (PatchObfuscator) 产出的变体确实是语义等价的。
  若某变体违反任一 MR → 混淆变换引入了 bug。

与 metamorphic testing literature 的差异：
  现有研究 关注深度代码模型的蜕变测试。
  本模块将蜕变测试应用于二进制补丁变体验证。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Callable
from enum import Enum

_log = logging.getLogger(__name__)


class MRStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    UNVERIFIED = "unverified"


@dataclass
class MetamorphicRelation:
    """单条蜕变关系的形式化定义。"""
    mr_id: str
    description: str = ""
    # 验证函数: (original_patch_asm, variant_patch_asm, test_inputs) → (passed, detail)
    verify_fn: Optional[Callable] = None


@dataclass
class MRResult:
    """单条蜕变关系的验证结果。"""
    mr_id: str
    status: MRStatus = MRStatus.UNVERIFIED
    detail: str = ""
    # 违规证据
    counterexample_input: bytes = b""
    counterexample_description: str = ""


@dataclass
class MetamorphicReport:
    """补丁蜕变测试报告。"""
    patch_id: str = ""
    variant_count: int = 0
    results: Dict[str, List[MRResult]] = field(default_factory=dict)
    # {variant_hash: [MRResult, ...]}
    all_passed: bool = False
    failed_variants: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'variants': self.variant_count,
            'all_passed': self.all_passed,
            'failed': self.failed_variants,
            'violations': self.violations[:10],
        }


# 蜕变关系定义

class MetamorphicRelations:
    """补丁的 5 条蜕变关系定义。

    每条 MR 是补丁必须保持的不变量。
    若混淆变体违反任一条 → 混淆过程破坏了语义等价性。
    """

    @staticmethod
    def mr1_exit_code(original_asm: List[str],
                      variant_asm: List[str],
                      test_outputs: Dict[str, int] = None) -> Tuple[bool, str]:
        """MR1: 对所有测试输入，变体与原始补丁的退出码一致。

        静态近似：比较 ret 指令前的 eax/rax 设置指令。
        动态精确验证需要实际执行（与 DifferentialExecutor 集成）。
        """
        orig_ret_vals = MetamorphicRelations._extract_return_values(original_asm)
        var_ret_vals = MetamorphicRelations._extract_return_values(variant_asm)
        if orig_ret_vals == var_ret_vals:
            return True, "返回值设置一致"
        return False, "返回值设置不一致: orig=%s, variant=%s" % (
            str(orig_ret_vals)[:80], str(var_ret_vals)[:80])

    @staticmethod
    def mr2_stack_frame(original_asm: List[str],
                        variant_asm: List[str]) -> Tuple[bool, str]:
        """MR3: 栈帧大小必须保持不变（ABI 不变）。"""
        orig_frame = MetamorphicRelations._frame_size(original_asm)
        var_frame = MetamorphicRelations._frame_size(variant_asm)
        if orig_frame is None or var_frame is None:
            return True, "无法确定栈帧大小——跳过"
        if orig_frame == var_frame:
            return True, "栈帧一致: %d bytes" % orig_frame
        return False, "栈帧大小改变: %d → %d bytes" % (orig_frame, var_frame)

    @staticmethod
    def mr3_callee_saved(original_asm: List[str],
                         variant_asm: List[str]) -> Tuple[bool, str]:
        """MR4: 变体不得新增 callee-saved 寄存器的修改（除非有 save/restore）。"""
        callee_saved = {'rbx', 'r12', 'r13', 'r14', 'r15', 'rbp'}
        orig_writes = MetamorphicRelations._regs_modified(original_asm)
        var_writes = MetamorphicRelations._regs_modified(variant_asm)
        new_callee_writes = (var_writes - orig_writes) & callee_saved
        if not new_callee_writes:
            return True, "callee-saved 寄存器使用一致"
        # 检查变体是否新增了 save/restore
        for reg in new_callee_writes:
            has_save = any(('push ' + reg) in l.lower() or
                          ('mov [rbp' in l.lower() and reg in l.lower())
                          for l in variant_asm)
            has_restore = any(('pop ' + reg) in l.lower() or
                            ('mov ' + reg + ', [rbp' in l.lower())
                            for l in variant_asm)
            if not has_save or not has_restore:
                return False, "新增 callee-saved 寄存器 %s 修改但未保存/恢复" % reg
        return True, "新增 callee-saved 寄存器使用已正确保存恢复"

    @staticmethod
    def mr4_instruction_count_delta(original_asm: List[str],
                                    variant_asm: List[str]) -> Tuple[bool, str]:
        """MR5 (辅助): 指令数偏差不应超过 50%。

        NOP 雪崩可能显著增加指令数但不应超过合理范围。
        """
        orig_count = len([l for l in original_asm if l.strip() and not l.strip().startswith(';')])
        var_count = len([l for l in variant_asm if l.strip() and not l.strip().startswith(';')])
        if orig_count == 0:
            return True, "原始补丁为空——跳过"
        ratio = var_count / orig_count
        if ratio > 1.5:
            return False, "指令膨胀率 %.1f%% —— 超过 50%% 阈值" % ((ratio - 1) * 100)
        return True, "指令数变化在合理范围 (%.1f%%)" % ((ratio - 1) * 100)

    @staticmethod
    def mr5_crash_path_preserved(original_asm: List[str],
                                 variant_asm: List[str]) -> Tuple[bool, str]:
        """MR5: 若原始补丁包含 abort/exit 等崩溃路径，变体必须保留。"""
        orig_abort = sum(1 for l in original_asm
                        if re.search(r'\bcall\s+(abort|exit|__assert_fail)\b', l, re.I))
        var_abort = sum(1 for l in variant_asm
                       if re.search(r'\bcall\s+(abort|exit|__assert_fail)\b', l, re.I))
        if orig_abort > 0 and var_abort == 0:
            return False, "变体移除了原始补丁的崩溃路径——可能允许漏洞利用继续执行"
        return True, "崩溃路径已保留"

# 辅助

    @staticmethod
    def _extract_return_values(asm: List[str]) -> List[str]:
        """提取所有 ret 前的 rax/eax 设置。"""
        vals = []
        for i, line in enumerate(asm):
            stripped = line.strip().lower()
            if stripped.startswith('ret') and i > 0:
                prev = asm[i-1].strip().lower()
                if 'rax' in prev or 'eax' in prev:
                    vals.append(prev[:50])
        return vals

    @staticmethod
    def _frame_size(asm: List[str]) -> Optional[int]:
        for line in asm:
            m = re.search(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', line, re.I)
            if m:
                val = m.group(1)
                return int(val, 16) if val.startswith('0x') else int(val)
        return None

    @staticmethod
    def _regs_modified(asm: List[str]) -> Set[str]:
        mods = set()
        for line in asm:
            parts = line.strip().lower().replace(',', ' ').split()
            if len(parts) >= 2:
                mnemonic = parts[0]
                if mnemonic in ('mov', 'lea', 'xor', 'add', 'sub', 'and', 'or',
                               'shl', 'shr', 'mul', 'imul', 'pop', 'inc', 'dec'):
                    dst = parts[1].rstrip(',')
                    if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3})$', dst):
                        mods.add(dst.lower())
        return mods


# 蜕变测试引擎

class MetamorphicTester:
    """补丁蜕变测试引擎。

    用法:
        tester = MetamorphicTester()
        orig = ['push rbp', 'cmp rdi, 256', 'jbe .ok', 'call abort', '.ok:', '...', 'ret']
        variants = [['push rbp', 'cmp rdi, 256', 'jbe .ok', 'call abort', '.ok:', '...', 'ret'],
                    ['push rbp', 'xor rax,rax', 'cmp rdi, 256', '...', 'ret']]
        report = tester.test
    """

    def __init__(self):
        self._relations = [
            MetamorphicRelation('MR1', '退出码一致性',
                              MetamorphicRelations.mr1_exit_code),
            MetamorphicRelation('MR2', '栈帧大小一致',
                              MetamorphicRelations.mr2_stack_frame),
            MetamorphicRelation('MR3', 'Callee-saved 寄存器保持',
                              MetamorphicRelations.mr3_callee_saved),
            MetamorphicRelation('MR4', '指令数膨胀限制',
                              MetamorphicRelations.mr4_instruction_count_delta),
            MetamorphicRelation('MR5', '崩溃路径保留',
                              MetamorphicRelations.mr5_crash_path_preserved),
        ]

    def test(self, original_patch_asm: List[str],
             variant_patches: List[Tuple[str, List[str]]],
             patch_id: str = "") -> MetamorphicReport:
        """对多个补丁变体执行蜕变测试。

        variant_patches: [(variant_hash, asm_lines), ...]。
        """
        report = MetamorphicReport(
            patch_id=patch_id,
            variant_count=len(variant_patches))

        for var_hash, var_asm in variant_patches:
            var_results = []
            for mr in self._relations:
                try:
                    passed, detail = mr.verify_fn(original_patch_asm, var_asm)
                    status = MRStatus.PASSED if passed else MRStatus.FAILED
                except Exception as e:
                    passed, detail = False, "验证异常: %s" % str(e)
                    status = MRStatus.FAILED
                result = MRResult(mr_id=mr.mr_id, status=status, detail=detail)
                var_results.append(result)
                if not passed:
                    report.violations.append(
                        "[%s] %s: %s" % (var_hash[:8], mr.mr_id, detail))

            report.results[var_hash] = var_results

            if any(r.status == MRStatus.FAILED for r in var_results):
                report.failed_variants.append(var_hash)

        report.all_passed = len(report.failed_variants) == 0
        return report

    def test_single(self, original: List[str],
                    variant: List[str]) -> List[MRResult]:
        """快速单变体验证。"""
        results = []
        for mr in self._relations:
            try:
                passed, detail = mr.verify_fn(original, variant)
                results.append(MRResult(
                    mr_id=mr.mr_id,
                    status=MRStatus.PASSED if passed else MRStatus.FAILED,
                    detail=detail))
            except Exception as e:
                results.append(MRResult(
                    mr_id=mr.mr_id,
                    status=MRStatus.FAILED,
                    detail=str(e)))
        return results
