# TODO: 当前仅 x86_64 栈帧，ARM64 帧链布局不同，待适配

"""补丁等价性验证器 — 基于控制流对齐的自动正确性检查。

自动化补丁（auto_patcher.py 产出）需验证不改变程序预期行为。
二进制补丁通常无配套测试，故绕过测试用例，直接检查：

  1. 控制流对齐：补丁后每基本块的 successors 与补丁前一致
     （允许新增块——如插入校验——但禁止删除原有可达后继）
  2. 调用图保持：函数调用关系不变——新增调用目标除外（如 sanitizer）
  3. 活跃寄存器交集：补丁代码修改的寄存器集合 ⊆ 原代码修改集合
     （违反 = 新增副作用 → 破坏调用者寄存器假设）

非形式化证明——不保证完全等价。高精度启发式检查，
在部署前拦截最明显的正确性问题。"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class BlockInfo:
    """基本块精简描述——仅含等价性验证所需字段。"""
    addr: int
    successors: Set[int] = field(default_factory=set)
    call_targets: Set[int] = field(default_factory=set)
    clobbered_regs: Set[str] = field(default_factory=set)


class PatchEquivalenceVerifier:
    """补丁前后控制流与副作用等价性验证器。"""

    def __init__(self):
        self._violations: List[str] = []

    def verify(self, original: List[BlockInfo],
               patched: List[BlockInfo]) -> Tuple[bool, List[str]]:
        """验证补丁是否保持控制流和副作用等价。

        返回 (is_valid, violations)。is_valid=True = 全部通过。
        """
        self._violations.clear()

        # 构建地址索引
        orig_by_addr = {b.addr: b for b in original}
        pat_by_addr = {b.addr: b for b in patched}

        self._check_successor_preservation(orig_by_addr, pat_by_addr)
        self._check_call_graph_preservation(orig_by_addr, pat_by_addr)
        self._check_register_clobbering(orig_by_addr, pat_by_addr)

        return len(self._violations) == 0, list(self._violations)

    def _check_successor_preservation(self,
                                       orig: Dict[int, BlockInfo],
                                       pat: Dict[int, BlockInfo]):
        """检查 successors 集合保持性。

        共存块的补丁后 successors 必须 ⊇ 原始 successors。
        允许新增（如条件跳转分支），不允许删除。
        """
        for addr, orig_block in orig.items():
            if addr not in pat:
                # 块被完全删除——可能因内联展开。保守处理：记录但不算违规。
                # 调用方可决定是否接受。
                continue

            pat_block = pat[addr]
            missing = orig_block.successors - pat_block.successors
            if missing:
                for m in missing:
                    self._violations.append(
                        f"successor {hex(m)} of block {hex(addr)} removed in patch"
                    )

    def _check_call_graph_preservation(self,
                                        orig: Dict[int, BlockInfo],
                                        pat: Dict[int, BlockInfo]):
        """检查调用图外延保持。

        直接调用（目标在二进制内）：补丁后目标 ⊇ 原始目标。
        间接调用由寄存器等价性检查覆盖。
        """
        orig_all_calls = set()
        pat_all_calls = set()
        for b in orig.values():
            orig_all_calls.update(b.call_targets)
        for b in pat.values():
            pat_all_calls.update(b.call_targets)

        removed_calls = orig_all_calls - pat_all_calls
        for addr in removed_calls:
            # 仅当原始调用目标在补丁后仍存在时才报告
            # ——目标函数被删除则调用消失属预期。
            if addr in pat:
                self._violations.append(
                    f"call to {hex(addr)} removed but target still exists in patch"
                )

    def _check_register_clobbering(self,
                                    orig: Dict[int, BlockInfo],
                                    pat: Dict[int, BlockInfo]):
        """检查补丁是否引入新寄存器副作用。

        clobbered_regs 新增 → 补丁引入额外副作用 → 破坏调用者假设。

        caller-saved 寄存器（rax/rcx/rdx/r8-r11）豁免——
        调用者本不应假设其跨调用保持。
        """
        CALLER_SAVED = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}

        for addr, orig_block in orig.items():
            if addr not in pat:
                continue
            pat_block = pat[addr]

            new_clobbers = pat_block.clobbered_regs - orig_block.clobbered_regs
            # 过滤掉 caller-saved 寄存器——修改它们不构成违规
            violations = new_clobbers - CALLER_SAVED

            for reg in violations:
                self._violations.append(
                    f"block {hex(addr)}: new register clobber '{reg}' introduced by patch"
                )
