# 分支范围路径条件分析器 (Branch-Scoped Path Condition Analyzer)
#
# 核心创新: 在线性指令流中识别条件分支的语义范围 (branch scope),
# 精确判定 free 和 use 是否落在同一分支路径上.
#
# 传统路径敏感分析在二进制层面面临两个困难:
#   1. 线性反汇编丢失 CFG 结构 - 无法直接获取支配关系
#   2. 路径爆炸 - 完整路径枚举代价过高
#
# 本模块采用分支范围近似:
# 每个 jcc 指令定义一个分支范围 [jcc_addr, merge_addr]
# taken 路径: jcc → target
# fallthrough 路径: jcc → jcc+len → merge
#   - merge_addr = min(target, jcc+1 之后的第一条非顺序指令的目标)
#
# 对 free-use 对, 若 free 在 taken 路径且 use 在 fallthrough 路径
# (或反之), 两者互斥 → 过滤该 UAF 告警.
#
# 理论依据:
#   分支条件驱动的区间窄化; 路径敏感二进制分析降低误报;
#   跨入口UAF检测用路径敏感排除不可达对.
#

import re
from typing import Dict, List, Optional, Set, Tuple


class BranchScope:
    """单个条件分支的语义范围."""
    __slots__ = ("jcc_addr", "target", "fallthrough", "merge_addr",
                 "taken_range", "fallthrough_range", "condition_reg",
                 "condition_val", "is_taken_branch", "ret_addr", "jmp_addr")

    def __init__(self, jcc_addr: int, target: int, fallthrough: int,
                 merge_addr: int, condition_reg: str = "",
                 condition_val: int = 0, is_taken_branch: bool = True,
                 ret_addr: Optional[int] = None,
                 jmp_addr: Optional[int] = None):
        self.jcc_addr = jcc_addr
        self.target = target
        self.fallthrough = fallthrough
        self.merge_addr = merge_addr
        self.ret_addr = ret_addr
        self.jmp_addr = jmp_addr
        # backward merge: fallthrough经ret退出, taken路径回跳到merge_addr
        # taken_range为target到jmp指令, fallthrough_range为fallthrough到ret
        if merge_addr < target and ret_addr is not None:
            self.taken_range = (target, jmp_addr if jmp_addr is not None else target)
            self.fallthrough_range = (fallthrough, ret_addr)
        else:
            # 前向跳转: merge_addr是汇合点, taken路径到达但不包含merge
            self.taken_range = (min(target, merge_addr), max(target, merge_addr) - 1)
            self.fallthrough_range = (fallthrough, merge_addr)
        self.condition_reg = condition_reg
        self.condition_val = condition_val
        self.is_taken_branch = is_taken_branch


class PathAnalyzer:
    """分支范围路径条件分析器.

    两阶段:
      Phase 1 (build_scope_map): 扫描指令流, 对每个 jcc 构建 BranchScope
      Phase 2 (check_mutually_exclusive): 对 free-use 对判定路径互斥性
    """

    _JCC_MNEMS = {"je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                  "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns"}
    _CMP_MNEMS = {"cmp", "test"}

    def __init__(self):
        self._scopes: List[BranchScope] = []
        self._addr_to_scopes: Dict[int, List[BranchScope]] = {}
        self._last_cmp_reg: str = ""
        self._last_cmp_val: int = 0
        self._last_cmp_addr: int = 0
        self._user_func_ranges: List[Tuple[int, int]] = []

    def build_scope_map(self, instructions: List[dict],
                        user_func_ranges: Optional[List[Tuple[int, int]]] = None):
        """Phase 1: 扫描线性指令流构建分支范围图."""
        self._scopes.clear()
        self._addr_to_scopes.clear()
        self._user_func_ranges = user_func_ranges or []

        n = len(instructions)
        for i, ins in enumerate(instructions):
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)

            if mnem in self._CMP_MNEMS and len(ops) >= 2:
                reg = self._norm_reg(ops[0])
                val = self._parse_imm(ops[1])
                if val is not None:
                    self._last_cmp_reg = reg
                    self._last_cmp_val = val
                    self._last_cmp_addr = addr
                continue

            if mnem not in self._JCC_MNEMS or not ops:
                continue

            target = self._parse_jmp_target(ops[0])
            if target is None:
                continue

            fallthrough = instructions[i + 1].get("address", 0) if i + 1 < n else addr + 1
            merge_addr, ret_addr, jmp_addr = self._find_merge_point(
                instructions, i, target, fallthrough, addr)

            cond_reg = self._last_cmp_reg if (addr - self._last_cmp_addr <= 30) else ""
            cond_val = self._last_cmp_val if cond_reg else 0

            scope = BranchScope(
                jcc_addr=addr, target=target, fallthrough=fallthrough,
                merge_addr=merge_addr, condition_reg=cond_reg,
                condition_val=cond_val, ret_addr=ret_addr, jmp_addr=jmp_addr)

            self._scopes.append(scope)
            for lo, hi in (scope.taken_range, scope.fallthrough_range):
                if lo <= hi:
                    for a in range(lo, hi + 1):
                        self._addr_to_scopes.setdefault(a, []).append(scope)

    def _find_merge_point(self, instructions: List[dict], jcc_idx: int,
                           target: int, fallthrough: int,
                           jcc_addr: int = 0
                           ) -> Tuple[int, Optional[int], Optional[int]]:
        """推断分支汇合点.

        返回 (merge_addr, ret_addr, jmp_addr):
          merge_addr - 分支汇合点
          ret_addr - fallthrough路径中的ret地址(backward merge时用于range)
          jmp_addr - taken路径中的jmp地址(backward merge时用于range)

        target < fallthrough: 后向跳转(循环), merge=target.
        target > fallthrough: 前向跳转, 扫描fallthrough路径中的
          无条件jmp或ret - ret表示fallthrough路径提前退出,
          taken路径延伸到jmp回跳点. 无jmp/ret则merge=target.
        """
        if target == fallthrough:
            return target, None, None
        if target < fallthrough:
            return target, None, None
        addr_to_idx = {ins.get("address", 0): i for i, ins in enumerate(instructions)}
        ft_idx = addr_to_idx.get(fallthrough, jcc_idx + 1)
        tgt_idx = addr_to_idx.get(target, len(instructions))
        for k in range(ft_idx, min(tgt_idx, len(instructions))):
            ins = instructions[k]
            mnem = ins.get("mnemonic", "").lower()
            if mnem == "jmp" and ins.get("operands"):
                jmp_tgt = self._parse_jmp_target(ins["operands"][0])
                if jmp_tgt is not None and jmp_tgt >= target:
                    # tail-call: jmp目标不在当前函数范围内 → 不是回跳merge
                    if self._is_tailcall(jmp_tgt, jcc_addr):
                        continue
                    return jmp_tgt, None, None
            if mnem == "ret":
                ret_addr_val = ins.get("address", 0)
                for j in range(tgt_idx, min(len(instructions), tgt_idx + 50)):
                    nxt = instructions[j]
                    if nxt.get("mnemonic", "").lower() == "jmp" and nxt.get("operands"):
                        jmp_tgt = self._parse_jmp_target(nxt["operands"][0])
                        if jmp_tgt is not None:
                            return jmp_tgt, ret_addr_val, nxt.get("address", 0)
                break
        if target in addr_to_idx:
            return target, None, None
        return fallthrough, None, None

    def _is_tailcall(self, jmp_target: int, jcc_addr: int) -> bool:
        """jmp目标超出jcc所在函数范围 → tail-call而非回跳."""
        if not self._user_func_ranges:
            return False
        for lo, hi in self._user_func_ranges:
            if lo <= jcc_addr < hi:
                return not (lo <= jmp_target < hi)
        return False

    def are_mutually_exclusive(self, free_addr: int, use_addr: int) -> bool:
        """判定 free 和 use 是否落在互斥的分支路径上."""
        free_scope = self._find_innermost_scope(free_addr)
        use_scope = self._find_innermost_scope(use_addr)

        if free_scope is None or use_scope is None:
            return False
        if free_scope.jcc_addr != use_scope.jcc_addr:
            return False

        free_in_taken = self._in_taken_path(free_addr, free_scope)
        use_in_taken = self._in_taken_path(use_addr, use_scope)

        return free_in_taken != use_in_taken

    def _find_innermost_scope(self, addr: int) -> Optional[BranchScope]:
        """查找包含该地址的最内层分支范围."""
        scopes = list(self._addr_to_scopes.get(addr, []))
        if not scopes:
            for s in self._scopes:
                if s.taken_range[0] <= addr <= s.taken_range[1]:
                    scopes.append(s)
                elif s.fallthrough_range[0] <= addr <= s.fallthrough_range[1]:
                    scopes.append(s)
        if not scopes:
            return None
        return min(scopes, key=lambda s: s.merge_addr - s.jcc_addr)

    @staticmethod
    def _in_taken_path(addr: int, scope: BranchScope) -> bool:
        """判定地址是否在 taken 路径上 (非 fallthrough)."""
        lo, hi = scope.taken_range
        return lo <= addr <= hi

    @staticmethod
    def _norm_reg(reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "")
        return {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                "esi": "rsi", "edi": "rdi", "r8d": "r8", "r9d": "r9",
                "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
                "si": "rsi", "di": "rdi"}.get(r, r)

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("%").replace("$", "")
        if "#" in s:
            s = s.split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    @staticmethod
    def _parse_jmp_target(operand: str) -> Optional[int]:
        o = operand.strip().lower().split("<")[0].strip()
        if not o:
            return None
        if o.startswith("0x"):
            try:
                return int(o, 16)
            except ValueError:
                return None
        if re.match(r'^[0-9a-f]{5,}$', o):
            return int(o, 16)
        return None


__all__ = ["PathAnalyzer", "BranchScope"]
