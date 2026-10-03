"""DRIFT Temporal Path Verifier — per-finding线性模拟的UAF时间验证.

free后寄存器/栈槽被覆盖→过滤FP; freed状态追踪+别名传播.
对每个free→use对, 从函数入口模拟到use行, 检查use_reg是否仍持有freed对象.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from .object_identity import (
    _canon_reg, _ALLOC_FUNCS, _FREE_FUNCS,
    _MOV_REG, _MOV_STACK_LOAD, _MOV_STACK_STORE,
    _LEA_PAT, _XOR_ZERO, _parse_int)


@dataclass
class PathBlockState:
    """抽象状态: 寄存器/栈槽持有的对象及状态(live|freed)."""
    reg_obj: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    stack_obj: Dict[int, Tuple[str, str]] = field(default_factory=dict)
    was_freed: set = field(default_factory=set)
    def get_reg_obj(self, reg: str) -> Optional[Tuple[str, str]]:
        return self.reg_obj.get(_canon_reg(reg))
    def set_reg(self, reg: str, oid_label: str, status: str):
        self.reg_obj[_canon_reg(reg)] = (oid_label, status)
    def kill_reg(self, reg: str):
        self.reg_obj.pop(_canon_reg(reg), None)

# mov [rbp+N], imm → kill栈槽
_MOV_STACK_STORE_IMM = re.compile(
    r'\bmov\s+(?:qword|dword|word|byte)(?:\s+ptr)?\s+'
    r'\[(?:rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\],\s*'
    r'(0x[0-9a-f]+|\d+)', re.I)
_MOV_IMM = re.compile(r'\bmov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', re.I)

class TemporalPathVerifier:
    """路径敏感的UAF时间验证器 — per-finding线性模拟."""
    _FREE_ARG_REGS = ['rdi', 'rcx']
    _CALLER_SAVED = ['rax','rcx','rdx','r8','r9','r10','r11']

    def __init__(self, sim_window: int = 500):
        self._sim_window = sim_window

    def verify(self, asm_lines: List[str],
               uaf_findings: List[dict]) -> List[dict]:
        """主入口: per-finding线性模拟."""
        verified = []
        for f in uaf_findings:
            result = self._verify_one(f, asm_lines)
            if result:
                verified.append(result)
        return verified

    def _verify_one(self, finding: dict, asm_lines: List[str]) -> Optional[dict]:
        """Per-finding线性模拟: 函数入口→use行."""
        free_line = finding.get('free_line', -1)
        use_line = finding.get('use_line', -1)
        use_reg = finding.get('use_reg', '')

        # double-free特殊处理: 无需寄存器级别验证, 但需排除CRT artifact
        is_double_free = finding.get('double_free', False)
        if is_double_free:
            alloc_line = finding.get('alloc_line', -1)
            # 跨函数double-free (alloc在用户代码, free在CRT) → artifact
            if alloc_line > 0 and free_line - alloc_line > 500:
                return None  # CRT artifact, 过滤
            finding['temporal_verified'] = True
            finding['temporal_skipped'] = False
            finding['double_free_verified'] = True
            finding['confidence'] = min(1.0, finding.get('confidence', 0.9) + 0.05)
            oid = finding.get('obj_id', '?')
            finding['temporal_evidence'] = (
                f'double-free-verified: {oid} '
                f'free@{free_line} alloc@{alloc_line}')
            return finding

        # 无法做时间验证的finding: use_reg为空
        if not use_reg:
            finding['temporal_skipped'] = True
            finding['temporal_verified'] = False
            finding['confidence'] = finding.get('confidence', 0.5) * 0.25
            finding['temporal_evidence'] = 'temporal-skip: no use_reg (artifact)'
            return finding
        if free_line < 0:
            finding['temporal_skipped'] = True
            finding['temporal_verified'] = False
            finding['confidence'] = finding.get('confidence', 0.5) * 0.2
            finding['temporal_evidence'] = (
                f'temporal-skip: free={free_line} use={use_line} (invalid range)')
            return finding

        # 跨函数free-before-use: free在调用者, use在被调者.
        # 地址序use_line<free_line (被调者地址低), 但执行序free先于use.
        # FreeUseValidator已通过调用图遍历验证了时间序和对象身份.
        if use_line <= free_line:
            return self._verify_cross_fn_order(finding, asm_lines)

        # 找函数入口: 从free_line向上扫描找函数标签 <func>:
        fn_start = self._find_func_start(asm_lines, free_line)

        # 跨函数检测: 若use_line远离free_line(>300行), 检查是否跨函数边界
        actual_distance = use_line - free_line
        if actual_distance > 300:
            # 检查free和use是否在同一个函数内
            use_fn_start = self._find_func_start(asm_lines, use_line)
            if use_fn_start != fn_start:
                # 跨函数边界 → 无法在当前模拟中验证 → 大幅降级
                finding['temporal_skipped'] = True
                finding['temporal_verified'] = False
                finding['confidence'] = finding.get('confidence', 0.5) * 0.2
                finding['temporal_evidence'] = (
                    f'temporal-skip: cross-function free@{free_line}'
                    f'(fn@{fn_start})→use@{use_line}(fn@{use_fn_start})')
                return finding

        state = PathBlockState()
        for i in range(fn_start, use_line + 1):
            if i >= len(asm_lines):
                break
            self._exec_insn_oneline(asm_lines[i], i, state)

        # 检查: use_reg在state中是否为freed
        rv = state.get_reg_obj(use_reg)
        if rv and rv[1] == 'freed':
            finding['temporal_verified'] = True
            finding['temporal_skipped'] = False
            finding['confidence'] = min(1.0, finding.get('confidence', 0.5) + 0.15)
            finding['temporal_evidence'] = (
                f'temporal-verified: {rv[0]} freed in {use_reg} '
                f'line {free_line}→{use_line}')
            return finding

        # 对象曾被freed, 但use_reg不再持有它 (被覆盖/清零) → FP
        if state.was_freed and (rv is None or rv[1] == 'live'):
            # 若有freed对象但use_reg不是freed → 中间被覆盖
            return None  # 过滤FP

        # rv存在但不是freed (是live的另一个对象) → 也是FP
        if rv and rv[1] == 'live' and state.was_freed:
            return None

        # 从未freed → 保守保留但降级
        finding['temporal_verified'] = False
        finding['temporal_skipped'] = False
        finding['confidence'] = finding.get('confidence', 0.5) * 0.7
        return finding

    def _verify_cross_fn_order(self, finding: dict,
                                asm_lines: List[str]) -> Optional[dict]:
        """跨函数执行序验证: free在调用者, use在被调者.

        地址序: use_line < free_line (被调者地址低, 在asm_lines中先出现).
        执行序: 调用者free → call callee → callee use.
        FreeUseValidator已通过调用图遍历验证了时间序和对象身份,
        此处做轻量级线性模拟确认use_reg在参数传递链中.
        """
        free_line = finding.get('free_line', -1)
        use_line = finding.get('use_line', -1)
        use_reg = finding.get('use_reg', '')
        oid = finding.get('obj_id', '?')

        # 从use所在函数入口模拟到use行
        use_fn_start = self._find_func_start(asm_lines, use_line)
        state = PathBlockState()

        # 种子参数寄存器: x64 Windows前4参在rcx/rdx/r8/r9.
        # 标记为freed状态 (调用者在call前已free).
        for param_reg in ('rcx', 'rdx', 'r8', 'r9'):
            state.set_reg(param_reg, oid, 'freed')
            state.was_freed.add(oid)

        for i in range(use_fn_start, use_line + 1):
            if i >= len(asm_lines):
                break
            self._exec_insn_oneline(asm_lines[i], i, state)

        # 检查use_reg在use点是否持有freed对象
        rv = state.get_reg_obj(use_reg)
        if rv is not None and rv[1] == 'freed':
            finding['temporal_verified'] = True
            finding['temporal_skipped'] = False
            finding['confidence'] = min(1.0, finding.get('confidence', 0.5) + 0.08)
            finding['temporal_evidence'] = (
                f'cross-fn-verified: {oid} freed@caller L{free_line}, '
                f'use@{use_reg}@{use_line} (execution-order validated)')
            return finding

        # use_reg可能被覆盖或参数链断裂
        if rv is not None and state.was_freed:
            # 持有live对象但freed对象在别处 → 可能不是同一对象
            finding['temporal_verified'] = False
            finding['temporal_skipped'] = False
            finding['confidence'] = finding.get('confidence', 0.5) * 0.4
            finding['temporal_evidence'] = (
                f'cross-fn-overwritten: {oid} free@L{free_line} '
                f'use@{use_reg}@L{use_line} (reg overwritten)')
            return finding

        # use_reg无对象 → 参数传递链完全断裂, 保守降级
        finding['temporal_verified'] = False
        finding['temporal_skipped'] = False
        finding['confidence'] = finding.get('confidence', 0.5) * 0.3
        finding['temporal_evidence'] = (
            f'cross-fn-uncertain: {oid} free@L{free_line} use@{use_reg}@L{use_line} '
            f'(param chain broken)')
        return finding

    _FN_LABEL = re.compile(r'[0-9a-f]+\s+<[^>]+>:\s*$')
    _PUSH_RBP = re.compile(r'\s*[0-9a-f]+:\s+push\s+rbp', re.I)

    def _find_func_start(self, asm_lines: List[str], from_line: int) -> int:
        """向上扫描找最近的函数入口标签 <func>: 或 push rbp序言."""
        for i in range(from_line, max(0, from_line - 500), -1):
            il = asm_lines[i].strip()
            if self._FN_LABEL.match(il):
                return i
            if self._PUSH_RBP.match(il):
                if i == 0 or not asm_lines[i-1].strip() or \
                   self._FN_LABEL.match(asm_lines[i-1].strip()):
                    return i
        return max(0, from_line - self._sim_window)

    def _exec_insn_oneline(self, line: str, idx: int, state: PathBlockState):
        """执行单条指令对状态的影响."""
        il = line.strip().lower()
        if not il or il.startswith(';') or il.startswith('.'):
            return

        # alloc: call malloc → rax=live, kill other caller-saved
        m = _ALLOC_FUNCS.search(il)
        if m:
            state.set_reg('rax', f"alloc@{idx}#{m.group(1).lower()}", 'live')
            for r in self._CALLER_SAVED:
                if r != 'rax':
                    state.kill_reg(r)
            return

        # free: freed传播+记录was_freed+杀caller-saved
        m = _FREE_FUNCS.search(il)
        if m:
            freed_oid = None
            for arg_reg in self._FREE_ARG_REGS:
                val = state.get_reg_obj(arg_reg)
                if val:
                    freed_oid = val[0]
                    break
            if freed_oid:
                state.was_freed.add(freed_oid)
                for reg in list(state.reg_obj.keys()):
                    if state.reg_obj[reg][0] == freed_oid:
                        state.reg_obj[reg] = (freed_oid, 'freed')
                # 栈槽也标记freed
                for off in list(state.stack_obj.keys()):
                    if state.stack_obj[off][0] == freed_oid:
                        state.stack_obj[off] = (freed_oid, 'freed')
            for r in self._CALLER_SAVED:
                state.kill_reg(r)
            return

        # mov [rbp+N], imm / mov [rsp+N], imm → kill栈槽
        m = _MOV_STACK_STORE_IMM.search(il)
        if m:
            sign, off_str = m.group(1), m.group(2)
            offset = _parse_int(off_str) or 0
            if sign == '-': offset = -offset
            state.stack_obj.pop(offset, None)
            return

        # mov reg, [rbp+N] / mov reg, [rsp+N] — 栈加载
        m = _MOV_STACK_LOAD.search(il)
        if m:
            dst, sign, off_str = m.group(1), m.group(2), m.group(3)
            offset = _parse_int(off_str) or 0
            if sign == '-': offset = -offset
            if offset in state.stack_obj:
                state.set_reg(dst, state.stack_obj[offset][0], state.stack_obj[offset][1])
            else:
                state.kill_reg(dst)
            return

        # mov [rbp+N], reg / mov [rsp+N], reg — 栈保存
        m = _MOV_STACK_STORE.search(il)
        if m:
            sign, off_str, src = m.group(1), m.group(2), m.group(3)
            offset = _parse_int(off_str) or 0
            if sign == '-': offset = -offset
            sv = state.get_reg_obj(src)
            if sv:
                state.stack_obj[offset] = sv
            elif offset in state.stack_obj:
                del state.stack_obj[offset]
            return

        # mov reg, reg
        m = _MOV_REG.search(il)
        if m:
            dst, src = m.group(1), m.group(2)
            if _canon_reg(src) in ('rbp','rsp','rip'):
                state.kill_reg(dst); return
            sv = state.get_reg_obj(src)
            if sv: state.set_reg(dst, sv[0], sv[1])
            else: state.kill_reg(dst)
            return

        # mov reg, imm / xor reg,reg → kill
        m = _MOV_IMM.search(il) or _XOR_ZERO.search(il)
        if m:
            state.kill_reg(m.group(1)); return

        # lea dst, [base+off] → 派生指针(同一对象)
        m = _LEA_PAT.search(il)
        if m:
            dst, base = m.group(1), m.group(2)
            bv = state.get_reg_obj(base)
            if bv: state.set_reg(dst, bv[0], bv[1])
            else: state.kill_reg(dst)
            return

        # generic call → kill caller-saved
        if re.search(r'\bcall\b', il):
            for r in self._CALLER_SAVED:
                state.kill_reg(r)


# smoke
def _check():
    tv = TemporalPathVerifier()
    # Case1: callee-saved rbx holds freed ptr after free → UAF
    r1 = tv.verify(
        ["  401000:\tmov ecx,0x40","  401005:\tcall malloc",
         "  40100a:\tmov rbx,rax","  40100d:\tmov rcx,rbx",
         "  401010:\tcall free","  401015:\tmov eax,[rbx]","  401018:\tret"],
        [{'obj_id':'o1','free_line':4,'use_line':5,'use_reg':'rbx','confidence':0.5}])
    assert len(r1)==1 and r1[0].get('temporal_verified'), f"Case1:{r1}"
    # Case2: xor rbx,rbx after free → FP filtered
    r2 = tv.verify(
        ["  402000:\tmov ecx,0x40","  402005:\tcall malloc",
         "  40200a:\tmov rbx,rax","  40200d:\tmov rcx,rbx",
         "  402010:\tcall free","  402015:\txor rbx,rbx",
         "  402018:\tmov eax,[rbx]","  40201b:\tret"],
        [{'obj_id':'o2','free_line':4,'use_line':6,'use_reg':'rbx','confidence':0.5}])
    assert len(r2)==0 or not r2[0].get('temporal_verified'), f"Case2:{r2}"
    # Case3: stack save→free→stack zero→use → FP filtered
    r3 = tv.verify(
        ["  403000:\tmov ecx,0x40","  403005:\tcall malloc",
         "  40300a:\tmov [rbp-0x8],rax","  40300e:\tmov rax,[rbp-0x8]",
         "  403012:\tmov rcx,rax","  403015:\tcall free",
         "  40301a:\tmov QWORD PTR [rbp-0x8],0x0","  40301e:\tmov rax,[rbp-0x8]",
         "  403022:\tmov [rax],0x42","  403028:\tret"],
        [{'obj_id':'o3','free_line':5,'use_line':8,'use_reg':'rax','confidence':0.5}])
    assert len(r3)==0 or not r3[0].get('temporal_verified'), f"Case3:{r3}"
    # Case4: stack save→free→NO stack zero→use → UAF verified
    r4 = tv.verify(
        ["  404000:\tmov ecx,0x40","  404005:\tcall malloc",
         "  40400a:\tmov [rbp-0x8],rax","  40400e:\tmov rax,[rbp-0x8]",
         "  404012:\tmov rcx,rax","  404015:\tcall free",
         "  40401a:\tmov rax,[rbp-0x8]","  40401e:\tmov [rax],0x42","  404024:\tret"],
        [{'obj_id':'o4','free_line':5,'use_line':7,'use_reg':'rax','confidence':0.5}])
    assert len(r4)==1 and r4[0].get('temporal_verified'), f"Case4:{r4}"
    print("[OK] temporal_path_verifier tests passed")

if __name__ == '__main__':
    _check()
