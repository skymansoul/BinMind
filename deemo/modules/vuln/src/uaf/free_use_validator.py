"""DRIFT free-use对验证器 — 对象身份一致性检查.

核心算法: 对每个(free, use)对, 后向数据流切片验证:
  1. free释放的对象O和use使用的对象O'是同一个
  2. free和use之间没有O的重新分配 (re-alloc)
  3. free到use的路径上O的身份未被kill

与旧版的区别:
  旧版: free(p) + *q 且 free在use之前 → UAF (不验证p==q)
  新版: free(obj#3) + use(obj#3) → UAF (身份粒度)

创建: 2024-08-14  更新: 2024-08-14 (执行序调用图处理)
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re

from .object_identity import (
    HeapObject, ObjectIdentity, ObjIdTracker,
    _canon_reg, _ALLOC_FUNCS, _FREE_FUNCS, _parse_int)
from .pointer_kill_set import (
    InsnEffect, analyze_insn_effects, _is_user_func)


@dataclass
class ValidatedUAFFinding:
    """一条验证通过的UAF发现."""
    obj_id: str = ""              # 对象身份标签
    alloc_line: int = -1           # 分配指令行号
    alloc_func: str = ""           # malloc/calloc/realloc
    free_line: int = -1            # free指令行号
    use_line: int = -1             # use指令行号
    use_reg: str = ""              # 解引用时使用的寄存器
    free_reg: str = ""             # free时使用的寄存器
    instruction_distance: int = 0  # free→use指令距离
    double_free: bool = False
    confidence: float = 0.0
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            'obj_id': self.obj_id,
            'alloc_line': self.alloc_line,
            'alloc_func': self.alloc_func,
            'free_line': self.free_line,
            'use_line': self.use_line,
            'use_reg': self.use_reg,
            'free_reg': self.free_reg,
            'distance': self.instruction_distance,
            'double_free': self.double_free,
            'confidence': self.confidence,
            'evidence': self.evidence,
        }


# ——— CRT函数识别 (复用pointer_kill_set的_is_user_func) ———
_CRT_PREFIXES = ('__', '_')
_CRT_KEYWORDS = ('mingw', 'crt', 'atexit', 'runtime', 'startup',
                 'handler', 'managed', 'initterm', 'invoke', 'register')


def _is_user_fn(name: str) -> bool:
    return _is_user_func(name, _CRT_PREFIXES, _CRT_KEYWORDS)


class FreeUseValidator:
    """free-use对验证器 — 对象身份一致性 + 调用图执行序.

    算法:
      1. 从asm_lines提取InsnEffect序列
      2. 构建函数入口映射
      3. 从main开始按调用图执行序处理 (非地址序)
      4. 遇到call user_func → 递归进入被调函数
      5. ObjIdTracker追踪对象身份
      6. 对每个free/use, 验证对象身份是否一致
    """

    def __init__(self):
        self._tracker = ObjIdTracker()

    def validate(self, asm_lines: List[str]
                 ) -> Tuple[List[ValidatedUAFFinding], ObjIdTracker]:
        """完整验证管线: 解析→函数入口映射→执行序处理."""
        self._tracker = ObjIdTracker()
        effects = analyze_insn_effects(asm_lines)

        # 构建函数入口索引: 函数名→第一个指令的effects下标
        fn_entry: Dict[str, int] = {}
        for i, eff in enumerate(effects):
            if eff.is_func_entry and eff.func_name:
                if eff.func_name not in fn_entry:
                    fn_entry[eff.func_name] = i

        findings: List[ValidatedUAFFinding] = []

        if 'main' in fn_entry:
            self._process_execution_order(
                effects, fn_entry, findings)
        else:
            # 无main (如库文件) → 回退到线性处理
            self._validate_linear(effects, findings)

        return findings, self._tracker

# 执行序处理: 从main出发, 按调用图遍历

    def _process_execution_order(self, effects: List[InsnEffect],
                                  fn_entry: Dict[str, int],
                                  findings: List[ValidatedUAFFinding]) -> None:
        """显式调用栈的执行序处理.

        栈元素: (return_idx, caller_fn_end)
        从main入口开始, 遇到call user_func时跳转到被调函数,
        ret时弹栈返回调用点.
        """
        # call栈: 保存返回位置和调用者的函数结束位置
        call_stack: List[Tuple[int, int]] = []
        # 递归检测: 当前调用链上的函数集合
        call_chain: Set[str] = set()

        i = fn_entry['main']
        fn_end = self._get_fn_end(effects, fn_entry, 'main')
        call_chain.add('main')

        while i < len(effects):
            # 到达当前函数末尾 → 检查是否需要返回调用者
            if i >= fn_end:
                if call_stack:
                    self._tracker.track_ret()
                    i, fn_end = call_stack.pop()
                    continue
                else:
                    break  # main返回, 处理结束

            eff = effects[i]
            in_user = eff.in_user_func

# ALLOC
            if eff.gen_alloc:
                if in_user:
                    if eff.free_call:  # realloc
                        freed_oid = self._tracker.track_free(
                            eff.addr, eff.line, eff.free_reg)
                        if freed_oid:
                            obj = self._tracker.objects.get(freed_oid)
                            if obj and obj.double_freed:
                                if not _has_jmp_between(
                                        effects, obj.freed_line, eff.line):
                                    findings.append(ValidatedUAFFinding(
                                        obj_id=freed_oid.label(),
                                        alloc_line=obj.alloc_line,
                                        alloc_func=obj.oid.alloc_func,
                                        free_line=eff.line,
                                        use_line=eff.line,
                                        free_reg=eff.free_reg,
                                        instruction_distance=0,
                                        double_free=True, confidence=0.95,
                                        evidence=f'double free via realloc: {freed_oid.label()}'))
                    self._tracker.track_alloc(
                        eff.addr, eff.gen_func, eff.line)
                i += 1
                continue

# FREE
            if eff.free_call:
                if in_user:
                    freed_oid = self._tracker.track_free(
                        eff.addr, eff.line, eff.free_reg)
                    if freed_oid:
                        obj = self._tracker.objects.get(freed_oid)
                        if obj and obj.double_freed:
                            # 过滤: free之间若有跳转指令 → 互斥分支 → 跳过
                            if _has_jmp_between(
                                    effects, obj.freed_line, eff.line):
                                pass  # 不同路径上的两个free, 非真实double free
                            else:
                                findings.append(ValidatedUAFFinding(
                                    obj_id=freed_oid.label(),
                                    alloc_line=obj.alloc_line,
                                    alloc_func=obj.oid.alloc_func,
                                    free_line=eff.line,
                                    use_line=eff.line,
                                    free_reg=eff.free_reg,
                                    instruction_distance=0,
                                    double_free=True, confidence=0.95,
                                    evidence=f'double free: {freed_oid.label()}'))
                i += 1
                continue

            # ——— DEREF: UAF检查 (在heap_load之前, 因为heap_load可能kill rax) ———
            if eff.deref_reg and in_user:
                obj = self._tracker.check_use(eff.line, eff.deref_reg)
                if obj:
                    findings.append(ValidatedUAFFinding(
                        obj_id=obj.oid.label(),
                        alloc_line=obj.alloc_line,
                        alloc_func=obj.oid.alloc_func,
                        free_line=obj.freed_line,
                        use_line=eff.line,
                        use_reg=eff.deref_reg,
                        free_reg='rdi',
                        instruction_distance=eff.line - obj.freed_line,
                        confidence=self._compute_confidence(obj, eff.line),
                        evidence=(
                            f'{obj.oid.label()} freed at line '
                            f'{obj.freed_line}, used via '
                            f'{eff.deref_reg} at line {eff.line}')))

# MOV / STACK / HEAP / LEA / XOR / KILL
            if eff.mov_dst and eff.mov_src:
                self._tracker.track_mov_reg(eff.mov_dst, eff.mov_src)
            if eff.kills:
                for r in eff.kills:
                    self._tracker.track_mov_imm(r)
            if eff.xor_zero:
                self._tracker.track_xor_zero(eff.xor_zero)
            if eff.stack_store:
                self._tracker.track_stack_store(
                    eff.stack_store[0], eff.stack_store[1])
            if eff.stack_load:
                self._tracker.track_stack_load(
                    eff.stack_load[0], eff.stack_load[1])
            if eff.heap_store:
                self._tracker.track_heap_store(
                    eff.heap_store[0], eff.heap_store[1], eff.heap_store[2])
            if eff.heap_load:
                self._tracker.track_heap_load(
                    eff.heap_load[0], eff.heap_load[1], eff.heap_load[2])
            if eff.global_store:
                self._tracker.track_global_store(
                    eff.global_store[0], eff.global_store[1])
            if eff.global_load:
                self._tracker.track_global_load(
                    eff.global_load[0], eff.global_load[1])
            if eff.lea_dst and eff.lea_base:
                self._tracker.track_lea(
                    eff.lea_dst, eff.lea_base, eff.lea_off)

# CALL: 用户函数→递归进入, CRT→模拟
            if eff.is_call:
                target = eff.call_target
                # 检查函数调用的参数寄存器是否持有freed对象 (UAF via arg passing)
                if in_user and not eff.gen_alloc and not eff.free_call:
                    for arg_reg in ('rcx', 'rdx', 'r8', 'r9'):
                        obj = self._tracker.check_use(eff.line, arg_reg)
                        if obj:
                            # 过滤: free与call之间有条件跳转 → 不同执行路径
                            if _has_jmp_between(
                                    effects, obj.freed_line, eff.line):
                                continue
                            findings.append(ValidatedUAFFinding(
                                obj_id=obj.oid.label(),
                                alloc_line=obj.alloc_line,
                                alloc_func=obj.oid.alloc_func,
                                free_line=obj.freed_line,
                                use_line=eff.line,
                                use_reg=arg_reg,
                                free_reg='rdi',
                                instruction_distance=eff.line - obj.freed_line,
                                confidence=self._compute_confidence(obj, eff.line),
                                evidence=(
                                    f'{obj.oid.label()} freed at line '
                                    f'{obj.freed_line}, used as arg({arg_reg}) '
                                    f'in call to {target or "?"} at line {eff.line}')))
                if (target and _is_user_fn(target)
                        and target in fn_entry
                        and target not in call_chain):
                    # 用户函数调用: 保存返回位置, 跳转到被调函数
                    self._tracker.track_call_clobber()
                    self._tracker.stack_obj.clear()  # 新栈帧
                    call_stack.append((i + 1, fn_end))
                    call_chain.add(target)
                    i = fn_entry[target]
                    fn_end = self._get_fn_end(effects, fn_entry, target)
                    continue  # 跳过i+=1, 处理被调函数第一条指令
                else:
                    # CRT调用或未追踪函数: push后立即模拟ret
                    self._tracker.track_call_clobber()
                    self._tracker.track_ret()

            # ——— RET: 执行序模式下, track_ret在i>=fn_end边界处理,
            # 此处不重复调用. 只对CRT调用做立即push-pop模拟. ———

            i += 1

# 线性回退: 无main时使用

    def _validate_linear(self, effects: List[InsnEffect],
                         findings: List[ValidatedUAFFinding]) -> None:
        """线性扫描回退 — 当找不到main时使用."""
        for eff in effects:
            in_user = eff.in_user_func

            if eff.gen_alloc:
                if not in_user:
                    continue
                if eff.free_call:
                    freed_oid = self._tracker.track_free(
                        eff.addr, eff.line, eff.free_reg)
                    if freed_oid:
                        obj = self._tracker.objects.get(freed_oid)
                        if obj and obj.double_freed:
                            findings.append(ValidatedUAFFinding(
                                obj_id=freed_oid.label(),
                                alloc_line=obj.alloc_line,
                                alloc_func=obj.oid.alloc_func,
                                free_line=eff.line, use_line=eff.line,
                                free_reg=eff.free_reg,
                                instruction_distance=0,
                                double_free=True, confidence=0.95,
                                evidence=f'double free via realloc: {freed_oid.label()}'))
                self._tracker.track_alloc(eff.addr, eff.gen_func, eff.line)
                continue

            if eff.free_call:
                if not in_user:
                    continue
                freed_oid = self._tracker.track_free(
                    eff.addr, eff.line, eff.free_reg)
                if freed_oid:
                    obj = self._tracker.objects.get(freed_oid)
                    if obj and obj.double_freed:
                        findings.append(ValidatedUAFFinding(
                            obj_id=freed_oid.label(),
                            alloc_line=obj.alloc_line,
                            alloc_func=obj.oid.alloc_func,
                            free_line=eff.line, use_line=eff.line,
                            free_reg=eff.free_reg,
                            instruction_distance=0,
                            double_free=True, confidence=0.95,
                            evidence=f'double free: {freed_oid.label()}'))
                continue

            if eff.mov_dst and eff.mov_src:
                self._tracker.track_mov_reg(eff.mov_dst, eff.mov_src)
            if eff.kills:
                for r in eff.kills:
                    self._tracker.track_mov_imm(r)
            if eff.xor_zero:
                self._tracker.track_xor_zero(eff.xor_zero)
            if eff.stack_store:
                self._tracker.track_stack_store(
                    eff.stack_store[0], eff.stack_store[1])
            if eff.stack_load:
                self._tracker.track_stack_load(
                    eff.stack_load[0], eff.stack_load[1])
            if eff.heap_store:
                self._tracker.track_heap_store(
                    eff.heap_store[0], eff.heap_store[1], eff.heap_store[2])
            if eff.heap_load:
                self._tracker.track_heap_load(
                    eff.heap_load[0], eff.heap_load[1], eff.heap_load[2])
            if eff.lea_dst and eff.lea_base:
                self._tracker.track_lea(
                    eff.lea_dst, eff.lea_base, eff.lea_off)
            if eff.is_call:
                self._tracker.track_call_clobber()
            if eff.is_ret:
                self._tracker.track_ret()
            if eff.deref_reg and in_user:
                obj = self._tracker.check_use(eff.line, eff.deref_reg)
                if obj:
                    findings.append(ValidatedUAFFinding(
                        obj_id=obj.oid.label(),
                        alloc_line=obj.alloc_line,
                        alloc_func=obj.oid.alloc_func,
                        free_line=obj.freed_line,
                        use_line=eff.line,
                        use_reg=eff.deref_reg,
                        free_reg='rdi',
                        instruction_distance=eff.line - obj.freed_line,
                        confidence=self._compute_confidence(obj, eff.line),
                        evidence=(
                            f'{obj.oid.label()} freed at line '
                            f'{obj.freed_line}, used via '
                            f'{eff.deref_reg} at line {eff.line}')))

# helpers

    @staticmethod
    def _get_fn_end(effects: List[InsnEffect],
                    fn_entry: Dict[str, int],
                    fn_name: str) -> int:
        """返回函数在effects中的结束位置 (下一个函数入口或末尾)."""
        start = fn_entry[fn_name]
        end = len(effects)
        for name, idx in fn_entry.items():
            if idx > start and idx < end:
                end = idx
        return end

    def _compute_confidence(self, obj: HeapObject,
                            use_line: int) -> float:
        """基于多因素计算UAF置信度."""
        score = 0.5
        if obj.oid.alloc_func in ('malloc', 'calloc'):
            score += 0.1
        elif obj.oid.alloc_func == 'realloc':
            score += 0.05
        dist = use_line - obj.freed_line
        if dist <= 5:
            score += 0.2
        elif dist <= 15:
            score += 0.1
        elif dist <= 30:
            score += 0.05
        if obj.double_freed:
            score += 0.3
        return min(score, 1.0)


def filter_infeasible_paths(findings: List[ValidatedUAFFinding],
                            asm_lines: List[str]
                            ) -> List[ValidatedUAFFinding]:
    """过滤不可行路径上的UAF — 若free和use之间存在re-alloc则排除.

    仅对同函数内的free-use对检查re-alloc.
    跨函数场景: free在被调者(低地址)时, ret后调用者中的alloc
    在地址序上出现在free和use之间, 但执行序上发生于free之前.
    检测标准: free与use之间有函数标签→跨函数→跳过re-alloc检查.
    """
    filtered = []
    for f in findings:
        if not _has_function_label_between(asm_lines, f.free_line, f.use_line):
            if _has_realloc_between(asm_lines, f.free_line, f.use_line):
                continue
        filtered.append(f)
    return filtered


def _has_function_label_between(asm_lines: List[str], free_line: int,
                                 use_line: int) -> bool:
    """检查free和use之间是否有函数入口标签 (表示跨函数)."""
    for i in range(free_line + 1, use_line):
        line = asm_lines[i].strip()
        if _FUNC_LABEL.match(line):
            return True
    return False


def _has_realloc_between(asm_lines: List[str], free_line: int,
                         use_line: int) -> bool:
    """检查free和use之间是否有新的分配 (可能重用同一指针)."""
    for i in range(free_line + 1, use_line):
        line = asm_lines[i].strip().lower()
        if _ALLOC_FUNCS.search(line):
            return True
    return False


# 函数标签: 140001760 <free_all>:
_FUNC_LABEL = re.compile(r'^[0-9a-f]+\s+<[^>]+>:\s*$')

# x86-64条件跳转: je, jne, jg, jl, jge, jle, jbe, jae, jb, ja, js, jns, jo, jno, jp, jnp, jcxz, jecxz, jrcxz
# + 无条件跳转 jmp — 用于检测不同执行路径
_JMP_PAT = re.compile(
    r'\b(j(?:mp|e|ne|g|ge|l|le|be|ae|b|a|s|ns|o|no|p|np|cxz|ecxz|rcxz))\b', re.I)


def _has_jmp_between(effects: list, start_line: int,
                      end_line: int) -> bool:
    """检查start和end之间是否有跳转指令 (不同执行路径).

    仅在start和end属于同一函数时检查.
    若有函数标签在start和end之间 → 跨函数 → 不检查 (保守, 因为
    无关函数内的跳转不应过滤跨函数findings).
    """
    cross_function = False
    has_jmp = False
    for eff in effects:
        if start_line < eff.line < end_line:
            if eff.is_func_entry:
                cross_function = True
            if _JMP_PAT.match(eff.mnemonic):
                has_jmp = True
    if cross_function:
        return False
    return has_jmp
