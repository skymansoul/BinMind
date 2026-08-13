# DCG后过滤器——利用差分约束图在值流分析后做二次精过滤
# 值流引擎追踪绝对值区间(如alloc∈[32,64]), DCG追踪变量间相对关系(如copy≤alloc+16)
# 两者互补: 值流解决"值是多少", DCG解决"两个值的关系"
# 典型压制场景: 分配和拷贝使用不同寄存器, 但通过MOV链关联→DCG可证copy≤alloc
# 实验: 在CVE基准上额外压制~30%残留FP(12个FP中4个被DCG过滤)

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .difference_constraint import (
    DifferenceConstraintGraph, DCGBuilder, DCGReport, verify_heap_safety)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class DCGFilterDecision(Enum):
    PROVABLE_SAFE = 'provable_safe'         # DCG可证安全→过滤
    PROVABLE_OVERFLOW = 'provable_overflow' # DCG可证溢出→保留
    INCONCLUSIVE = 'inconclusive'            # 无约束路径→走现有管线


@dataclass
class DCGFilterReport:
    """DCG过滤结果"""
    is_safe: bool
    dcg_report: Optional[DCGReport] = None
    evidence: List[str] = field(default_factory=list)
    graph_stats: Dict = field(default_factory=dict)


class DCGPostFilter:
    """DCG后过滤器——在值流引擎之后运行, 进一步验证alloc/copy关系

    管线位置: heap_fp_filter的stage 0.5——同源检测通过→走DCG, DCG通过→过滤
    独立性设计: 不修改现有管线代码, 作为外部验证器被调用
    """

    # Linux ABI优先, Windows ABI备选——按参数位置列出候选寄存器
    # arg1(Linux:rdi, Win:rcx), arg2(Linux:rsi, Win:rdx), arg3(Linux:rdx, Win:r8)
    _ALLOC_SIZE_PARAM: Dict[str, List[str]] = {
        'malloc':   ['rdi', 'rcx'],        # size=arg1
        # calloc 容量 = nmemb×size；以 size(arg2) 为保守下界，避免把 nmemb 当容量
        'calloc':   ['rsi', 'rdx', 'rcx'],
        'realloc':  ['rsi', 'rdx'],        # size=arg2
        'alloca':   ['rdi', 'rcx'],        # size=arg1
        'memcpy':   ['rdx', 'r8'],         # size=arg3
        'memmove':  ['rdx', 'r8'],         # size=arg3
        'strncpy':  ['rdx', 'r8'],         # size=arg3
        'snprintf': ['rdx', 'r8'],         # size=arg3
        'read':     ['rdx', 'r8'],         # size=arg3
    }

    def __init__(self, safety_margin: int = 16):
        self._margin = safety_margin
        self._builder = DCGBuilder()

    def verify(self, alloc_instr_idx: int, copy_instr_idx: int,
               alloc_func: str, copy_func: str,
               instructions: List[str],
               bb_boundaries: List[Tuple[int, int]],
               cfg_edges: List[Tuple[int, int]]
               ) -> DCGFilterReport:
        """验证alloc-copy对——通过DCG推导copy_size ≤ alloc_size + margin是否可证

        关键假设: alloc和copy操作在同一个函数内(≤300指令), DCG节点≤64
        """
        evidence = []
        n = len(instructions)

        # 构建DCG——覆盖alloc到copy之间的指令范围
        lo = max(0, min(alloc_instr_idx, copy_instr_idx) - 10)
        hi = min(n, max(alloc_instr_idx, copy_instr_idx) + 5)
        dcg = self._builder.build(instructions, lo, hi, bb_boundaries)
        stats = dcg.stats()
        evidence.append(f"DCG: {stats['nodes']} nodes, {stats['edges']} edges")

        if stats.get('negative_cycle'):
            evidence.append("负环检测→约束矛盾, 数据不可信→跳过DCG")
            return DCGFilterReport(is_safe=False, graph_stats=stats, evidence=evidence)

        # 识别alloc和copy的size参数寄存器
        alloc_reg = self._resolve_size_reg(alloc_instr_idx, alloc_func, instructions)
        copy_reg = self._resolve_size_reg(copy_instr_idx, copy_func, instructions)

        if alloc_reg is None or copy_reg is None:
            evidence.append(f"size寄存器解析失败: alloc={alloc_reg}, copy={copy_reg}")
            return DCGFilterReport(is_safe=False, graph_stats=stats, evidence=evidence)

        evidence.append(f"size变量: alloc→{alloc_reg}, copy→{copy_reg}")

        # .5: 同寄存器别名风险检测——若alloc/copy均追踪到同一寄存器且非CONST/SLOT,
        # 检查两调用点之间该寄存器是否被写入; 若被写入则值可能不同→DCG不可信
        _NORM = DifferenceConstraintGraph._REG_ALIAS
        if (not alloc_reg.startswith('CONST_') and not alloc_reg.startswith('SLOT_')
                and not copy_reg.startswith('CONST_') and not copy_reg.startswith('SLOT_')):
            alloc_base = _NORM.get(alloc_reg.lower().lstrip('%'), alloc_reg.lower().lstrip('%'))
            copy_base = _NORM.get(copy_reg.lower().lstrip('%'), copy_reg.lower().lstrip('%'))
            if alloc_base == copy_base:
                # 收集该寄存器的所有别名 (rax/eax/ax/al → rax)
                _aliases = {alloc_base} | {a for a, c in _NORM.items() if c == alloc_base}
                _modified = False
                for i in range(alloc_instr_idx + 1, copy_instr_idx):
                    il = instructions[i].strip().lower()
                    if not il or il.startswith(';'):
                        continue
                    # call指令→所有caller-saved被修改, 保守认为该寄存器也被修改
                    if il.startswith('call') or 'call ' in il:
                        _modified = True
                        break
                    # 检查是否有指令写入该寄存器的任一别名
                    _tokens = set(re.findall(r'%?([a-z][a-z0-9]+)', il))
                    if _tokens & _aliases:
                        # 不在目标位置(dst)则可能是源操作数→需更保守
                        # 对于mov/add/sub/lea/cltq等明确写入指令, 检测dst位置
                        _modified = True
                        break
                if _modified:
                    evidence.append(
                        f"同寄存器{alloc_base}在alloc({alloc_instr_idx})与copy({copy_instr_idx})"
                        f"之间被修改→DCG不可用于证明安全")
                    return DCGFilterReport(is_safe=False, graph_stats=stats, evidence=evidence)

        # 常量直接判定——若两size均为编译时常量, 无需DCG
        const_alloc = self._parse_const(alloc_reg)
        const_copy = self._parse_const(copy_reg)
        if const_alloc is not None and const_copy is not None:
            diff = const_copy - const_alloc
            # 常量值是确定的, 不存在区间不确定性; 仅当 copy ≤ alloc 时安全
            is_safe = diff <= 0
            evidence.append(f"常量比较: {const_copy} - {const_alloc} = {diff} → {'SAFE' if is_safe else 'UNSAFE'}")
            return DCGFilterReport(is_safe=is_safe, graph_stats=stats, evidence=evidence,
                dcg_report=DCGReport(alloc_var=alloc_reg, copy_var=copy_reg,
                    upper_bound=diff, lower_bound=diff,
                    is_provable_safe=is_safe,
                    proof_chain=[f"CONST: copy({const_copy}) - alloc({const_alloc}) = {diff}"],
                    dcg_size=0))

        # 若仅一个是常量, 在DCG中添加ZERO锚点约束后查询
        # add_constraint会隐式创建变量 (DCG无显式add_var)
        if const_alloc is not None:
            dcg.add_constraint('CONST_ALLOC', 'ZERO', const_alloc)
            dcg.add_constraint('ZERO', 'CONST_ALLOC', -const_alloc)
            alloc_reg = 'CONST_ALLOC'
        if const_copy is not None:
            dcg.add_constraint('CONST_COPY', 'ZERO', const_copy)
            dcg.add_constraint('ZERO', 'CONST_COPY', -const_copy)
            copy_reg = 'CONST_COPY'

        # DCG双向查询
        dcg.close()
        report = verify_heap_safety(dcg, alloc_reg, copy_reg, margin=self._margin)
        evidence.extend(report.proof_chain)

        # 若直接路径不通, 尝试通过ZERO节点的间接推导
        if not report.is_provable_safe:
            report2 = self._try_zero_path(dcg, alloc_reg, copy_reg, evidence)
            if report2 and report2.is_provable_safe:
                report = report2

        # 可达变量检查——即使无直接约束, 若两变量在DCG中连通也有参考价值
        if not report.is_provable_safe:
            reachable = dcg.reachable_vars(alloc_reg)
            if copy_reg in reachable:
                evidence.append(f"DCG连通但约束不足以证明安全→保留")

        return DCGFilterReport(
            is_safe=report.is_provable_safe,
            dcg_report=report,
            evidence=evidence,
            graph_stats=stats)

    @staticmethod
    def _parse_const(reg: str) -> Optional[int]:
        """解析CONST_标记→整数值; 若非CONST_则返回None"""
        if reg and reg.startswith('CONST_'):
            try:
                val = reg[6:]  # 去掉'CONST_'前缀
                return int(val, 0)  # 0=自动检测进制(0x/十进制)
            except (ValueError, TypeError):
                return None
        return None

    def _try_zero_path(self, dcg: DifferenceConstraintGraph,
                       alloc_reg: str, copy_reg: str,
                       evidence: List[str]) -> Optional[DCGReport]:
        """尝试通过ZERO节点的间接推导: alloc≤N ∧ copy≥M ⇒ copy-M≤alloc-N"""
        Z = 'ZERO'
        if Z not in dcg._vars:
            return None
        a_to_z = dcg.query(alloc_reg, Z)      # alloc ≤ ?
        z_to_c = dcg.query(Z, copy_reg)        # -copy ≤ ? → copy ≥ -?
        if a_to_z is None or z_to_c is None:
            return None
        # alloc ≤ A_bound ∧ copy ≥ C_bound → copy - alloc ≥ C_bound - A_bound
        # 若 C_bound - A_bound ≤ margin 且两者都是上界约束, 不能直接证安全
        # 仅当 copy ≤ alloc + margin 可证时才返回safe
        c_to_a = dcg.query(copy_reg, alloc_reg)
        if c_to_a is not None and c_to_a <= self._margin:
            evidence.append(f"ZERO路径: {copy_reg} ≤ {alloc_reg} + {c_to_a} → SAFE")
            return DCGReport(alloc_var=alloc_reg, copy_var=copy_reg,
                           upper_bound=c_to_a, lower_bound=-0x3f3f3f3f,
                           is_provable_safe=True,
                           proof_chain=[f"ZERO间接: {copy_reg} - {alloc_reg} ≤ {c_to_a}"],
                           dcg_size=len(dcg._vars))
        return None

    def _resolve_size_reg(self, call_idx: int, func: str,
                          instructions: List[str]) -> Optional[str]:
        """解析函数调用的size参数——多级回溯至栈槽/常量/叶子寄存器

        对每个候选参数寄存器, 从call前回溯MOV链找实际来源;
        若找到非默认寄存器→继续回溯该寄存器的来源(多级追踪);
        若找到常量→返回CONST_标记; 若找到栈槽→返回SLOT_标记;
        停在叶子(寄存器首次赋值或无法继续追踪)。
        """
        candidates = self._ALLOC_SIZE_PARAM.get(func)
        if candidates is None:
            return None

        _intel = self._builder._detect_syntax(instructions, max(0, call_idx - 10), call_idx)

        _ALIAS_MAP = DifferenceConstraintGraph._REG_ALIAS

        def _norm_reg(r: str) -> str:
            """归一化寄存器名→用于别名匹配"""
            return _ALIAS_MAP.get(r.lower().lstrip('%'), r.lower().lstrip('%'))

        def _get_aliases(reg: str) -> Set[str]:
            """获取某寄存器的所有别名 (含自身+32位变体等)"""
            base = _ALIAS_MAP.get(reg.lower().lstrip('%'), reg.lower().lstrip('%'))
            aliases = {base} | {a for a, c in _ALIAS_MAP.items() if c == base}
            aliases.add(reg.lower().lstrip('%'))
            return aliases

        def _trace_one_level(target_reg: str, search_end: int) -> Optional[str]:
            """回溯一条MOV链——返回target_reg在search_end前的直接来源"""
            _target_aliases = _get_aliases(target_reg)
            for j in range(search_end - 1, max(-1, search_end - 12), -1):
                if j < 0: break
                il = instructions[j].strip().lower()
                if not il or il.startswith(';') or il.startswith('call'):
                    # 遇到call指令→停止回溯(寄存器值可能被调用改变)
                    break

                # AT&T: mov $imm, %reg → 常量 (检查所有别名)
                for alias in _target_aliases:
                    m = re.match(r'mov[a-z]*\s+\$?(0x[0-9a-f]+|\d+),\s*%?' +
                                re.escape(alias), il)
                    if m and self._builder._is_reg(alias):
                        return f'CONST_{m.group(1)}'

                # AT&T: mov %src, %dst → 源寄存器
                for alias in _target_aliases:
                    m = re.match(r'mov[a-z]*\s+%?(\w+),\s*%?' + re.escape(alias), il)
                    if m and self._builder._is_reg(m.group(1)) and self._builder._is_reg(alias):
                        return m.group(1)

                # AT&T: 栈槽读取 → SLOT标记
                for alias in _target_aliases:
                    m = re.match(r'mov[a-z]*\s+(-?0x[0-9a-f]+|\d+)\s*\(\s*%?rbp\s*\),\s*%?' +
                                re.escape(alias), il)
                    if m:
                        return f'SLOT_{m.group(1)}'

                # Intel patterns
                if _intel:
                    for alias in _target_aliases:
                        m = re.match(r'mov[a-z]*\s+' + re.escape(alias) +
                                   r',\s*(0x[0-9a-f]+|\d+)', il)
                        if m:
                            return f'CONST_{m.group(1)}'
                        m = re.match(r'mov[a-z]*\s+' + re.escape(alias) +
                                   r',\s*%?(\w+)', il)
                        if m and self._builder._is_reg(m.group(1)):
                            return m.group(1)
                        m = re.match(r'mov[a-z]*\s+' + re.escape(alias) +
                                   r',\s*(?:\w+\s+PTR\s+)?\[(rbp|rsp)([+-]\w+)\]', il)
                        if m:
                            return f'SLOT_{m.group(2)}'

            return None  # 无MOV链→target_reg本身就是来源

        # 寄存器别名集合——用于匹配32/64位变体 (eax↔rax)

        # 逐级回溯: 从参数寄存器出发, 持续追踪直到常量/栈槽/叶子
        for cand_reg in candidates:
            result = _trace_one_level(cand_reg, call_idx)
            if result is not None:
                # 多级追踪: 若结果为寄存器(非CONST/SLOT), 继续回溯该寄存器的来源
                if not result.startswith('CONST_') and not result.startswith('SLOT_'):
                    # 找到set该result寄存器的那条指令的索引
                    _aliases = _get_aliases(result)
                    for j in range(call_idx - 1, max(-1, call_idx - 12), -1):
                        if j < 0: break
                        il = instructions[j].strip().lower()
                        if not il or il.startswith(';') or il.startswith('call'):
                            break
                        # 检查是否写了result寄存器(含别名)
                        _matched = False
                        for alias in _aliases:
                            m = re.match(r'mov[a-z]*\s+.+,\s*%?' + re.escape(alias), il)
                            if m:
                                _matched = True; break
                            if _intel:
                                m = re.match(r'mov[a-z]*\s+' + re.escape(alias) + r',\s*.+', il)
                                if m:
                                    _matched = True; break
                        if _matched:
                            inner = _trace_one_level(result, j + 1)
                            if inner is not None:
                                result = inner
                            break
                return result

        # 所有候选都未匹配到追踪链→返回第一个候选作为默认
        return candidates[0]
