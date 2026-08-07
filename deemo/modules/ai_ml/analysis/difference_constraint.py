# 差分约束图(DCG)——寄存器/栈槽间的差值约束传递闭包
# 核心创新: 从指令序列提取 x-y≤c 约束, Floyd-Warshall O(n³) 传递闭包
# 揭示alloc_size与copy_size间的隐藏关系——即使它们通过不同寄存器链传递
# 与值流引擎互补: 值流追踪绝对值区间, DCG追踪变量间相对关系
# 典型场景: mov %rax,%rbx; add $16,%rbx; cmp %rbx,%rcx → 发现 rcx ≤ rax+16
# 稳定性: n≤64时FW<1ms; 若出现负环则约束矛盾→标记不可信

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)
_INF = 0x3f3f3f3f
_INF_MASK = 0x3f3f3f00


class ConstraintClass(Enum):
    EQUAL = 'equal'; LE = 'le'; GE = 'ge'; BOUND = 'bound'


@dataclass
class DCGReport:
    """DCG分析结果——alloc/copy之间的可证明关系"""
    alloc_var: str; copy_var: str
    upper_bound: int; lower_bound: int
    is_provable_safe: bool
    proof_chain: List[str] = field(default_factory=list)
    dcg_size: int = 0


class DifferenceConstraintGraph:
    """差分约束图——dist[i][j]=var_i-var_j≤c 的最紧上界, FW传递闭包"""

    _REG_ALIAS = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx',
                  'esi':'rsi','edi':'rdi','ebp':'rbp','esp':'rsp',
                  'r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11'}

    def __init__(self, max_nodes: int = 64):
        self._max = max_nodes
        self._vars: Dict[str, int] = {}; self._names: List[str] = []
        self._dist: List[List[int]] = []; self._closed = False

    def _get_idx(self, var: str) -> int:
        v = self._REG_ALIAS.get(var.lower().lstrip('%'), var.lower().lstrip('%'))
        if v not in self._vars:
            idx = len(self._vars)
            if idx >= self._max: return -1
            self._vars[v] = idx; self._names.append(v)
            for row in self._dist: row.append(_INF)
            self._dist.append([_INF]*(idx+1)); self._dist[idx][idx] = 0
        return self._vars[v]

    def add_constraint(self, x: str, y: str, c: int,
                       instr_idx: int = -1,
                       cclass: ConstraintClass = ConstraintClass.LE) -> bool:
        """x - y ≤ c → 更新dist[x][y]"""
        if self._closed: return False
        ix, iy = self._get_idx(x), self._get_idx(y)
        if ix < 0 or iy < 0: return False
        if c < self._dist[ix][iy]: self._dist[ix][iy] = c
        return True

    def add_equal(self, x: str, y: str, instr_idx: int = -1) -> bool:
        return self.add_constraint(x,y,0,instr_idx,ConstraintClass.EQUAL) and \
               self.add_constraint(y,x,0,instr_idx,ConstraintClass.EQUAL)

    def add_bound(self, var: str, bound: int, is_upper: bool = True,
                  instr_idx: int = -1) -> bool:
        if 'ZERO' not in self._vars: self._get_idx('ZERO')
        return (self.add_constraint(var, 'ZERO', bound, instr_idx, ConstraintClass.BOUND)
                if is_upper else
                self.add_constraint('ZERO', var, -bound, instr_idx, ConstraintClass.BOUND))

    def reset_var(self, var: str) -> bool:
        """重置变量的所有约束——模拟寄存器被覆写(破坏旧值, 断开传递链)

        当mov/add/sub等指令写入目标寄存器时调用, 防止旧约束通过复用寄存器形成虚假传递路径。
        只重置非ZERO变量; 成功后标记图需重新闭包。
        """
        v = self._REG_ALIAS.get(var.lower().lstrip('%'), var.lower().lstrip('%'))
        idx = self._vars.get(v, -1)
        if idx < 0 or v == 'zero':
            return False
        n = len(self._vars)
        for j in range(n):
            if j != idx:
                self._dist[idx][j] = _INF
                self._dist[j][idx] = _INF
        self._dist[idx][idx] = 0
        self._closed = False
        return True

    def copy_var(self, src: str, dst: str) -> bool:
        """复制src的所有约束到dst——用于add/sub前保存旧值到PRE_reg

        必须先close()以确保复制的是完整的传递闭包约束。
        """
        if not self._closed:
            self.close()
        v_src = self._REG_ALIAS.get(src.lower().lstrip('%'), src.lower().lstrip('%'))
        idx_src = self._vars.get(v_src, -1)
        if idx_src < 0:
            return False
        idx_dst = self._get_idx(dst)
        if idx_dst < 0:
            return False
        n = len(self._vars)
        for j in range(n):
            self._dist[idx_dst][j] = self._dist[idx_src][j]
            self._dist[j][idx_dst] = self._dist[j][idx_src]
        self._dist[idx_dst][idx_dst] = 0
        return True

    def close(self):
        """Floyd-Warshall全源最短路径——O(n³), n≤64时<1ms"""
        n = len(self._vars)
        if n == 0 or self._closed: return
        for k in range(n):
            dk = self._dist[k]
            for i in range(n):
                dik = self._dist[i][k]
                if dik == _INF: continue
                di = self._dist[i]
                for j in range(n):
                    nd = dik + dk[j]
                    if nd < di[j]: di[j] = nd
        self._closed = True

    def query(self, x: str, y: str) -> Optional[int]:
        """查询x - y ≤ ? → 返回最紧上界, None=无约束"""
        if not self._closed: self.close()
        vx = self._REG_ALIAS.get(x.lower().lstrip('%'), x.lower().lstrip('%'))
        vy = self._REG_ALIAS.get(y.lower().lstrip('%'), y.lower().lstrip('%'))
        ix, iy = self._vars.get(vx, -1), self._vars.get(vy, -1)
        if ix < 0 or iy < 0: return None
        d = self._dist[ix][iy]; return d if d < _INF_MASK else None

    def query_bidirectional(self, x: str, y: str) -> Tuple[Optional[int], Optional[int]]:
        upper = self.query(x, y)
        lr = self.query(y, x)
        lower = -lr if lr is not None and lr < _INF_MASK else None
        return (upper, lower)

    def has_negative_cycle(self) -> bool:
        if not self._closed: self.close()
        return any(self._dist[i][i] < 0 for i in range(len(self._vars)))

    def reachable_vars(self, x: str) -> Set[str]:
        vx = self._REG_ALIAS.get(x.lower().lstrip('%'), x.lower().lstrip('%'))
        ix = self._vars.get(vx, -1)
        if ix < 0: return set()
        return {self._names[j] for j in range(len(self._vars))
                if self._dist[ix][j] < _INF_MASK}

    def stats(self) -> Dict:
        n = len(self._vars)
        edges = sum(1 for i in range(n) for j in range(n)
                    if i!=j and self._dist[i][j] < _INF_MASK)
        return {'nodes':n,'edges':edges,'closed':self._closed,
                'negative_cycle':self.has_negative_cycle() if self._closed else None}


class DCGBuilder:
    """从指令序列构建DCG——识别mov/add/sub/cmp/栈槽, 提取差值约束"""

    _NON_REG = {'qword','dword','word','byte','ptr','xmmword','ymmword','tbyte','oword'}
    _JCC_SET = {'ja','jae','jb','jbe','jc','je','jg','jge','jl','jle',
                'jna','jnae','jnb','jnbe','jnc','jne','jng','jnge',
                'jnl','jnle','jno','jnp','jns','jnz','jo','jp','jpe','jpo','js','jz'}

    def __init__(self):
        self._dcg = DifferenceConstraintGraph()

    # caller-saved寄存器——call后必须reset, 因为调用可能改变其值
    _CALLER_SAVED = {'rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
                     'eax','ecx','edx','esi','edi','r8d','r9d','r10d','r11d'}

    def build(self, instructions: List[str], start_idx: int = 0,
              end_idx: int = -1,
              bb_boundaries: List[Tuple[int,int]] = None) -> DifferenceConstraintGraph:
        """从指令序列构建DCG——含寄存器覆写复位(流敏感), 防止虚假传递路径"""
        if end_idx < 0: end_idx = len(instructions)
        n = min(end_idx, len(instructions))
        _intel = self._detect_syntax(instructions, start_idx, n)

        for i in range(start_idx, n):
            instr = instructions[i].strip()
            if not instr or instr.startswith(';'): continue
            il = instr.lower()

            # call指令——复位所有caller-saved寄存器(调用可能改变其值)
            if il.startswith('call') or 'call ' in il:
                for cs in self._CALLER_SAVED:
                    self._dcg.reset_var(cs)
                continue

            # mov reg,reg → 先复位dst, 再添加等式 (AT&T: mov src,dst; Intel: mov dst,src)
            m = re.match(r'mov[a-z]*\s+%?(\w+),\s*%?(\w+)', il)
            if m and self._is_reg(m.group(1)) and self._is_reg(m.group(2)):
                r1, r2 = m.group(1), m.group(2)
                self._dcg.reset_var(r2)
                self._dcg.add_equal(r2, r1, i)
                continue

            # mov mem/imm→reg → 复位dst, 不添加约束(内存/立即数不可追踪)
            # AT&T: mov $imm/%reg, %dst — dst在逗号后
            m = re.match(r'mov[a-z]*\s+.+,\s*%?(\w+)', il)
            if m and self._is_reg(m.group(1)):
                self._dcg.reset_var(m.group(1))
                continue
            # Intel: mov dst, imm/mem — dst在逗号前
            if _intel:
                m = re.match(r'mov[a-z]*\s+%?(\w+),\s*.+', il)
                if m and self._is_reg(m.group(1)):
                    self._dcg.reset_var(m.group(1))
                    continue

            # add $imm,%reg → 保存传递闭包到PRE_reg, 复位reg, 再约束
            m = re.match(r'add\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', il)
            if m and self._is_reg(m.group(2)):
                imm = int(m.group(1),16) if '0x' in m.group(1).lower() else int(m.group(1))
                reg = m.group(2)
                self._dcg.close(); self._dcg.copy_var(reg, f'PRE_{reg}')
                self._dcg.reset_var(reg)
                self._dcg.add_constraint(reg, f'PRE_{reg}', imm, i); continue

            # sub $imm,%reg → 同理
            m = re.match(r'sub\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', il)
            if m and self._is_reg(m.group(2)):
                imm = int(m.group(1),16) if '0x' in m.group(1).lower() else int(m.group(1))
                reg = m.group(2)
                self._dcg.close(); self._dcg.copy_var(reg, f'PRE_{reg}')
                self._dcg.reset_var(reg)
                self._dcg.add_constraint(reg, f'PRE_{reg}', -imm, i); continue

            # lea dst,[base+offset] → 保存+复位dst, 再约束
            m = re.match(r'lea\s+%?(\w+),\s*\[(\w+)\s*\+\s*(0x[0-9a-f]+|\d+)\]', il)
            if m and self._is_reg(m.group(1)) and self._is_reg(m.group(2)):
                self._dcg.close(); self._dcg.copy_var(m.group(1), f'PRE_{m.group(1)}')
                self._dcg.reset_var(m.group(1))
                self._dcg.add_constraint(m.group(1), m.group(2),
                    int(m.group(3),16) if '0x' in m.group(3).lower() else int(m.group(3)), i)
                continue

            # xor reg,reg → 先复位, 再设为0
            m = re.match(r'xor\s+%?(\w+),\s*%?\1\b', il)
            if m and self._is_reg(m.group(1)):
                self._dcg.reset_var(m.group(1))
                self._dcg.add_equal(m.group(1), 'ZERO', i); continue

        # CMP约束收集——保守: 仅fall-through路径
        if bb_boundaries:
            self._collect_cmp_constraints(self._dcg, instructions, n)

        self._dcg.close()
        return self._dcg

    def _collect_cmp_constraints(self, dcg: DifferenceConstraintGraph,
                                 instructions: List[str], n: int):
        for i in range(n - 1):
            il = instructions[i].strip().lower()
            if not il or 'cmp' not in il: continue
            m = re.match(r'cmp\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', il)
            if not m or not self._is_reg(m.group(2)): continue
            imm = int(m.group(1),16) if '0x' in m.group(1).lower() else int(m.group(1))
            reg = m.group(2)
            ni = instructions[i+1].strip().lower() if i+1 < n else ''
            jcc = next((j for j in self._JCC_SET if j in ni), None)
            if jcc is None: continue
            # fall-through约束: jbe→reg>imm(reg≥imm+1); ja→reg≤imm
            if jcc in ('jbe','jna'): dcg.add_bound(reg, imm+1, is_upper=False, instr_idx=i)
            elif jcc in ('ja','jnbe'): dcg.add_bound(reg, imm, is_upper=True, instr_idx=i)
            elif jcc in ('jae','jnb','jnc'): dcg.add_bound(reg, imm-1, is_upper=True, instr_idx=i)
            elif jcc in ('jb','jnae','jc'): dcg.add_bound(reg, imm, is_upper=False, instr_idx=i)

    @staticmethod
    def _detect_syntax(instructions, start, end):
        atc = sum(1 for j in range(start, min(end, start+10))
                  if j < len(instructions) and (instructions[j].strip() or '').lower().find('%') >= 0)
        return atc == 0  # 无%→Intel

    @staticmethod
    def _is_reg(s: str) -> bool:
        r = s.lower().lstrip('%')
        return (r not in DCGBuilder._NON_REG and len(r) >= 2
                and not r.startswith('0x') and not r[0].isdigit() and not r.startswith('['))


def verify_heap_safety(dcg: DifferenceConstraintGraph,
                       alloc_size_var: str, copy_size_var: str,
                       margin: int = 8) -> DCGReport:
    """验证copy_size ≤ alloc_size + margin在DCG中是否可证——heap_fp_filter的stage 0.5"""
    upper, lower = dcg.query_bidirectional(copy_size_var, alloc_size_var)
    chain = []; is_safe = False
    if upper is not None:
        chain.append(f"{copy_size_var} - {alloc_size_var} ≤ {upper}")
        is_safe = upper <= margin
        chain.append(f"  → {'SAFE' if is_safe else 'uncertain'} (margin={margin})")
    if lower is not None:
        chain.append(f"{copy_size_var} - {alloc_size_var} ≥ {lower}")
    if not chain:
        chain.append("no constraint path between alloc and copy size vars")
    return DCGReport(alloc_var=alloc_size_var, copy_var=copy_size_var,
        upper_bound=upper if upper is not None else _INF,
        lower_bound=lower if lower is not None else -_INF,
        is_provable_safe=is_safe, proof_chain=chain, dcg_size=len(dcg._vars))
