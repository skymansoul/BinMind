# UAF Demand-Driven 分析 — 从use site后向追踪alloc/free路径
"""需求驱动的UAF检测 — 从指针使用点后向分析。

不从前向逐指令追踪指针，而是从每个指针解引用点出发，
沿指令流后向切片，寻找该指针值的alloc来源及路径上的free调用。
若某条路径上存在free且在use之前无re-alloc → 确认为UAF。

方法依据: Undangle demand-driven 后向切片 +
          Datalog pointer provenance tracking，操作在x86_64汇编级别。

与旧版 uaf_analyzer (前向追踪) 互补:
  旧版: 从malloc出发前向追踪 → 跨函数/存内存时断开
  新版: 从use出发后向切 → 只需找定义链，处理全局指针UAF更准确
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

_log = logging.getLogger(__name__)


class ProvenanceKind(str, Enum):
    ALLOC = "alloc"
    LOAD_GLOBAL = "load_global"
    LOAD_STACK = "load_stack"
    PARAMETER = "parameter"
    UNKNOWN = "unknown"


@dataclass
class PointerProvenance:
    """指针值的来源信息。"""
    kind: ProvenanceKind = ProvenanceKind.UNKNOWN
    line: int = -1
    alloc_func: str = ""
    load_addr: str = ""
    reg: str = ""
    param_idx: int = -1
    confidence: float = 0.0


@dataclass
class FreeUsePath:
    """一条从free到use的潜在UAF路径。"""
    use_line: int = -1
    use_reg: str = ""
    free_line: int = -1
    free_reg: str = ""
    alloc_line: int = -1
    prov: Optional[PointerProvenance] = None
    alloc_to_free_guards: List[str] = field(default_factory=list)
    free_to_use_guards: List[str] = field(default_factory=list)
    realloc_on_path: bool = False
    instruction_distance: int = 0
    # 跨函数call路径: free在caller, use在callee (行号顺序反转)
    is_call_path: bool = False
    # 路径可行性 (由 UAFPathVerifier 填充)
    path_feasible: Optional[bool] = None
    feasibility_score: float = 0.0


@dataclass
class DemandDrivenReport:
    """Demand-driven UAF分析报告。"""
    function_name: str = ""
    total_use_sites: int = 0
    total_alloc_sites: int = 0
    free_sites: int = 0
    uaf_paths: List[FreeUsePath] = field(default_factory=list)
    confirmed_uaf: int = 0
    potential_uaf: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'use_sites': self.total_use_sites,
            'alloc_sites': self.total_alloc_sites,
            'free_sites': self.free_sites,
            'uaf_paths': len(self.uaf_paths),
            'confirmed': self.confirmed_uaf,
            'potential': self.potential_uaf,
            'high_conf': self.high_confidence,
            'med_conf': self.medium_confidence,
            'low_conf': self.low_confidence,
        }


# 汇编匹配模式

_ALLOC_FUNCS = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(malloc|calloc|realloc|_Znwm|_Znam|kmalloc|kzalloc|vmalloc)(?:@plt)?>?\b', re.I)
_FREE_FUNCS = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(free|kfree|vfree|delete|_ZdlPv|_ZdaPv)(?:@plt)?>?\b', re.I)
_DEREF_PAT = re.compile(
    r'\b(mov|movzx|movsx|add|sub|cmp)\s+'
    r'(\w+),\s*(?:(?:qword|dword|word|byte)(?:\s+ptr)?\s+)?\[(\w+)([+\-]\s*(?:0x[0-9a-f]+|\d+))?\]', re.I)
_GLOBAL_LOAD = re.compile(
    r'\bmov\s+(\w+),\s*(?:\w+\s+(?:ptr\s+)?)?\[rip[+\-]\s*(0x[0-9a-f]+|\w+)\]', re.I)
_STACK_LOAD = re.compile(
    r'\bmov\s+(\w+),\s*(?:\w+\s+(?:ptr\s+)?)?\[(?:rbp|rsp)([+\-]\s*(?:0x[0-9a-f]+|\d+))\]', re.I)
_MEM_STORE = re.compile(
    r'\bmov\s+(?:\w+\s+(?:ptr\s+)?)?\[(\w+(?:[+\-]\s*(?:0x[0-9a-f]+|\d+))?)\],\s*(\w+)', re.I)
# 函数标签: 0000000140001760 <main>:
_FUNC_LABEL = re.compile(
    r'^[0-9a-f]+\s+<([\w.@]+)>:\s*$', re.I)
# CRT/库函数: 以下划线/点开头, 或匹配已知CRT模式 (非用户代码)
_CRT_FUNC = re.compile(
    r'(^_)|(^\.)|'  # _xxx / __xxx / .l_start / .weak
    r'([Cc][Rr][Tt][Ss]tart|[Ss]tartup$|check_managed|duplicate_pp|'
    r'^atexit$|^safe_flush$|mark_section|pseudo_reloc|register_frame|'
    r'^wcsnlen$|^strnlen$|^wcrtomb$|^mbrtowc$|^bitstob$|^dtoa_|'
    r'^init_fpreg|^fallback_)', re.I)
# Windows x64调用约定: 第一参数在rcx (Linux: rdi)
_FREE_ARG_PAT = re.compile(
    r'\bmov\s+(rcx|ecx|rdi|edi),\s*(\w+)', re.I)


# 寄存器工具


def _norm_reg(reg: str) -> str:
    """寄存器名规格化: rax/eax/ax/al → rax (同物理寄存器)。"""
    r = reg.lower().strip()
    # 64-bit 寄存器家族 → 规范化到 64-bit 名称
    _REG_FAMILY = {
        'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
        'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
        'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
        'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
        'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
        'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
        'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
        'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
        'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
        'r12': 'r12', 'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
        'r13': 'r13', 'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
        'r14': 'r14', 'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
        'r15': 'r15', 'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
    }
    return _REG_FAMILY.get(r, r)


def _is_gp_reg(s: str) -> bool:
    """判断字符串是否为通用寄存器名。"""
    return _norm_reg(s) not in ('rbp', 'rsp', 'rip', s if len(s) > 4 else '') and (
        s.startswith(('r', 'e')) or s in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'))


def _strip_addr(line: str) -> str:
    """剥离objdump行的地址前缀: '  1400017d5:\t48 89 c1  \tmov rcx,rax' → 'mov rcx,rax'。
    也处理非objdump格式(纯指令)不变。
    """
    s = line.strip()
    # objdump格式: 地址: 字节码  指令
    # 找tab后的最后一段
    if '\t' in s:
        parts = s.split('\t')
        s = parts[-1].strip()
    # 去掉可能的地址前缀 (如 '1400017d5:')
    if s and s[0].isalnum() and ':' in s[:20]:
        colon = s.index(':')
        prefix = s[:colon]
        if all(c in '0123456789abcdefABCDEF' for c in prefix):
            s = s[colon + 1:].strip()
    return s


# DemandDrivenUAFAnalyzer

class DemandDrivenUAFAnalyzer:
    """从指针解引用点出发的需求驱动UAF检测。

    算法:
      1. 扫描 alloc/free/use/mem_store 位置
      2. 对每个use site, 后向追踪指针来源 (alloc/load/param)
      3. 在alloc→use路径上寻找free
      4. 若free存在且无re-alloc → 标记UAF路径
      5. 收集路径guard条件供 UAFPathVerifier 验证可行性
    """

    def __init__(self, max_trace_distance: int = 150):
        self._max_trace = max_trace_distance
        self._func_ranges: List[Tuple[int, int, str]] = []
        self._crt_line_set: set = set()
        self._user_line_set: set = set()

# 函数边界检测

    def _build_func_map(self, asm: List[str]) -> None:
        """扫描函数标签, 标记CRT vs 用户函数边界。
        用于过滤CRT启动/清理代码中的alloc/free/use噪音。"""
        labels: List[Tuple[int, str]] = []
        for i, line in enumerate(asm):
            m = _FUNC_LABEL.match(line.strip())
            if m:
                labels.append((i, m.group(1)))
        self._func_ranges = []
        self._crt_line_set = set()
        self._user_line_set = set()
        for idx, (start, name) in enumerate(labels):
            end = labels[idx + 1][0] if idx + 1 < len(labels) else len(asm)
            self._func_ranges.append((start, end, name))
            if _CRT_FUNC.search(name):
                for ln in range(start, end):
                    self._crt_line_set.add(ln)
            else:
                for ln in range(start, end):
                    self._user_line_set.add(ln)

    def analyze(self, asm_lines: List[str],
                function_name: str = "") -> DemandDrivenReport:
        report = DemandDrivenReport(function_name=function_name)
        # 构建函数边界 → 过滤CRT噪音
        self._build_func_map(asm_lines)
        alloc_sites = self._index_alloc_sites(asm_lines)
        free_sites = self._index_free_sites(asm_lines)
        use_sites = self._index_use_sites(asm_lines)
        mem_stores = self._index_mem_stores(asm_lines)

        report.total_alloc_sites = len(alloc_sites)
        report.free_sites = len(free_sites)
        report.total_use_sites = len(use_sites)

        if not use_sites or not free_sites:
            return report

        for use in use_sites:
            prov = self._trace_provenance(asm_lines, use['line'], use['reg'],
                                          alloc_sites, mem_stores)
            if prov.kind == ProvenanceKind.UNKNOWN:
                continue

            alloc_start = prov.line if prov.line >= 0 else 0
            for free in free_sites:
                if not (alloc_start <= free['line'] <= use['line']):
                    continue
                # 关键过滤: free的参数必须与use共享同一指针源
                free_reg = free.get('arg_reg', 'rcx')
                if not self._same_pointer_source(
                        asm_lines, free['line'], free_reg,
                        use['line'], use['reg'], alloc_sites, mem_stores):
                    continue
                has_realloc = self._has_realloc_between(
                    asm_lines, free['line'], use['line'], alloc_sites)

                path = FreeUsePath(
                    use_line=use['line'], use_reg=use['reg'],
                    free_line=free['line'], free_reg=free.get('arg_reg', 'rcx'),
                    alloc_line=prov.line, prov=prov,
                    alloc_to_free_guards=self._collect_guards(
                        asm_lines, alloc_start, free['line']),
                    free_to_use_guards=self._collect_guards(
                        asm_lines, free['line'], use['line']),
                    realloc_on_path=has_realloc,
                    instruction_distance=use['line'] - free['line'],
                )
                report.uaf_paths.append(path)

        for p in report.uaf_paths:
            if p.realloc_on_path:
                continue
            report.confirmed_uaf += 1
            conf = self._estimate_confidence(p)
            if conf >= 0.7:
                report.high_confidence += 1
            elif conf >= 0.4:
                report.medium_confidence += 1
            else:
                report.low_confidence += 1

# 跨函数调用链UAF检测
        # 场景: free(g_global) 在函数A, 随后call funcB, funcB内部deref g_global
        # 由于funcB的use行号可能小于free行号(代码布局), 需要特殊处理
        self._find_call_uaf_paths(asm_lines, alloc_sites, free_sites,
                                  use_sites, mem_stores, report)

        return report

    def _find_call_uaf_paths(self, asm, alloc_sites, free_sites,
                              use_sites, mem_stores, report):
        """检测跨函数调用链的UAF: free后调用某函数, 该函数内部deref同源指针。

        从free所在函数向后扫描call指令, 若call目标函数内部有use且
        free和use共享同一指针源, 则生成UAF路径。
        """
        # 构建函数名→{line: reg, ...}的映射, 用于快速查找某函数内所有use
        func_uses: Dict[str, List[Dict]] = {}
        for u in use_sites:
            for s, e, name in self._func_ranges:
                if s <= u['line'] < e:
                    func_uses.setdefault(name, []).append(u)
                    break

        if not func_uses:
            return

        # call指令模式: call <addr> <func_name>
        _CALL_PAT = re.compile(
            r'\bcall\s+(?:[0-9a-f]+\s+<)?([\w.@]+)', re.I)

        for free in free_sites:
            free_line = free['line']
            free_reg = free.get('arg_reg', 'rcx')

            # 在free之后(同函数内)扫描15行, 找call指令
            free_func = None
            for s, e, name in self._func_ranges:
                if s <= free_line < e:
                    free_func = name
                    scan_end = e
                    break
            if free_func is None:
                scan_end = min(free_line + 15, len(asm))

            for i in range(free_line + 1, min(free_line + 16, scan_end)):
                if not self._in_user_code(i):
                    continue
                cm = _CALL_PAT.search(asm[i])
                if not cm:
                    continue
                callee = cm.group(1)
                if callee not in func_uses:
                    continue
                # 该call目标函数内部有use, 检查是否同源
                callee_uses = func_uses[callee]
                for cu in callee_uses:
                    if not self._same_pointer_source(
                            asm, free_line, free_reg,
                            cu['line'], cu['reg'], alloc_sites, mem_stores):
                        continue
# 同源! 生成UAF路径
                    prov = self._trace_provenance(
                        asm, cu['line'], cu['reg'], alloc_sites, mem_stores)
                    alloc_line = prov.line if prov.line >= 0 else 0
                    has_realloc = self._has_realloc_between(
                        asm, free_line, i, alloc_sites)
                    # call路径: guard收集在free_line>use_line时不适用
                    # 跨函数: alloc→free用正常guard, free→use不可用行序
                    path = FreeUsePath(
                        use_line=cu['line'], use_reg=cu['reg'],
                        free_line=free_line, free_reg=free_reg,
                        alloc_line=alloc_line, prov=prov,
                        alloc_to_free_guards=self._collect_guards(
                            asm, alloc_line, free_line),
                        free_to_use_guards=[],  # 跨函数无法用行序收集guard
                        realloc_on_path=has_realloc,
                        instruction_distance=i - free_line,
                        is_call_path=True,
                    )
                    # 避免重复
                    existing = [(p.use_line, p.free_line) for p in report.uaf_paths]
                    if (path.use_line, path.free_line) not in existing:
                        report.uaf_paths.append(path)
                    break  # 一个call只取第一个匹配use

        # 更新confirmed计数
        for p in report.uaf_paths:
            if p.realloc_on_path:
                continue
            if not getattr(p, '_counted', False):
                p._counted = True
                report.confirmed_uaf += 1
                conf = self._estimate_confidence(p)
                if conf >= 0.7:
                    report.high_confidence += 1
                elif conf >= 0.4:
                    report.medium_confidence += 1
                else:
                    report.low_confidence += 1

    def _in_user_code(self, line: int) -> bool:
        """判断行是否在用户代码(非CRT函数)中。无函数边界时默认通过。"""
        if not self._func_ranges:
            return True  # 无边界信息 → 全部通过（口径: 阶段校验语义, 非测试结果宣称）
        return line not in self._crt_line_set

# 位置索引 (过滤CRT噪音)

    def _index_alloc_sites(self, asm):
        return [
            {'line': i, 'func': m.group(1).lower()}
            for i, line in enumerate(asm) if (m := _ALLOC_FUNCS.search(line))
            and self._in_user_code(i)]

    def _index_free_sites(self, asm):
        return [{'line': i, 'func': m.group(1).lower(),
                 'arg_reg': self._find_free_arg(asm, i)}
                for i, line in enumerate(asm) if (m := _FREE_FUNCS.search(line))
                and self._in_user_code(i)]

    def _index_use_sites(self, asm):
        return [
            {'line': i, 'reg': m.group(3), 'access_type': m.group(1)}
            for i, line in enumerate(asm) if (m := _DEREF_PAT.search(line))
            and m.group(3) not in ('rip', 'rsp', 'rbp')
            and self._in_user_code(i)]

    def _index_mem_stores(self, asm):
        return [
            {'line': i, 'addr': m.group(1), 'src_reg': m.group(2)}
            for i, line in enumerate(asm) if (m := _MEM_STORE.search(line))
            and m.group(2) not in ('0', 'rsp', 'rbp')]

# 来源追踪 (栈感知后向追踪)

    def _trace_provenance(self, asm: List[str], use_line: int,
                          use_reg: str, alloc_sites: List[Dict],
                          mem_stores: List[Dict]) -> PointerProvenance:
        """后向追踪寄存器到堆分配来源, 支持栈槽存储/加载链。
        例: malloc→rax→[rbp-8]→...→mov rax,[rbp-8]→use→rax
        """
        visited: set = set()  # (line, reg)防循环
        alloc_line = self._trace_reg_to_alloc(
            asm, use_line, use_reg, alloc_sites, mem_stores, visited, 0)
        if alloc_line >= 0:
            af = next((a['func'] for a in alloc_sites if a['line'] == alloc_line), '')
            return PointerProvenance(kind=ProvenanceKind.ALLOC,
                line=alloc_line, alloc_func=af, reg=use_reg, confidence=0.9)
        # 备选: 来自全局加载
        for i in range(use_line - 1, max(use_line - self._max_trace, -1), -1):
            gm = _GLOBAL_LOAD.search(asm[i])
            if gm and gm.group(1) == use_reg:
                return PointerProvenance(kind=ProvenanceKind.LOAD_GLOBAL,
                    line=i, load_addr=gm.group(2), reg=use_reg, confidence=0.6)
        return PointerProvenance(kind=ProvenanceKind.UNKNOWN, reg=use_reg)

    def _trace_reg_to_alloc(self, asm: List[str], line: int, reg: str,
                             alloc_sites: List[Dict], mem_stores: List[Dict],
                             visited: set, depth: int) -> int:
        """后向追踪reg到最近的alloc site, 支持栈槽链和寄存器mov。
        返回alloc_site的line, 或-1表示未找到。
        """
        if depth > 20:
            return -1
        key = (line, reg)
        if key in visited:
            return -1
        visited.add(key)
        norm_reg = _norm_reg(reg)

        # 1) 若reg=rax且在alloc返回之后附近 → 直接命中
        # BUT: 先检查rax是否来自栈加载 — 若是, 走栈槽追踪避免误配
        if norm_reg == 'rax':
            # 快速检查: rax在最近几条指令中是否从栈加载
            for j in range(line - 1, max(line - 5, -1), -1):
                sm_j = _STACK_LOAD.search(asm[j])
                if sm_j and _norm_reg(sm_j.group(1)) == 'rax':
                    # rax来自栈槽 → 走栈槽追踪, 不信任最近alloc捷径
                    store_alloc = self._find_stack_store_source(
                        asm, sm_j.group(2), j, alloc_sites, mem_stores, visited, depth + 1)
                    if store_alloc >= 0:
                        return store_alloc
                    break  # 栈槽存在但追踪失败 → 不走alloc捷径
            else:
                # rax不在最近栈加载中 → 可能是直接alloc返回
                for a in sorted(alloc_sites, key=lambda a: a['line'], reverse=True):
                    if a['line'] < line and (line - a['line']) <= self._max_trace:
                        closer = [a2 for a2 in alloc_sites
                                  if a['line'] < a2['line'] < line]
                        if not closer:
                            return a['line']

        # 2) 后向扫描: 找reg的上一个定义点
        for i in range(line - 1, max(line - self._max_trace, -1), -1):
            instr = _strip_addr(asm[i]).lower().replace(',', ' ')

            # 栈加载: mov reg, [rbp+/-N] 或 mov reg, [rsp+/-N]
            sm = _STACK_LOAD.search(asm[i])
            if sm and _norm_reg(sm.group(1)) == norm_reg:
                slot = sm.group(2)
                # 找最后写入此栈槽的store
                store_alloc = self._find_stack_store_source(
                    asm, slot, i, alloc_sites, mem_stores, visited, depth + 1)
                if store_alloc >= 0:
                    return store_alloc
                continue

            # 直接mov: mov reg, src_reg
            parts = instr.split()
            if len(parts) >= 3 and parts[0] in ('mov', 'movsxd'):
                d = parts[1].rstrip(',')
                s = parts[2]
                if _norm_reg(d) == norm_reg and _is_gp_reg(s):
                    sub = self._trace_reg_to_alloc(
                        asm, i, s, alloc_sites, mem_stores, visited, depth + 1)
                    if sub >= 0:
                        return sub
                # mov reg, [rip+...] → 全局加载
                if _norm_reg(d) == norm_reg and 'rip' in s:
                    break  # 无法进一步追踪

            # lea: lea reg, [...] — 地址计算, 不是从堆来
            if len(parts) >= 3 and parts[0] == 'lea':
                d = parts[1].rstrip(',')
                if _norm_reg(d) == norm_reg:
                    break  # lea不是堆指针

        return -1

    def _find_stack_store_source(self, asm: List[str], slot: str,
                                   load_line: int, alloc_sites: List[Dict],
                                   mem_stores: List[Dict],
                                   visited: set, depth: int) -> int:
        """找到写入栈槽slot的最近store, 追踪其源寄存器到alloc。
        例: free(r1)后r1的栈槽[rbp-8]被r2覆盖 → 不应追踪到r1的alloc。
        """
        for j in range(load_line - 1, max(load_line - 100, -1), -1):
            instr = _strip_addr(asm[j]).lower()  # 保留逗号供regex匹配
            m = _MEM_STORE.search(instr)
            if m:
                stored_addr = m.group(1)
                src = m.group(2)
                # 匹配: [rbp-N] 或 [rbp+N]
                if slot in stored_addr or stored_addr in slot:
                    if src in ('rax', 'eax'):
                        # 找最近的alloc < store_line
                        for a in sorted(alloc_sites, key=lambda a: a['line'], reverse=True):
                            if a['line'] < j and (j - a['line']) <= self._max_trace:
                                closer = [a2 for a2 in alloc_sites
                                          if a['line'] < a2['line'] < j]
                                if not closer:
                                    return a['line']
                    elif _is_gp_reg(src):
                        return self._trace_reg_to_alloc(
                            asm, j, src, alloc_sites, mem_stores, visited, depth)
                    break
        return -1

# 同一指针源验证

    def _same_pointer_source(self, asm: List[str],
                              free_line: int, free_reg: str,
                              use_line: int, use_reg: str,
                              alloc_sites: List[Dict],
                              mem_stores: List[Dict]) -> bool:
        """验证free参数和use寄存器是否指向同一指针对象。

        避免free(obj_A) + use(obj_B) → 误配为UAF。
        四级判定:
          1. 同寄存器名或兼容名 (rax/eax→同物理寄存器)
          2. 同alloc来源 (trace_reg_to_alloc匹配)
          3. 同栈槽来源
          4. free通过栈槽追踪到与use相同的alloc
        """
        # 级别1: 寄存器名兼容
        if _norm_reg(free_reg) == _norm_reg(use_reg):
            return True

        # 级别2: 追踪到同一alloc
        free_alloc = self._trace_reg_to_alloc(
            asm, free_line, free_reg, alloc_sites, mem_stores, set(), 0)
        use_alloc = self._trace_reg_to_alloc(
            asm, use_line, use_reg, alloc_sites, mem_stores, set(), 0)
        if free_alloc >= 0 and use_alloc >= 0 and free_alloc == use_alloc:
            return True

        # 级别3: use通过栈槽追踪到free_alloc
        if free_alloc >= 0 and use_alloc < 0:
            for i in range(use_line - 1, max(use_line - 10, -1), -1):
                sm = _STACK_LOAD.search(asm[i])
                if sm and _norm_reg(sm.group(1)) == _norm_reg(use_reg):
                    store_alloc = self._find_stack_store_source(
                        asm, sm.group(2), i, alloc_sites, mem_stores, set(), 0)
                    if store_alloc == free_alloc:
                        return True

        # 级别4: free通过栈槽追踪到use_alloc
        if use_alloc >= 0 and free_alloc < 0:
            for i in range(free_line - 1, max(free_line - 10, -1), -1):
                sm = _STACK_LOAD.search(asm[i])
                if sm and _norm_reg(sm.group(1)) == _norm_reg(free_reg):
                    store_alloc = self._find_stack_store_source(
                        asm, sm.group(2), i, alloc_sites, mem_stores, set(), 0)
                    if store_alloc == use_alloc:
                        return True

        return False

    @staticmethod
    def _has_realloc_between(asm: List[str], free_line: int,
                              use_line: int, alloc_sites: List[Dict]) -> bool:
        return any(free_line < a['line'] < use_line for a in alloc_sites)

    @staticmethod
    def _collect_guards(asm: List[str], start: int, end: int) -> List[str]:
        guards = []
        for i in range(max(start, 0), min(end + 1, len(asm))):
            line = asm[i].strip()
            if re.search(r'\b(cmp|test|j[a-z]{1,3})\b', line, re.I):
                guards.append(line)
        return guards

# 置信度

    @staticmethod
    def _estimate_confidence(path: FreeUsePath) -> float:
        score = (path.prov.confidence * 0.4) if path.prov else 0.0
        d = path.instruction_distance
        score += 0.3 if d <= 5 else 0.2 if d <= 15 else 0.1 if d <= 30 else 0.0
        if path.prov and path.prov.kind == ProvenanceKind.ALLOC: score += 0.2
        elif path.prov and path.prov.kind == ProvenanceKind.LOAD_STACK: score += 0.1
        if path.realloc_on_path: score *= 0.3
        return min(score, 1.0)

# 辅助

    @staticmethod
    def _find_free_arg(asm: List[str], free_idx: int) -> str:
        """找free调用的参数寄存器 (Win x64: rcx, Linux x64: rdi)。"""
        for j in range(free_idx - 1, max(free_idx - 8, -1), -1):
            instr = _strip_addr(asm[j]).lower().replace(',', ' ')
            m = _FREE_ARG_PAT.search(instr)
            if m:
                return m.group(2)
        # 默认: Windows x64第一参数 → rcx
        return 'rcx'
