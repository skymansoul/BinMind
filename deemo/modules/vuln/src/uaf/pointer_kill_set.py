"""DRIFT 指针Kill/Gen分析 — 数据流层面的指针对象生命周期.

对每个指令, 确定它"杀死"(kill)哪些寄存器的对象身份, 以及"生成"(gen)哪些.
然后从free点后向数据流切片, 确认free和use作用于同一对象身份.

创建: 2026-06-29
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re

from .object_identity import (
    _canon_reg, _ALLOC_FUNCS, _FREE_FUNCS, _DEREF_PAT,
    _MEM_WRITE_PAT, _MOV_REG, _MOV_STACK_LOAD, _MOV_STACK_STORE,
    _LEA_PAT, _XOR_ZERO, _RIP_LOAD_PAT, _parse_int)


@dataclass
class InsnEffect:
    """单条指令对寄存器对象身份的效应."""
    line: int
    addr: int = 0
    mnemonic: str = ""
    # KILL: 这些寄存器在此指令后失去对象身份
    kills: Set[str] = field(default_factory=set)
    # GEN: 此指令生成了新对象身份 (malloc call)
    gen_alloc: bool = False
    gen_func: str = ""
    # USE: 此指令解引用了哪个寄存器
    deref_reg: Optional[str] = None
    # MOV: 寄存器间移动
    mov_dst: Optional[str] = None
    mov_src: Optional[str] = None
    # STACK: 栈槽存取
    stack_store: Optional[Tuple[int, str]] = None  # (offset, src_reg)
    stack_load: Optional[Tuple[str, int]] = None   # (dst_reg, offset)
    # FREE: free调用, 参数来自哪个寄存器
    free_call: bool = False
    free_reg: str = ""
    # LEA: 派生指针
    lea_dst: Optional[str] = None
    lea_base: Optional[str] = None
    lea_off: int = 0
    # XOR: 清零
    xor_zero: Optional[str] = None
    # HEAP: 堆上struct字段存取 (通过非栈指针间接访问)
    # heap_store: (base_reg, offset, value_reg) — mov [base+off], value
    heap_store: Optional[Tuple[str, int, str]] = None
    # heap_load: (dst_reg, base_reg, offset) — mov dst, [base+off]
    heap_load: Optional[Tuple[str, str, int]] = None
    # GLOBAL: 全局变量存取 (RIP相对寻址)
    # global_store: (rip_offset, src_reg) — mov [rip+off], src
    global_store: Optional[Tuple[int, str]] = None
    # global_load: (dst_reg, rip_offset) — mov dst, [rip+off]
    global_load: Optional[Tuple[str, int]] = None
    # RET: 函数返回 → 清除所有寄存器身份
    is_ret: bool = False
    # CALL_CLOBBER: 函数返回后易失寄存器被破坏
    is_call: bool = False  # call到非alloc/free函数
    call_target: str = ""  # call目标函数名 (如 task_run)
    # FUNC_ENTRY: 函数入口 (push rbp; mov rbp, rsp) → 新函数上下文
    is_func_entry: bool = False
    # USER_FUNC: 当前指令在用户函数中 (非CRT/库代码)
    in_user_func: bool = True
    # 当前函数名 (用于CRT过滤)
    func_name: str = ""


def analyze_insn_effects(asm_lines: List[str]) -> List[InsnEffect]:
    """分析每条指令对指针对象身份的影响.

    这是DRIFT的"数据流预处理"步骤 — 将汇编指令分类为
    ALLOC/GEN/USE/KILL/MOV/STACK/FREE/XOR/LEA 九类效应,
    供后续对象身份追踪使用.
    """
    effects: List[InsnEffect] = []
    # 当前函数上下文: 初始为CRT (main之前的初始化代码)
    _current_func = ""
    _in_user = False

    # 函数名→是否用户函数的判定模式
    _CRT_PREFIXES = ('__', '_')  # __tmainCRTStartup, _pei386, etc.
    _CRT_KEYWORDS = ('mingw', 'crt', 'atexit', 'runtime', 'startup',
                     'handler', 'managed', 'initterm', 'invoke', 'register')

    _FN_LABEL_RE = re.compile(r'[0-9a-f]+\s+<([^>]+)>:\s*$')

    for i, line in enumerate(asm_lines):
        il = line.strip()
        if not il or il.startswith(';') or il.startswith('.'):
            continue

        # 提取指令地址 (objdump格式: "  401000:   48 8b 45 f8    mov ...")
        addr = 0
        addr_m = re.match(r'\s*([0-9a-f]+):\s+', il)
        if addr_m:
            addr = int(addr_m.group(1), 16)

        il_lower = il.lower()
        eff = InsnEffect(line=i, addr=addr)

        # 函数标签检测: 更新当前函数上下文 (用户 vs CRT)
        fn_m = _FN_LABEL_RE.match(il)
        if fn_m:
            _current_func = fn_m.group(1)
            _in_user = _is_user_func(_current_func,
                                     _CRT_PREFIXES, _CRT_KEYWORDS)
        eff.func_name = _current_func
        eff.in_user_func = _in_user

        # 提取助记符 — objdump格式: "140001001: 48 89 e5 mov rbp,rsp"
        # 跳过地址和机器码字节, 取第一个非十六进制token
        if addr_m:
            # 地址后的内容: 机器码(连续hex字节) + 助记符 + 操作数
            after_addr = il_lower[addr_m.end():].strip()
            non_hex_start = 0
            for token in after_addr.split():
                if re.match(r'^[0-9a-f]{2}$', token):
                    non_hex_start += len(token) + 1
                else:
                    break
            rest = after_addr[non_hex_start:].strip()
            mnem_parts = rest.split()
            eff.mnemonic = mnem_parts[0] if mnem_parts else ""
        else:
            parts = il_lower.split()
            eff.mnemonic = parts[0] if parts else ""

        # 函数入口检测: push rbp 后跟 帧指针设置 (mov rbp,rsp 或 lea rbp,[rsp+N])
        # 直接用原始行内容检测, 避免依赖助记符提取
        if ('push' in il_lower and 'rbp' in il_lower
                and _has_frame_pointer_setup(asm_lines, i)):
            eff.is_func_entry = True
        # 也检测 enter 指令 (少见但存在)
        if eff.mnemonic == 'enter':
            eff.is_func_entry = True

        # 1. ALLOC — call malloc/calloc/realloc
        alloc_m = _ALLOC_FUNCS.search(il_lower)
        if alloc_m:
            eff.gen_alloc = True
            eff.gen_func = alloc_m.group(1).lower()
            # realloc 同时释放旧指针 → 也设为 free_call
            if eff.gen_func == 'realloc':
                eff.free_call = True
                eff.free_reg = _find_free_arg(asm_lines, i)
            effects.append(eff)
            continue

        # 2. FREE — call free/delete
        free_m = _FREE_FUNCS.search(il_lower)
        if free_m:
            eff.free_call = True
            # 从前面指令找free的参数寄存器
            eff.free_reg = _find_free_arg(asm_lines, i)
            effects.append(eff)
            continue

        # 3. 从指令操作数中提取效应

        # XOR zero
        xor_m = _XOR_ZERO.search(il_lower)
        if xor_m:
            eff.xor_zero = _canon_reg(xor_m.group(1))
            eff.kills.add(eff.xor_zero)

        # LEA
        lea_m = _LEA_PAT.search(il)
        if lea_m:
            eff.lea_dst = _canon_reg(lea_m.group(1))
            eff.lea_base = _canon_reg(lea_m.group(2))
            sign = 1 if lea_m.group(3) == '+' else -1
            eff.lea_off = sign * _parse_int(lea_m.group(4))

        # Stack store
        stack_s_m = _MOV_STACK_STORE.search(il)
        if stack_s_m:
            sign = 1 if stack_s_m.group(1) == '+' else -1
            off = sign * _parse_int(stack_s_m.group(2))
            src = _canon_reg(stack_s_m.group(3))
            eff.stack_store = (off, src)

        # Stack load
        stack_l_m = _MOV_STACK_LOAD.search(il)
        if stack_l_m:
            dst = _canon_reg(stack_l_m.group(1))
            sign = 1 if stack_l_m.group(2) == '+' else -1
            off = sign * _parse_int(stack_l_m.group(3))
            eff.stack_load = (dst, off)

        # MOV reg, reg
        mov_m = _MOV_REG.search(il)
        if mov_m:
            eff.mov_dst = _canon_reg(mov_m.group(1))
            eff.mov_src = _canon_reg(mov_m.group(2))

        # MOV reg, imm → kill dst
        # re.search (非match): objdump行有地址前缀
        if re.search(r'\bmov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', il_lower):
            m = re.search(r'\bmov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', il_lower)
            if m:
                d = _canon_reg(m.group(1))
                eff.kills.add(d)

        # 解引用检查: [reg] 模式
        deref_m = _DEREF_PAT.search(il)
        if deref_m:
            deref_mnem = deref_m.group(1).lower()
            base_reg = _canon_reg(deref_m.group(3))
            if base_reg not in ('rip', 'rsp', 'rbp', 'rsi', 'rdi'):
                eff.deref_reg = base_reg
                # 堆struct字段加载: mov dst, [base+off] → 恢复对象身份
                if deref_mnem == 'mov':
                    dst_reg = _canon_reg(deref_m.group(2))
                    off_str = (deref_m.group(4) or '').replace(' ', '')
                    heap_off = 0
                    if off_str:
                        sign = -1 if off_str.startswith('-') else 1
                        heap_off = sign * (_parse_int(
                            off_str.lstrip('+-')) or 0)
                    eff.heap_load = (dst_reg, base_reg, heap_off)

        # 内存写入: mov [reg], val
        write_m = _MEM_WRITE_PAT.search(il)
        if write_m:
            base_reg = _canon_reg(write_m.group(1))
            val_reg = _canon_reg(write_m.group(3))
            if base_reg not in ('rip', 'rsp', 'rbp'):
                eff.deref_reg = base_reg  # 通过指针写入=解引用
                # 堆struct字段存储: mov [base+off], val → 记录对象身份传递
                off_str = (write_m.group(2) or '').replace(' ', '')
                heap_off = 0
                if off_str:
                    sign = -1 if off_str.startswith('-') else 1
                    heap_off = sign * (_parse_int(
                        off_str.lstrip('+-')) or 0)
                eff.heap_store = (base_reg, heap_off, val_reg)
            elif base_reg == 'rip':
                # 全局变量存储: mov [rip+off], val
                # 目标绝对地址 ≈ addr + 7 (典型RIP相对mov指令长度) + rip_off
                off_str = (write_m.group(2) or '').replace(' ', '')
                if off_str:
                    sign = -1 if off_str.startswith('-') else 1
                    rip_off = sign * (_parse_int(off_str.lstrip('+-')) or 0)
                    eff.global_store = (addr + 7 + rip_off, val_reg)

        # RIP相对寻址的LOAD: mov dst, [rip+off]
        # 目标绝对地址 ≈ addr + 7 + rip_off
        rip_load_m = _RIP_LOAD_PAT.search(il)
        if rip_load_m:
            dst = _canon_reg(rip_load_m.group(1))
            sign = -1 if rip_load_m.group(2) == '-' else 1
            rip_off = sign * (_parse_int(rip_load_m.group(3)) or 0)
            eff.global_load = (dst, addr + 7 + rip_off)

        # call clobber — push call_stack, 不杀参数寄存器
        # rcx/rdx/r8-r9的kill移除: 被调函数需要寄存器中的对象身份
        # 处理参数保存; _call_stack机制在ret时恢复调用前状态.
        if eff.mnemonic == 'call' and not alloc_m and not free_m:
            eff.is_call = True
            eff.call_target = _extract_call_target(il_lower)

        # ret → 清除所有寄存器 + 栈槽对象身份
        # re.search (非match): objdump行有地址前缀
        if re.search(r'\b(ret|retn|rep\s+ret)\b', il_lower):
            eff.is_ret = True

        effects.append(eff)

    return effects


def _is_user_func(name: str, crt_prefixes: tuple,
                  crt_keywords: tuple) -> bool:
    """判定函数名是否为用户代码 (非CRT/库).

    采用黑名单+白名单混合策略:
      - main 永远是用户函数
      - __ / _ 开头 (非C++ mangled _Z) → CRT
      - 包含 mingw/crt/atexit/runtime/startup/handler → CRT
      - 包含特殊CRT模式 → CRT
      - 其他 → 用户代码 (保守)
    """
    if not name:
        return False  # 未知标签 (如 .l_start) → 保守视为CRT, 不追踪
    # 以 . 开头的本地标签 → CRT
    if name.startswith('.'):
        return False
    nl = name.lower()
    # main 永远是用户入口
    if nl == 'main':
        return True
    # 显式CRT前缀: __ 或 _
    if nl.startswith('__'):
        return False
    if nl.startswith('_') and not nl.startswith('_z'):
        return False
    # CRT关键词
    for kw in crt_keywords:
        if kw in nl:
            return False
    # CRT特定函数模式
    _CRT_NAMES = {'winmaincrtstartup', 'maincrtstartup',
                  'check_managed_app', 'duplicate_ppstrings',
                  'do_pseudo_reloc', 'mark_section_writable',
                  'restore_modified_sections', 'safe_flush'}
    if nl in _CRT_NAMES:
        return False
    # 默认 → 用户代码
    return True


def _find_free_arg(asm_lines: List[str], free_idx: int) -> str:
    """向前5条指令内找free参数的来源寄存器 (rdi on SysV/MS64)."""
    for j in range(free_idx - 1, max(free_idx - 6, -1), -1):
        line = asm_lines[j].strip().lower().replace(',', ' ')
        m = re.search(r'\bmov\s+(rdi|rcx|edi|ecx),?\s*(\w+)', line)
        if m:
            return _canon_reg(m.group(2))
    return 'rdi'


_CALL_TARGET_RE = re.compile(r'call\s+(?:[0-9a-f]+\s+<)?(\w+)>?', re.I)


def _extract_call_target(il_lower: str) -> str:
    """从call指令中提取目标函数名. Intel: call ADDR <func>"""
    m = _CALL_TARGET_RE.search(il_lower)
    return m.group(1) if m else ""


def _has_frame_pointer_setup(asm_lines: List[str], line_idx: int) -> bool:
    """检查line_idx后~8条指令内是否有帧指针设置 (push rbp → mov/lea rbp).

    支持标准序言和非标准序言:
      push rbp; mov rbp, rsp                         ← 标准
      push rbp; push rbx; sub rsp, N; lea rbp, [rsp+N] ← 额外push
    """
    for j in range(line_idx + 1, min(line_idx + 8, len(asm_lines))):
        nl = asm_lines[j].strip().lower()
        if not nl or nl.startswith(';') or nl.startswith('.'):
            continue
        # mov rbp, rsp (排除 [rbp+N] 和 [rsp+N] 内存操作)
        if ('mov' in nl and 'rbp' in nl and 'rsp' in nl
                and not re.search(r'\[(?:rbp|rsp)', nl)):
            return True
        # lea rbp, [rsp+N] (e.g., lea rbp, [rsp+0x30])
        if re.search(r'\blea\s+rbp,\s*\[rsp[+\-]', nl):
            return True
    return False


def compute_kill_gen(insn_effects: List[InsnEffect]
                     ) -> Tuple[Dict[int, Set[str]], Dict[int, Set[str]]]:
    """计算每个程序点的KILL/GEN集合.

    返回: (kill_at, gen_at) — 每个行号的kill集合和gen集合.
    kill: 该指令清除的寄存器对象身份.
    gen: 该指令生成的对象身份 (malloc).
    """
    kill_at: Dict[int, Set[str]] = {}
    gen_at: Dict[int, Set[str]] = {}

    for eff in insn_effects:
        if eff.kills:
            kill_at[eff.line] = eff.kills.copy()
        if eff.gen_alloc:
            # malloc → gen rax (持有新对象)
            gen_at[eff.line] = {'rax', 'eax'}

    return kill_at, gen_at
