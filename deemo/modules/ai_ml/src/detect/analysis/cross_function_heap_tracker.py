# 跨函数堆溢出检测-malloc/copy包装器识别 + 调用点合成配对
# 解决CVE-2020-25656型FN: alloc和copy在不同函数中(包装器模式)
import re, logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)
_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}
_COPY_FUNCS = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'memset',
              'sprintf', 'snprintf', 'gets', 'read', 'fread', 'recv'}
_NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr', 'xmmword',
           'ymmword', 'zmmword', 'tbyte', 'oword', 'mmword'}
_CRT_PFX = ('__', '_', '.', 'mingw', 'msvc', 'pre_c_init', 'pre_cpp_init',
            'dyn_tls', 'pei386', 'gnu_exception', 'register_frame',
            'deregister_frame', 'do_global', 'mark_section', 'restore_',
            'tmain', 'FindPE', 'GetPE', 'IsNon', 'mingw_')
_WIN_PARAMS = ['rcx', 'rdx', 'r8', 'r9']
_LINUX_PARAMS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_REG32 = {'rax':'eax','rbx':'ebx','rcx':'ecx','rdx':'edx','rsi':'esi',
          'rdi':'edi','rbp':'ebp','rsp':'esp','r8':'r8d','r9':'r9d',
          'r10':'r10d','r11':'r11d','r12':'r12d','r13':'r13d',
          'r14':'r14d','r15':'r15d'}
_REG64 = {v: k for k, v in _REG32.items()}


@dataclass
class FuncSummary:
    """函数alloc/copy行为摘要-轻量malloc/memcpy包装器识别"""
    name: str
    is_alloc_wrapper: bool = False   # 调用malloc并返回rax
    is_copy_wrapper: bool = False    # 调用memcpy且dst来自参数
    alloc_func: str = ""             # 底层alloc函数名
    alloc_size_param: int = -1       # alloc大小是第几个参数
    copy_func: str = ""              # 底层copy函数名
    dst_param: int = -1              # dst是第几个参数
    size_param: int = -1             # copy大小是第几个参数


class CrossFunctionHeapTracker:
    """跨函数堆溢出检测-包装器摘要 + 调用点数据流合成配对"""
    def build_summaries(self, functions: List) -> Dict[str, FuncSummary]:
        summaries: Dict[str, FuncSummary] = {}
        for func in functions:
            if not func.instructions or self._is_crt(func.name): continue
            s = self._summarize(func)
            if s.is_alloc_wrapper or s.is_copy_wrapper:
                summaries[func.name] = s
        return summaries

    def _summarize(self, func) -> FuncSummary:
        instrs = func.instructions
        s = FuncSummary(name=func.name)
        is_att = self._detect_syntax(instrs)
        params = _LINUX_PARAMS if is_att else _WIN_PARAMS
        for i, il in enumerate(instrs):
            il = il.strip().lower()
            if 'call' not in il: continue
            # alloc wrapper检测: 调用malloc→返回rax
            for af in _ALLOC_FUNCS:
                if af not in il: continue
                if self._returns_rax(instrs, i):
                    s.is_alloc_wrapper = True; s.alloc_func = af
                    sr = self._trace_arg(instrs, i, 0, params, is_att)
                    if sr is not None: s.alloc_size_param = self._param_idx(sr, params)
                break
            # copy wrapper检测: 调用memcpy→dst来自参数
            for cf in _COPY_FUNCS:
                if cf not in il: continue
                dr = self._trace_arg(instrs, i, 0, params, is_att)
                if dr is not None:
                    s.is_copy_wrapper = True; s.copy_func = cf
                    s.dst_param = self._param_idx(dr, params)
                    szr = self._trace_arg(instrs, i, 2, params, is_att)
                    if szr is not None: s.size_param = self._param_idx(szr, params)
                break
        return s

    def detect(self, functions: List, summaries: Dict[str, FuncSummary]
              ) -> List[Dict]:
        findings = []
        for func in functions:
            if not func.instructions or self._is_crt(func.name): continue
            findings.extend(self._scan_caller(func, summaries))
        return findings

    def _scan_caller(self, func, summaries: Dict[str, FuncSummary]) -> List[Dict]:
        instrs = func.instructions
        is_att = self._detect_syntax(instrs)
        params = _LINUX_PARAMS if is_att else _WIN_PARAMS
        # 收集alloc wrapper调用: (call_idx, summary, size_src, result_dest)
        allocs = []
        for i, il in enumerate(instrs):
            il = il.strip().lower()
            if 'call' not in il: continue
            cn = self._callee(il)
            if not cn or cn not in summaries: continue
            ws = summaries[cn]
            if ws.is_alloc_wrapper:
                sz = self._call_arg_src(instrs, i, ws.alloc_size_param, params, is_att)
                rd = self._rax_dest(instrs, i, is_att)
                allocs.append((i, ws, sz, rd))
        # 匹配copy wrapper调用
        findings = []
        for i, il in enumerate(instrs):
            il = il.strip().lower()
            if 'call' not in il: continue
            cn = self._callee(il)
            if not cn or cn not in summaries: continue
            ws = summaries[cn]
            if not ws.is_copy_wrapper: continue
            dst_src = self._call_arg_src(instrs, i, ws.dst_param, params, is_att)
            sz_src = self._call_arg_src(instrs, i, ws.size_param, params, is_att) if ws.size_param >= 0 else None
            for ai, aw, a_sz, a_dest in allocs:
                if ai >= i: continue
                if not dst_src or not a_dest: continue
                if dst_src != a_dest: continue  # copy dst必须来自alloc结果
                ev = [f"cross-func heap: {aw.name}(alloc)→{ws.name}(copy) in {func.name}",
                      f"alloc={aw.alloc_func}(param{aw.alloc_size_param}) copy={ws.copy_func}(param{ws.size_param})"]
                a_v = self._resolve_val(instrs, a_sz, is_att) if a_sz else None
                c_v = self._resolve_val(instrs, sz_src, is_att) if sz_src else None
                conf, verdict = 0.55, 'cross_heap_likely'
                if a_v is not None and c_v is not None:
                    try:
                        if int(c_v, 0) > int(a_v, 0):
                            conf, verdict = 0.85, 'cross_heap_confirmed'
                            ev.append(f"overflow: alloc={a_v} < copy={c_v}")
                        else:
                            ev.append(f"safe: alloc={a_v} >= copy={c_v}")
                            continue  # 安全, 不报告
                    except (ValueError, TypeError): pass
                else:
                    ev.append(f"alloc_sz={a_v or '?'} copy_sz={c_v or '?'}")
                findings.append({'type': verdict, 'confidence': conf,
                    'func_name': func.name, 'alloc_wrapper': aw.name,
                    'copy_wrapper': ws.name, 'alloc_func': aw.alloc_func,
                    'copy_func': ws.copy_func, 'evidence': ev})
        return findings

# 指令解析辅助
    @staticmethod
    def _detect_syntax(instrs: List[str]) -> bool:
        return any('%' in i for i in instrs[:min(15, len(instrs))]
                   if i.strip() and not i.strip().startswith(';'))
    @staticmethod
    def _is_crt(name: str) -> bool:
        return any(name.lower().startswith(p) for p in _CRT_PFX)
    @staticmethod
    def _callee(instr: str) -> Optional[str]:
        m = re.search(r'call\s+(?:qword\s+ptr\s+)?(?:0x)?[0-9a-f]+\s+<([^>]+)>', instr)
        if m: return m.group(1)
        m = re.search(r'call\s+(?:qword\s+ptr\s+)?\[rip[+\-]0x[0-9a-f]+\]\s*<([^>]+)>', instr)
        if m: return m.group(1)
        if re.search(r'call\s+\*?%?\w+$', instr) or re.search(r'call\s+(?:rax|rbx|rcx|rdx|rsi|rdi|r\d+)', instr):
            return None
        m = re.search(r'call\s+(?:qword\s+ptr\s+)?([a-z_]\w*(?:@\w+)?)', instr)
        return m.group(1) if m else None
    @staticmethod
    def _returns_rax(instrs: List[str], ci: int) -> bool:
        for j in range(ci + 1, min(ci + 10, len(instrs))):
            il = instrs[j].strip().lower()
            if 'ret' in il and not il.startswith(';'): return True
            if 'call' in il: return False
            if re.search(rf'(?:mov\s+\$?(?:0x[0-9a-f]+|\d+)|xor)\s+%?(?:rax|eax)\b', il):
                return False
        return False

    def _trace_arg(self, instrs: List[str], ci: int, arg_i: int,
                   params: List[str], is_att: bool) -> Optional[str]:
        if arg_i >= len(params): return None
        r = self._trace_back(instrs, ci - 1, params[arg_i], is_att, 8)
        if r and r.startswith('slot:'):
            pi = self._slot_to_param(instrs, r, params, is_att)
            return pi if pi is not None else r
        return r
    def _call_arg_src(self, instrs: List[str], ci: int, arg_i: int,
                      params: List[str], is_att: bool) -> Optional[str]:
        if arg_i < 0 or arg_i >= len(params): return None
        return self._trace_back(instrs, ci - 1, params[arg_i], is_att, 6)
    @staticmethod
    def _slot_to_param(instrs: List[str], slot: str, params: List[str],
                       is_att: bool) -> Optional[str]:
        off = slot.split('@')[1] if '@' in slot else None
        if not off: return None
        off = off.strip().lower()
        pat = re.compile(rf'mov\s+(?:qword|dword|word)?\s*(?:ptr\s+)?'
                         rf'\[rbp{re.escape(off)}\]\s*,\s*%?(\w+)')
        for i in range(min(15, len(instrs))):
            il = instrs[i].strip().lower()
            if not il or il.startswith(';'): continue
            m = pat.search(il)
            if m and m.group(1) not in _NON_REG:
                r = m.group(1).lower()
                if r in params: return r
                r64 = _REG64.get(r)
                if r64 and r64 in params: return r64
        return None

    def _trace_back(self, instrs: List[str], start: int, target: str,
                    is_att: bool, md: int) -> Optional[str]:
        """反向追踪寄存器值来源→返回'slot:REG@OFF', 'const:N', reg名"""
        cur = target.lower().lstrip('%')
        for j in range(start, max(-1, start - md), -1):
            if j < 0: break
            il = instrs[j].strip().lower()
            if not il or il.startswith(';') or il.startswith('.'): continue
            # 栈加载 (含32/64位变体)
            for r in [cur] + self._reg_aliases(cur):
                m = re.search(rf'mov\s+%?{re.escape(r)}\s*,\s*(?:\w+\s+ptr\s+)?'
                             r'\[rbp([+\-]0x[0-9a-f]+)\]', il)
                if m: return f'slot:{r}@{m.group(1)}'
            # 寄存器mov (含32/64位变体)
            for r in [cur] + self._reg_aliases(cur):
                src = self._match_reg_mov(il, r, is_att)
                if src and src not in _NON_REG:
                    cur = src; break
            else: src = None
            if src: continue
            # movsxd (符号扩展)
            m = re.match(rf'movsxd\s+%?{re.escape(cur)}\s*,\s*%?(\w+)', il)
            if m and m.group(1) not in _NON_REG:
                cur = m.group(1).lower(); continue
            # cdqe
            if cur == 'rax' and 'cdqe' in il:
                cur = 'eax'; continue
            # mov imm (含32/64位变体)
            for r in [cur] + self._reg_aliases(cur):
                m = re.search(rf'mov\s+%?{re.escape(r)}\s*,\s*\$?(0x[0-9a-f]+|\d+)', il)
                if m: return f'const:{m.group(1)}'
            # xor reg,reg → 0
            if re.match(rf'xor\s+%?({re.escape(cur)}),\s*%?\1', il): return 'const:0'
            # lea reg, [reg2] → 指针别名
            m = re.match(rf'lea\s+%?{re.escape(cur)}\s*,\s*(?:qword\s+ptr\s+)?\[%?(\w+)\]', il)
            if m and m.group(1) not in _NON_REG:
                cur = m.group(1).lower(); continue
        return cur if cur != target.lower().lstrip('%') else None

    @staticmethod
    def _reg_aliases(reg: str) -> List[str]:
        r32, r64 = _REG32.get(reg), _REG64.get(reg)
        return [x for x in (r32, r64) if x]
    @staticmethod
    def _match_reg_mov(il: str, dst: str, is_att: bool) -> Optional[str]:
        if is_att:
            m = re.match(rf'mov\s+%(\w+),\s*%{re.escape(dst)}', il)
            return m.group(1) if m else None
        m = re.match(rf'mov\s+%?{re.escape(dst)},\s*%?(\w+)', il)
        return m.group(1) if m else None
    def _rax_dest(self, instrs: List[str], ci: int, is_att: bool
                  ) -> Optional[str]:
        for j in range(ci + 1, min(ci + 10, len(instrs))):
            il = instrs[j].strip().lower()
            if 'ret' in il and not il.startswith(';'): return None
            if 'call' in il: break
            m = re.search(rf'mov\s+(?:qword\s+ptr\s+)?\[rbp([+\-]0x[0-9a-f]+)\]\s*,'
                         r'\s*%?(?:rax|eax)', il)
            if m: return f'slot:rax@{m.group(1)}'
            if is_att:
                m = re.match(r'mov\s+%(?:rax|eax),\s*%(\w+)', il)
                if m and m.group(1) not in _NON_REG: return m.group(1).lower()
            else:
                m = re.match(rf'mov\s+%?(\w+),\s*%?(?:rax|eax)', il)
                if m and m.group(1) not in _NON_REG: return m.group(1).lower()
            if re.search(rf'(?:cmp|test)\s+.*%?(?:rax|eax)', il): continue
            if re.match(r'j[ae-gi-ln-pr-uw-z]', il): continue
        return 'rax'
    def _resolve_val(self, instrs: List[str], src: str, is_att: bool
                     ) -> Optional[str]:
        if not src: return None
        if src.startswith('const:'): return src[6:]
        if src.startswith('slot:'): return None
        deeper = self._trace_back(instrs, len(instrs) - 1, src, is_att, 10)
        if deeper and deeper.startswith('const:'): return deeper[6:]
        return None
    @staticmethod
    def _param_idx(reg: str, params: List[str]) -> int:
        r = reg.lower().lstrip('%')
        if r in params: return params.index(r)
        if r.startswith('slot:') or r.startswith('const:'): return -1
        for i, pr in enumerate(params):
            if _REG32.get(pr) == r: return i
        return -1
