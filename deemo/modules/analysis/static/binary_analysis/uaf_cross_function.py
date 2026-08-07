# 跨函数UAF检测增强 — 追踪指针通过函数调用逃逸后在调用者中的使用
# uaf_detector.py 仅做函数内扫描; 本模块补充跨函数场景
# 方法论依据: UAFSan — 别名分析+跨函数liveness

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .uaf_detector import UAFDetector, UAFVerdict, UAFFinding

@dataclass
class PointerEscape:
    """指针逃逸记录"""
    ptr_register: str              # 逃逸时的寄存器
    escape_addr: int               # 逃逸发生的地址
    escape_type: str               # 'return' | 'global_store' | 'arg_pass'
    target_function: str = ''      # 逃逸到的函数 (arg_pass) 或 '' (return/global)

class CrossFunctionUAFDetector(UAFDetector):
    """跨函数UAF检测 — 在函数内检测基础上增加跨函数指针追踪

    场景: 函数A分配堆指针, 传递给函数B, B中free, A中继续使用
    当前 uaf_detector.py 看不到B中的free→报告漏报
    本模块通过调用图传播指针liveness信息

    方法:
      1. 在每函数内识别"指针逃逸点": return ptr / store global / pass as arg
      2. 沿调用图传播逃逸信息: 若callee free了逃逸指针, 标记caller中的后续use
      3. 对逃逸指针在caller中free之后的引用→UAF
    """

    def detect_cross_function(
        self,
        functions: Dict[str, List[Tuple[int, str]]],
        call_graph: Dict[str, List[str]],
    ) -> List[UAFFinding]:
        """跨函数UAF检测

        functions: {func_name: [(addr, asm_text)]}
        call_graph: {caller: [callee]}

        返回: 跨函数UAF发现列表
        """
        findings: List[UAFFinding] = []

        for caller, callees in call_graph.items():
            if caller not in functions:
                continue
            caller_asm = functions[caller]

            # 分析caller: 找指针逃逸点 (传递给callee的参数)
            escapes = self._find_pointer_escapes(caller_asm, callees)

            for esc in escapes:
                if esc.escape_type != 'arg_pass':
                    continue
                callee = esc.target_function
                if callee not in functions:
                    continue

                # 分析callee: 是否free了该指针
                callee_asm = functions[callee]
                freed_in_callee = self._does_callee_free(callee_asm, esc.ptr_register)

                if not freed_in_callee:
                    continue

                # callee free了指针 → 扫描caller中call callee之后的引用
                call_idx = next((i for i, (a, _) in enumerate(caller_asm)
                                 if a > esc.escape_addr), len(caller_asm))
                if call_idx >= len(caller_asm):
                    continue
                # 追踪的寄存器: esc.ptr_register 是源 (rax), 但use可能在目标 (rdi) 中
                # 因为 mov rdi, rax 将ptr从rax传到了rdi
                track_regs = {esc.ptr_register}
                for (a, t) in caller_asm:
                    if a == esc.escape_addr:
                        parts = t.lower().strip().split(None, 1)
                        ops = parts[1] if len(parts) > 1 else ''
                        dest = ops.split(',')[0].strip()
                        if dest in ('rdi', 'edi', 'rsi', 'esi', 'rdx', 'edx', 'rcx', 'ecx'):
                            track_regs.add(dest)
                        break
                # 从call callee之后扫描对任一追踪寄存器的引用
                for reg in track_regs:
                    use_addr, use_text, _ = self._scan_post_free_use(
                        reg, caller_asm, call_idx - 1, caller_asm[call_idx - 1][0],
                    )
                    if use_addr >= 0:
                        break
                if use_addr >= 0:
                    findings.append(UAFFinding(
                        function_name=f'{caller}->{callee}',
                        malloc_addr=esc.escape_addr,
                        free_addr=esc.escape_addr,  # 实际free在callee中
                        use_addr=use_addr,
                        pointer_reg=esc.ptr_register,
                        verdict=UAFVerdict.LIKELY,
                        confidence=0.65,
                        use_insn_text=use_text,
                        evidence=[
                            f'pointer escaped from {caller} to {callee}',
                            f'freed in {callee}, used in {caller} @ 0x{use_addr:x}',
                        ],
                    ))

        return findings

    def _find_pointer_escapes(
        self, asm_lines: List[Tuple[int, str]], callees: List[str],
    ) -> List[PointerEscape]:
        """在caller中找传递给callee的指针"""
        escapes = []
        for addr, text in asm_lines:
            tlower = text.lower().strip()
            if 'call' not in tlower:
                continue
            for callee in callees:
                if callee not in tlower.replace(' ', ''):
                    continue
                # 找到call前对参数寄存器 (rdi/rsi) 的mov
                for i in range(len(asm_lines) - 1, -1, -1):
                    a, t = asm_lines[i]
                    if a >= addr: continue
                    parts = t.lower().strip().split(None, 1)
                    if not parts or parts[0] != 'mov': continue
                    ops = parts[1] if len(parts) > 1 else ''
                    dest = ops.split(',')[0].strip()
                    src = ops.split(',')[1].strip() if ',' in ops else ''
                    if dest in ('rdi', 'edi') and self._looks_like_heap_ptr(src):
                        escapes.append(PointerEscape(
                            ptr_register=src, escape_addr=a,
                            escape_type='arg_pass', target_function=callee,
                        ))
                    if addr - a > 30: break
        return escapes

    def _does_callee_free(
        self, asm_lines: List[Tuple[int, str]], ptr_reg: str,
    ) -> bool:
        """检查callee中是否free了指定寄存器的指针

        两种情况:
          a) free前有显式 mov rdi, ptr_reg → 直接匹配
          b) free前无rdi赋值 → rdi由调用者传入, 默认匹配
        """
        for addr, text in asm_lines:
            if not self._is_free_call(text):
                continue
            has_explicit_mov = False
            for i in range(len(asm_lines) - 1, -1, -1):
                a, t = asm_lines[i]
                if a >= addr: continue
                parts = t.lower().strip().split(None, 1)
                if not parts: continue
                if parts[0] != 'mov':
                    if addr - a > 20: break
                    continue
                ops = parts[1] if len(parts) > 1 else ''
                dest = ops.split(',')[0].strip()
                src = ops.split(',')[1].strip() if ',' in ops else ''
                if dest in ('rdi', 'edi'):
                    has_explicit_mov = True
                    if src == ptr_reg:
                        return True
                    break  # rdi被覆写为其他值→ptr_reg不在rdi中
                if addr - a > 20: break
            # 无显式rdi赋值→rdi保持调用者传入的值→匹配
            if not has_explicit_mov:
                return True
        return False

    def _is_free_call(self, text: str) -> bool:
        t = text.lower().replace(' ', '')
        return 'call' in t and 'free' in t

    @staticmethod
    def _looks_like_heap_ptr(reg: str) -> bool:
        """寄存器名是否像堆指针 (排除 rsp/rbp/立即数)"""
        import re
        return bool(re.match(r'^(r(?:ax|bx|cx|dx|si|di|8|9|1[0-5])|e(?:ax|bx|cx|dx|si|di))$', reg))
