# 初始创建: 从评分升级为路径敏感的UAF检测
# 指针别名追踪: 在free后扫描函数内是否仍引用已释放指针

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class UAFVerdict(Enum):
    CONFIRMED = "confirmed"         # free后必然use
    LIKELY = "likely"               # free后特定分支use
    POSSIBLE = "possible"           # 指针可能逃逸, 无法确认
    NOT_DETECTED = "not_detected"   # 未发现use after free


@dataclass
class UAFFinding:
    function_name: str
    malloc_addr: int
    free_addr: int
    use_addr: int                   # free后use的地址, -1=未找到
    pointer_reg: str                # 持有堆指针的寄存器
    verdict: UAFVerdict
    confidence: float
    use_insn_text: str = ''         # free后use的指令
    evidence: List[str] = field(default_factory=list)


# 识别"使用堆指针"的指令模式
_USE_PATTERNS = re.compile(
    r'(?:mov|add|sub|cmp|test|lea)\s+[^,]*\[?(\w+)\]?'
    r'|call\s+\[(\w+)\]',
    re.I,
)


class UAFDetector:
    """路径敏感的 UAF 检测器

    用法:
      detector = UAFDetector()
      findings = detector.detect(
          functions={'main': [(0x401000, 'call malloc'), ...]},
          heap_ops=[HeapOperation('malloc', 0x401000, 64, 'rax'), ...],
      )
    """

    def detect(
        self,
        functions: Dict[str, List[Tuple[int, str]]],
        heap_ops: Optional[List] = None,
    ) -> List[UAFFinding]:
        """检测所有函数中的 UAF

        heap_ops: 可选, 来自 uaf_candidate_scorer 的预筛选结果
                  格式: HeapOperation 列表

        返回: 按置信度降序排列的检测结果
        """
        findings: List[UAFFinding] = []

        for func_name, asm_lines in functions.items():
            findings.extend(self._detect_in_function(func_name, asm_lines))

        return sorted(findings, key=lambda f: -f.confidence)

    def _detect_in_function(
        self, func_name: str,
        asm_lines: List[Tuple[int, str]],
    ) -> List[UAFFinding]:
        """单函数内检测"""
        findings: List[UAFFinding] = []
        allocs: List[Tuple[int, str, int]] = []  # (addr, reg, size_hint)

        for i, (addr, text) in enumerate(asm_lines):
            text_lower = text.lower().strip()

            # 记录 malloc
            alloc_reg = self._match_alloc_return(text_lower)
            if alloc_reg:
                allocs.append((addr, alloc_reg, -1))

            # 检测 free
            freed_reg = self._match_free_arg(text_lower)
            if freed_reg and allocs:
                # 找最近匹配的 alloc
                matching_alloc = self._find_matching_alloc(
                    allocs, freed_reg, asm_lines, addr,
                )
                if matching_alloc is None:
                    continue

                a_addr, a_reg, _ = matching_alloc

                # 扫描 free 之后的指令, 查找对同一指针的引用
                use_addr, use_text, path_cond = self._scan_post_free_use(
                    freed_reg, asm_lines, i, addr,
                )

                if use_addr >= 0:
                    verdict = UAFVerdict.CONFIRMED if not path_cond else UAFVerdict.LIKELY
                    conf = 0.85 if not path_cond else 0.60
                    use_str = use_text
                else:
                    # 检查指针是否逃逸 (存储到全局/返回)
                    escaped = self._check_pointer_escape(
                        freed_reg, asm_lines, a_addr, addr,
                    )
                    if escaped:
                        verdict = UAFVerdict.POSSIBLE
                        conf = 0.35
                        use_str = 'pointer escaped to caller/global'
                    else:
                        verdict = UAFVerdict.NOT_DETECTED
                        conf = 0.10
                        use_str = ''

                findings.append(UAFFinding(
                    function_name=func_name,
                    malloc_addr=a_addr,
                    free_addr=addr,
                    use_addr=use_addr,
                    pointer_reg=freed_reg,
                    verdict=verdict,
                    confidence=conf,
                    use_insn_text=use_str,
                    evidence=[
                        f'malloc @ 0x{a_addr:x}',
                        f'free @ 0x{addr:x}',
                    ] + ([f'use @ 0x{use_addr:x}: {use_str}'] if use_addr >= 0 else []),
                ))

        return findings

    def _match_alloc_return(self, text: str) -> str:
        """匹配 malloc 调用, 返回持有返回值的寄存器"""
        if 'call' not in text:
            return ''
        for alloc in ('malloc', 'calloc', '__libc_malloc'):
            if alloc in text.replace(' ', ''):
                return 'rax'
        return ''

    def _match_free_arg(self, text: str) -> str:
        """匹配 free 调用, 返回被释放的指针所在寄存器"""
        if 'call' not in text or 'free' not in text.replace(' ', ''):
            return ''
        # free 的参数在 rdi 中
        return 'rdi'

    def _find_matching_alloc(
        self,
        allocs: List[Tuple[int, str, int]],
        freed_reg: str,
        asm_lines: List[Tuple[int, str]],
        free_addr: int,
    ) -> Optional[Tuple[int, str, int]]:
        """找与 free 配对的 malloc

        条件: alloc 的返回寄存器 (rax) 被移动到 free 的参数寄存器 (rdi)
        """
        for a_addr, a_reg, a_size in reversed(allocs):
            if a_addr >= free_addr:
                continue
            # 检查 alloc 和 free 之间是否有 mov freed_reg, rax
            if self._reg_transfer_exists(asm_lines, 'rax', freed_reg, a_addr, free_addr):
                return (a_addr, a_reg, a_size)
            # 直接匹配: freed_reg == rax (分配后rax未变)
            if freed_reg == 'rax':
                return (a_addr, a_reg, a_size)
        return allocs[-1] if allocs else None  # fallback: 最近的一个alloc

    def _reg_transfer_exists(
        self, asm_lines: List[Tuple[int, str]],
        src_reg: str, dst_reg: str,
        start_addr: int, end_addr: int,
    ) -> bool:
        """检查地址范围内是否存在 mov dst_reg, src_reg"""
        for addr, text in asm_lines:
            if not (start_addr < addr < end_addr):
                continue
            parts = text.lower().strip().split(None, 1)
            if not parts or parts[0] != 'mov':
                continue
            ops = parts[1] if len(parts) > 1 else ''
            dest = ops.split(',')[0].strip()
            src = ops.split(',')[1].strip() if ',' in ops else ''
            if dest == dst_reg and src == src_reg:
                return True
        return False

    def _scan_post_free_use(
        self,
        freed_reg: str,
        asm_lines: List[Tuple[int, str]],
        free_idx: int,
        free_addr: int,
    ) -> Tuple[int, str, bool]:
        """扫描 free 之后的指令, 查找对该指针的引用

        返回: (use_address, use_instruction_text, is_path_conditional)

        is_path_conditional: 若引用在条件分支内→True (仅在特定路径上触发)
        """
        in_conditional = False
        for j in range(free_idx + 1, len(asm_lines)):
            addr, text = asm_lines[j]
            text_lower = text.lower().strip()
            parts = text_lower.split(None, 1)
            mnemonic = parts[0] if parts else ''

            # 追踪条件分支
            if mnemonic.startswith('j') and mnemonic not in ('jmp',):
                in_conditional = True
            if mnemonic == 'ret':
                break

            # 跳转/调用指令不直接"使用"指针 - 检查操作数
            if mnemonic in ('jmp', 'call', 'ret', 'nop'):
                continue

            # 检查是否引用了已释放的指针寄存器
            ops = parts[1] if len(parts) > 1 else ''
            if freed_reg in ops or freed_reg == ops.strip():
                return (addr, text, in_conditional)

            # 检查是否通过内存引用 (如 [rax+8])
            if f'[{freed_reg}' in ops or f'[{freed_reg}+' in ops:
                return (addr, text, in_conditional)

        return (-1, '', False)

    def _check_pointer_escape(
        self, ptr_reg: str,
        asm_lines: List[Tuple[int, str]],
        alloc_addr: int, free_addr: int,
    ) -> bool:
        """检查指针是否在 free 前逃逸: 存储到内存/传递给其他函数/返回

        逃逸后本模块无法追踪→标记为 POSSIBLE
        """
        for addr, text in asm_lines:
            if not (alloc_addr < addr < free_addr):
                continue
            text_lower = text.lower().strip()
            parts = text_lower.split(None, 1)
            mnemonic = parts[0] if parts else ''
            ops = parts[1] if len(parts) > 1 else ''

            # 存储到内存: mov [mem], ptr_reg
            if mnemonic == 'mov' and f'[{ops.split(",")[0].strip()}]' in ops.replace(' ', ''):
                if ptr_reg in ops:
                    return True
            # 传递给函数: 作为参数寄存器
            if mnemonic == 'mov' and ops.startswith(('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')):
                if ptr_reg in ops:
                    return True
            # 返回给调用者: mov rax, ptr_reg
            if mnemonic == 'mov' and 'rax' in ops and ptr_reg in ops:
                if addr < free_addr:
                    return True

        return False
