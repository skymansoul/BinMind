# 过滤增强的堆溢出检测, 集成三层过滤器 (来源追踪+对齐归一化+安全检查)
# 本文件是 heap_overflow_detector.py 的过滤增强版本
# 直接调用 detect() 获得低误报率的检测结果

from typing import Dict, List, Optional, Tuple
from .heap_overflow_detector import (
    HeapOverflowDetector, HeapOverflowFinding, HeapOverflowVerdict, _HEAP_WRITERS,
)
from .heap_fp_filter import HeapFalsePositiveFilter, FilterVerdict

class FilteredHeapOverflowDetector(HeapOverflowDetector):
    """过滤增强的堆溢出检测器, 三层过滤大幅压低误报率

    用法与 HeapOverflowDetector 相同, 但 detect() 内部使用过滤器
    """

    def detect(
        self,
        functions: Dict[str, List[Tuple[int, str]]],
        call_graph: Optional[Dict[str, List[str]]] = None,
    ) -> List[HeapOverflowFinding]:
        findings: List[HeapOverflowFinding] = []

        for func_name, asm_lines in functions.items():
            filt = HeapFalsePositiveFilter()

            for addr, text in asm_lines:
                parts = text.strip().split(None, 1)
                mnemonic = parts[0] if parts else ''
                operands = parts[1] if len(parts) > 1 else ''
                filt.feed_instruction(addr, mnemonic, operands)
                # malloc 调用: 提取参数大小并更新过滤器
                if mnemonic == 'call' and any(
                    a in operands.lower().replace(' ', '')
                    for a in ('malloc', 'calloc', '__libc_malloc')
                ):
                    sz = self._extract_const_arg(text, asm_lines, addr, 0)
                    if sz > 0:
                        filt.track_alloc_with_size(addr, sz)

            for addr, text in asm_lines:
                tlower = text.lower().strip()
                if 'call' not in tlower:
                    continue
                for wfunc, (dst_idx, size_idx) in _HEAP_WRITERS.items():
                    if wfunc not in tlower.replace(' ', ''):
                        continue
                    write_sz = self._extract_const_arg(text, asm_lines, addr, size_idx)
                    dst_reg = self._extract_arg_reg(asm_lines, addr, dst_idx)
                    if write_sz < 0 or not dst_reg:
                        continue

                    asm_ctx = '\n'.join(
                        t for _, t in asm_lines[
                            max(0, next((i for i, (a, _) in enumerate(asm_lines) if a == addr), 0) - 5):
                        ]
                    )
                    ff = filt.check_write(addr, write_sz, dst_reg, asm_ctx)

                    if ff.verdict == FilterVerdict.CONFIRMED:
                        findings.append(HeapOverflowFinding(
                            function_name=func_name, alloc_address=ff.alloc_addr,
                            write_address=addr, alloc_size=ff.alloc_size,
                            write_size=ff.write_size, verdict=HeapOverflowVerdict.CONFIRMED,
                            confidence=ff.confidence,
                            evidence=[ff.reason, f'effective_alloc={ff.effective_alloc}'],
                        ))
                    elif ff.verdict not in (
                        FilterVerdict.FILTERED_ALIGNMENT,
                        FilterVerdict.FILTERED_PROVENANCE,
                        FilterVerdict.FILTERED_SAFETY,
                    ):
                        findings.append(HeapOverflowFinding(
                            function_name=func_name, alloc_address=ff.alloc_addr,
                            write_address=addr, alloc_size=ff.alloc_size,
                            write_size=ff.write_size, verdict=HeapOverflowVerdict.POTENTIAL,
                            confidence=ff.confidence, evidence=[ff.reason],
                        ))

        return sorted(findings, key=lambda f: -f.confidence)
