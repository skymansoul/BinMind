"""PcWBI-IRL: 内联复制加载建模.

与原 PcWBI 的本质区别:
  原 PcWBI 不建模编译器内联复制 (rep movs / SSE 存储), 来源追踪遇 call 即终止.
  PcWBI-IRL 解析 rep movs 和 movdqa 指令的块拷贝语义,
  将内联展开的 memcpy 识别为结构化复制操作并追踪 count 来源.
"""
import re
from collections import namedtuple
from typing import Dict, List, Optional, Tuple


InlineCopyRecord = namedtuple(
    'InlineCopyRecord',
    ['kind', 'count_expr', 'dst_expr', 'src_expr', 'line_number'],
)


class InlineRepLoadModeler:
    """内联复制加载建模器, 解析 rep movs / movdqa 块拷贝语义."""

    # rep movs 伪代码模式: while(n--) *dst++ = *src++
    _REP_MOVS_PSEUDO = re.compile(
        r'while\s*\(\s*(\w+)\s*--\s*\)\s*\*?(\w+)\+?\+?\s*=\s*\*?(\w+)\+?\+?',
        re.IGNORECASE,
    )
    # for 循环内联拷贝: for(i=0;i<n;i++) dst[i]=src[i]
    _FOR_COPY_PSEUDO = re.compile(
        r'for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;\s*\1\s*\+\+\s*\)'
        r'\s*(\w+)\s*\[\s*\1\s*\]\s*=\s*(\w+)\s*\[\s*\1\s*\]',
        re.IGNORECASE,
    )
    # rep movs 汇编: rep movs %rcx,%rdi,%rsi 或 rep movsq
    _REP_MOVS_ASM = re.compile(
        r'rep\s+movs[bwdq]?\s*(?:%(\w+),\s*%(\w+),\s*%(\w+))?',
        re.IGNORECASE,
    )
    # SSE 展开: 连续 movdqa/movdqu 序列
    _SSE_STORE_ASM = re.compile(
        r'movd[qau]?\s+(?:%xmm\d+|xmm\d+)\s*,\s*(?:%(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+))',
        re.IGNORECASE,
    )

    def __init__(self):
        self._copies: List[InlineCopyRecord] = []
        self._sse_count = 0

    def detect_inline_copy(self, instructions: list) -> List[InlineCopyRecord]:
        """从指令列表中检测内联复制模式."""
        results = []
        sse_streak = 0
        sse_base_reg = None
        sse_start_line = 0

        for idx, raw in enumerate(instructions):
            line = raw.strip() if isinstance(raw, str) else str(raw).strip()

            # 检测 rep movs
            m = self._REP_MOVS_ASM.search(line)
            if m:
                count_reg = m.group(1) or 'rcx'
                dst_reg = m.group(2) or 'rdi'
                src_reg = m.group(3) or 'rsi'
                results.append(InlineCopyRecord(
                    kind='rep_movs',
                    count_expr=count_reg,
                    dst_expr=dst_reg,
                    src_expr=src_reg,
                    line_number=idx,
                ))
                continue

            # 检测 SSE 存储 (movdqa %xmm0, (%rdi+offset))
            m2 = self._SSE_STORE_ASM.search(line)
            if m2:
                base_reg = m2.group(1)
                if sse_base_reg is None:
                    sse_base_reg = base_reg
                    sse_start_line = idx
                if base_reg == sse_base_reg:
                    sse_streak += 1
                    continue
            else:
                # 非 SSE 指令, 检查是否结束了一个 streak
                if sse_streak >= 2:
                    # 2+ 连续 movdqa 到同一基址 = 展开 memcpy
                    results.append(InlineCopyRecord(
                        kind='sse_unroll',
                        count_expr=str(sse_streak * 16),
                        dst_expr=sse_base_reg or '',
                        src_expr='',
                        line_number=sse_start_line,
                    ))
                sse_streak = 0
                sse_base_reg = None

        # 处理末尾 streak
        if sse_streak >= 2:
            results.append(InlineCopyRecord(
                kind='sse_unroll',
                count_expr=str(sse_streak * 16),
                dst_expr=sse_base_reg or '',
                src_expr='',
                line_number=sse_start_line,
            ))

        self._copies = results
        return results

    def detect_pseudo_inline_copy(self, pseudocode: str) -> List[InlineCopyRecord]:
        """从伪代码中检测内联复制模式."""
        results = []
        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            # while(n--) *dst++ = *src++
            m = self._REP_MOVS_PSEUDO.search(line)
            if m:
                count_var = m.group(1)
                dst_var = m.group(2)
                src_var = m.group(3)
                results.append(InlineCopyRecord(
                    kind='rep_movs_pseudo',
                    count_expr=count_var,
                    dst_expr=dst_var,
                    src_expr=src_var,
                    line_number=lineno,
                ))
                continue
            # for(i=0;i<n;i++) dst[i]=src[i]
            m2 = self._FOR_COPY_PSEUDO.search(line)
            if m2:
                iter_var, count_var, dst_var, src_var = m2.groups()
                results.append(InlineCopyRecord(
                    kind='for_copy_pseudo',
                    count_expr=count_var,
                    dst_expr=dst_var,
                    src_expr=src_var,
                    line_number=lineno,
                ))

        self._copies = results
        return results

    def model_rep_movs(self, count_reg: str, dst_reg: str,
                       src_reg: str) -> dict:
        """建模 rep movs 语义: count_reg 控制 copy 大小."""
        return {
            'kind': 'rep_movs',
            'count_source': count_reg,
            'dst': dst_reg,
            'src': src_reg,
            'byte_count_expr': count_reg,
            'element_size': 1,
            'semantics': 'block_copy',
            'tainted': True,
        }

    def model_sse_store(self, xmm_reg: str, dst_reg: str,
                        offset: int) -> dict:
        """建模 movdqa 语义: 16 字节块存储."""
        return {
            'kind': 'sse_store',
            'xmm': xmm_reg,
            'dst': dst_reg,
            'offset': offset,
            'byte_count': 16,
            'semantics': 'vector_store',
            'tainted': True,
        }

    def enhance_findings(self, findings: list,
                         inline_copies: list) -> list:
        """用内联复制信息增强 findings.

        如果 finding 的写入函数被内联展开, 用内联复制的 count_expr
        替代原 write_size, 并标注 inline_copy 信息.
        """
        if not findings or not inline_copies:
            return findings

        for f in findings:
            desc = f.get('description', '')
            func = f.get('function', '')
            # 如果 finding 提到 memcpy/strcpy/memmove 且没有明确的 write_size
            if any(kw in desc.lower() or kw in func.lower()
                   for kw in ('memcpy', 'strcpy', 'memmove', 'inline')):
                for cp in inline_copies:
                    # 匹配 dst 或 src 变量名
                    if (cp.dst_expr and cp.dst_expr in desc) or \
                       (cp.src_expr and cp.src_expr in desc):
                        f['inline_copy'] = {
                            'kind': cp.kind,
                            'count_expr': cp.count_expr,
                            'dst': cp.dst_expr,
                            'src': cp.src_expr,
                            'line': cp.line_number,
                        }
                        # 用内联复制的 count 表达式替代 write_size
                        if not f.get('write_size'):
                            try:
                                f['write_size'] = int(cp.count_expr)
                            except (ValueError, TypeError):
                                f['write_size_expr'] = cp.count_expr
                        break
        return findings

    @property
    def copies(self) -> List[InlineCopyRecord]:
        return self._copies
