# 格式字符串尺寸感知过滤 — snprintf有边界保护, sprintf无
# 区分这两类调用可进一步降低误报: 安全的snprintf调用不应标记为漏洞
# 即便格式参数可控, 有size参数的snprintf仍是受控的

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

class SizeAwareVerdict(Enum):
    DANGEROUS = "dangerous"          # printf/sprintf — 无size限制
    SIZE_PROTECTED = "size_protected" # snprintf/vsnprintf — 有size参数
    PARTIALLY_PROTECTED = "partial"   # fprintf — 输出到FILE*, 有限制但非内存

# printf家族按危险性分类
_DANGEROUS_PRINTF = {'printf', 'sprintf', 'vprintf', 'vsprintf'}
_SIZE_PROTECTED = {'snprintf', 'vsnprintf', '__snprintf_chk', '__vsnprintf_chk'}
_PARTIAL = {'fprintf', 'vfprintf', 'dprintf', 'vdprintf'}

@dataclass
class SizeAwareResult:
    verdict: SizeAwareVerdict
    has_explicit_size: bool
    size_arg_possible: bool       # 能否静态提取size参数值
    estimated_size: int            # -1=未知
    risk_adjustment: float         # 对基础置信度的调整

class FmtSizeAwareFilter:
    """尺寸感知的格式字符串过滤 — snprintf(已知size)降低置信度

    设计依据:
      sprintf(user_input, ...) — 无条件危险
      snprintf(buf, 256, user_input, ...) — 受size保护, 降低风险
      fprintf(stderr, user_input, ...) — 输出到文件, 利用面不同
    """

    def analyze(
        self, callee: str, asm_context: List[Tuple[int, str]], call_addr: int,
    ) -> SizeAwareResult:
        """分析格式字符串调用的size保护"""
        # 精确匹配函数名 — 避免子字符串匹配 (printf匹配到snprintf)
        callee_clean = callee.lower().replace(' ', '').strip()

        size_arg = -1
        # 先检查SIZE_PROTECTED — snprintf必须在DANGEROUS之前检查
        is_protected = callee_clean in _SIZE_PROTECTED
        if is_protected:
            size_arg = self._extract_size_arg(asm_context, call_addr)

        if is_protected:
            return SizeAwareResult(
                verdict=SizeAwareVerdict.SIZE_PROTECTED,
                has_explicit_size=True, size_arg_possible=(size_arg > 0),
                estimated_size=size_arg, risk_adjustment=-0.25,
            )
        elif callee_clean in _DANGEROUS_PRINTF:
            return SizeAwareResult(
                verdict=SizeAwareVerdict.DANGEROUS,
                has_explicit_size=False, size_arg_possible=False,
                estimated_size=-1, risk_adjustment=0.0,
            )
        elif callee_clean in _PARTIAL:
            return SizeAwareResult(
                verdict=SizeAwareVerdict.PARTIALLY_PROTECTED,
                has_explicit_size=False, size_arg_possible=False,
                estimated_size=-1, risk_adjustment=-0.10,
            )
        else:
            return SizeAwareResult(
                verdict=SizeAwareVerdict.PARTIALLY_PROTECTED,
                has_explicit_size=False, size_arg_possible=False,
                estimated_size=-1, risk_adjustment=-0.10,
            )

    def _extract_size_arg(
        self, asm_lines: List[Tuple[int, str]], call_addr: int,
    ) -> int:
        """提取snprintf的size参数 (x86_64: rsi = 第二个参数)"""
        for addr, text in reversed(asm_lines):
            if addr >= call_addr: continue
            parts = text.lower().strip().split(None, 1)
            if not parts or parts[0] not in ('mov', 'lea'): continue
            ops = parts[1] if len(parts) > 1 else ''
            dest = ops.split(',')[0].strip() if ',' in ops else ''
            if dest not in ('rsi', 'esi', 'sil'): continue
            src = ops.split(',')[1].strip() if ',' in ops else ''
            try: return int(src, 0)
            except ValueError: return -1
        return -1
