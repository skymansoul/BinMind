"""
自动补丁原理解释器 (Automated Patch Rationale Generator, APRG)
--------------------------------------------------------------
从二进制补丁的字节级差异自动生成人类可读的修复解释.

设计依据:
  安全补丁分析中, 分析师需要理解"补丁做了什么"和"为什么这样修复".
  现有工具 (BinDiff, Diaphora) 显示差异但仅给出字节/指令级对比,
  不提供语义解释. VeriBin (NDSS 2025) 判定安全性但不解释原理.

  APRG 将补丁差异映射为可解释的修复模式:
    1. 模式匹配: 将差异指令序列匹配到已知修复模式
       (边界检查插入 / 整数溢出保护 / UAF 指针清零 / 格式化串修复)
    2. 差异分类: 识别修改类型 (add_check / replace_call / insert_nop)
    3. 模板填充: 用具体地址/值实例化解释模板
    4. 输出: 自然语言解释 + 修复模式标签

 修复模式库 (可扩展):
    - BOUNDS_CHECK: 在 memcpy/strcpy 前插入 size 比较
    - INT_OVERFLOW: 乘法前插入溢出检查
    - UAF_NULLIFY: free 后指针清零
    - FORMAT_FIX: %s → %.100s 或 %n 移除
    - STACK_GUARD: 栈缓冲区增加 canary 检查
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class PatchExplanation:
    """补丁解释."""
    pattern_type: str         # 修复模式标签
    severity: str             # 'critical' | 'high' | 'medium' | 'low'
    summary: str              # 一句话摘要
    details: List[str] = field(default_factory=list)
    affected_addresses: List[str] = field(default_factory=list)
    confidence: float = 0.0   # 模式匹配置信度


# 修复模式 → (指令序列特征, 严重性, 解释模板)
_FIX_PATTERNS = [
    {
        'type': 'BOUNDS_CHECK',
        'severity': 'critical',
        'indicators': ['cmp', 'jg', 'jge', 'jb', 'jbe', 'call'],
        'template': (
            '在 {func} 调用前插入边界检查: 若 size > {limit}, '
            '则跳转到错误处理路径, 防止缓冲区溢出'
        ),
    },
    {
        'type': 'INT_OVERFLOW_GUARD',
        'severity': 'critical',
        'indicators': ['imul', 'mul', 'jo', 'jno', 'cmp', '0x7FFFFFFF'],
        'template': (
            '在乘法/加法操作后插入溢出检测 (检查 OF 标志位), '
            '防止整数溢出导致的内存分配不足'
        ),
    },
    {
        'type': 'UAF_NULLIFY',
        'severity': 'high',
        'indicators': ['mov', '0x0', 'call', 'free'],
        'template': (
            '在 free() 调用后将指针置零, 防止 use-after-free 重用悬挂指针. '
            '修改位于 {addr}'
        ),
    },
    {
        'type': 'FORMAT_STRING_FIX',
        'severity': 'high',
        'indicators': ['%s', '%.', 'push', 'call', 'printf'],
        'template': (
            '格式化字符串修复: 限制 %s 格式符的宽度或移除 %n, '
            '防止格式化字符串漏洞的信息泄露或任意写入'
        ),
    },
    {
        'type': 'STACK_GUARD_INSERT',
        'severity': 'medium',
        'indicators': ['fs:', 'gs:', 'mov', 'xor', '__stack_chk'],
        'template': (
            '插入栈 canary 检查: 函数返回前验证栈保护值, '
            '检测栈缓冲区溢出攻击'
        ),
    },
    {
        'type': 'REPLACE_DANGEROUS_CALL',
        'severity': 'critical',
        'indicators': ['strcpy', 'strncpy', 'sprintf', 'snprintf',
                       'gets', 'fgets', 'memcpy', 'memmove'],
        'template': (
            '将危险函数 {old_func} 替换为安全版本 {new_func}, '
            '增加目标缓冲区大小参数'
        ),
    },
]


class PatchRationaleGenerator:
    """自动补丁原理解释器.

    用法:
      prg = PatchRationaleGenerator()
      explanations = prg.explain(diff_instructions)
      for exp in explanations:
          print(f'[{exp.pattern_type}] {exp.summary}')
    """

    def __init__(self):
        self._patterns = _FIX_PATTERNS

    def explain(self, diff_instructions: List[str],
                context: Optional[Dict[str, Any]] = None
                ) -> List[PatchExplanation]:
        """从差异指令序列生成补丁解释."""
        context = context or {}
        explanations = []

        for pattern in self._patterns:
            score = self._match_pattern(diff_instructions, pattern['indicators'])
            if score < 0.25:
                continue

            # 模板填充
            summary = pattern['template'].format(
                func=context.get('vuln_function', '未知函数'),
                limit=context.get('buffer_size', '未知'),
                addr=', '.join(context.get('affected_addrs', ['未知地址'])),
                old_func=context.get('old_func', '未知'),
                new_func=context.get('new_func', '安全替代'),
            )

            details = self._extract_details(diff_instructions, pattern['type'])
            explanations.append(PatchExplanation(
                pattern_type=pattern['type'],
                severity=pattern['severity'],
                summary=summary,
                details=details,
                affected_addresses=context.get('affected_addrs', []),
                confidence=round(score, 3),
            ))

        explanations.sort(key=lambda e: e.confidence, reverse=True)
        return explanations

    def _match_pattern(self, instructions: List[str],
                       indicators: List[str]) -> float:
        """计算指令序列与模式指示符的匹配得分."""
        text = ' '.join(instructions).lower()
        hits = sum(1 for ind in indicators if ind.lower() in text)
        # 加权: 每命中一个指示符得 1/len(indicators) 分
        return hits / len(indicators) if indicators else 0.0

    def _extract_details(self, instructions: List[str],
                         pattern_type: str) -> List[str]:
        """从指令序列中提取具体细节."""
        details = []
        if pattern_type == 'BOUNDS_CHECK':
            for inst in instructions:
                if 'cmp' in inst:
                    details.append(f'比较指令: {inst.strip()}')
                if 'call' in inst and any(
                    f in inst for f in ('memcpy', 'strcpy', 'read', 'recv')
                ):
                    details.append(f'受保护的调用: {inst.strip()}')
        elif pattern_type == 'REPLACE_DANGEROUS_CALL':
            for inst in instructions:
                if 'call' in inst:
                    details.append(f'函数调用: {inst.strip()}')
        elif pattern_type == 'UAF_NULLIFY':
            for inst in instructions:
                if '0x0' in inst or 'xor' in inst.lower():
                    details.append(f'清零操作: {inst.strip()}')
        if not details:
            details.append('(无法提取具体细节, 基于模式匹配推断)')
        return details[:5]

    def generate_report(self, explanations: List[PatchExplanation]) -> str:
        """生成 Markdown 格式的解释报告."""
        if not explanations:
            return '未检测到已知修复模式. 补丁可能包含自定义修改.'

        lines = ['## 补丁原理分析', '']
        for i, exp in enumerate(explanations, 1):
            lines.append(f'### {i}. [{exp.pattern_type}] {exp.severity.upper()}')
            lines.append(f'**置信度**: {exp.confidence:.1%}')
            lines.append(f'**摘要**: {exp.summary}')
            lines.append('')
            if exp.details:
                lines.append('**细节**:')
                for d in exp.details:
                    lines.append(f'  - {d}')
                lines.append('')
        lines.append(f'*共检测到 {len(explanations)} 种修复模式*')
        return '\n'.join(lines)

    def add_pattern(self, pattern_def: Dict[str, Any]):
        """注册自定义修复模式."""
        self._patterns.append(pattern_def)
