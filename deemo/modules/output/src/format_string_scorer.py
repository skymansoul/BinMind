"""
格式化字符串漏洞精度评分 — 偏移量×%n可用性×栈布局可预测性。

问题定义:
  格式化字符串漏洞被报告为二值 (存在/不存在)，但实际利用难度
  差异极大:
    - printf(user_input): 格式串在栈上 0 偏移 → 直观利用
    - sprintf(buf, "%s:" + user_input): 格式串偏移 2-3 → 中等难度
    - fprintf(stderr, user_input): 仅写入 stderr → 低危 (通常)

  本模块提供第一个格式串漏洞精度评分模型，量化以下利用要素:
    1. 格式串偏移 — 攻击者控制的格式串距 printf 栈帧的距离
    2. %n 可用性 — 能否使用 %n 写入任意地址
    3. 宽度/精度控制 — 能否通过 %9999d 实现逐字节写入
    4. 输出可见性 — 攻击者能否看到格式化输出 (信息泄露)
    5. 栈布局 — 栈上是否存在可利用的指针链

参考:
  scut / team teso (2000): 经典格式串利用技术
  CTF 格式串挑战: 现代利用链模式 (2024-2025)
  无现有评分工具 — 现有扫描器仅做二值检测.

修改记录:
  2026-08-02 08:42 - 初始版本，五维格式串利用评分
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FormatStringContext(Enum):
    PRINTF_DIRECT = "printf_direct"      # printf(user_input)
    SPRINTF_BUFFER = "sprintf_buffer"    # sprintf(buf, fmt, ...) where fmt controlled
    FPRINTF_STDERR = "fprintf_stderr"    # fprintf(stderr, user_input)
    SNPRINTF = "snprintf"               # snprintf with controlled format
    SYSLOG = "syslog"                   # syslog(LOG_ERR, user_input)
    UNKNOWN = "unknown"


@dataclass
class FormatStringScore:
    """格式串漏洞精度评分。"""
    context: FormatStringContext
    stack_offset: int              # 格式串在栈上的参数偏移
    pct_n_usable: bool             # %n 是否可用
    width_control: bool            # 能否控制宽度/精度字段
    output_visible: bool           # 攻击者能否看到输出
    stack_pointer_chain: bool      # 栈上是否有可利用的指针链
    exploitability: float          # 0-10
    primitives: List[str] = field(default_factory=list)
    technique: str = ''


def _context_from_call(
    function_name: str,
    arg_position: int = 0,
) -> FormatStringContext:
    """从调用函数名推断格式串上下文。"""
    fn = function_name.lower()
    if 'fprintf' in fn:
        if 'stderr' in fn or arg_position >= 2:
            return FormatStringContext.FPRINTF_STDERR
        return FormatStringContext.PRINTF_DIRECT
    if 'sprintf' in fn:
        return FormatStringContext.SPRINTF_BUFFER
    if 'snprintf' in fn:
        return FormatStringContext.SNPRINTF
    if 'syslog' in fn:
        return FormatStringContext.SYSLOG
    if 'printf' in fn:
        return FormatStringContext.PRINTF_DIRECT
    return FormatStringContext.UNKNOWN


def score_format_string(
    function_name: str = 'printf',
    arg_position: int = 0,
    stack_offset: int = 1,
    pct_n_usable: Optional[bool] = None,
    width_control: bool = True,
    output_visible: Optional[bool] = None,
    stack_has_useful_ptrs: bool = True,
) -> FormatStringScore:
    """
    评估格式串漏洞的利用精度。

    stack_offset: 格式串在 printf 参数栈上的位置。
      1 = 第一个参数 (最易利用), 4+ = 深层偏移 (利用难度增大)。

    %n 检测: 如果未知，基于函数上下文推断。
      fprintf(stderr, ...) → %n 写入 stderr 文件描述符 → 几乎无用。
    """
    ctx = _context_from_call(function_name, arg_position)

    # %n 可用性默认推断
    if pct_n_usable is None:
        if ctx in (FormatStringContext.FPRINTF_STDERR, FormatStringContext.SYSLOG):
            pct_n_usable = False
        else:
            pct_n_usable = True

    # 输出可见性默认推断
    if output_visible is None:
        output_visible = ctx != FormatStringContext.FPRINTF_STDERR

    # --- 评分 ---
    # 偏移惩罚: offset 1→满分, offset 6+→减半
    offset_penalty = max(0.3, 1.0 - stack_offset * 0.12)

    # %n 贡献
    n_score = 0.40 if pct_n_usable else 0.05

    # 宽度控制贡献
    w_score = 0.25 if width_control else 0.05

    # 输出可见性贡献
    v_score = 0.20 if output_visible else 0.05

    # 栈指针链贡献
    p_score = 0.15 if stack_has_useful_ptrs else 0.0

    raw = (n_score + w_score + v_score + p_score) * 10.0 * offset_penalty
    exploitability = round(max(0.0, min(10.0, raw)), 1)

    # 可用原语
    prims = []
    if pct_n_usable and exploitability >= 4.0:
        prims.append('arbitrary_write_%n')
    if width_control:
        prims.append('bytewise_write')
    if output_visible:
        prims.append('memory_disclosure')
    if stack_has_useful_ptrs and exploitability >= 3.0:
        prims.append('pointer_chain_traversal')

    # 利用技术推荐
    if exploitability >= 7.0:
        tech = ('直接 GOT 覆写 — 使用 %n 将目标地址写入 GOT 条目。'
                '需要: 目标地址在栈上可达 + %n 可用')
    elif exploitability >= 4.0:
        tech = ('逐字节写入 — 使用 %hhn 逐字节覆写目标地址。'
                '需要: 宽度控制 + 多次格式串调用或循环')
    elif exploitability >= 2.0:
        tech = '仅信息泄露 — 读取栈内容但无可靠写入原语'
    else:
        tech = '利用难度高 — 缺乏关键原语 (%n不可用 或 输出不可见)'

    return FormatStringScore(
        context=ctx,
        stack_offset=stack_offset,
        pct_n_usable=pct_n_usable,
        width_control=width_control,
        output_visible=output_visible,
        stack_pointer_chain=stack_has_useful_ptrs,
        exploitability=exploitability,
        primitives=prims,
        technique=tech,
    )
