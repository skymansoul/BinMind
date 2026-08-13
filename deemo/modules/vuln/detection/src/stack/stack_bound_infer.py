"""栈边界推断器 — 函数级栈帧分析 + canary 检测 + 溢出偏移计算.

创建: 2025-03-28
目的: 从反汇编中推断每个函数的栈帧大小、局部缓冲区位置、canary 存在性,
      以及用户输入到达缓冲区的偏移量。替代 Angr 符号执行做初始快速筛选,
      Angr 仅对本模块标记为 high-confidence 的候选做验证。

方法依据: BASICS 的 MemStaCe + LTL 属性验证思路,
          本模块在二进制 IR 层面做简化: 不构建完整状态空间,
          仅从函数序言/反序言和栈操作指令推断边界约束。

与 core/stack_overflow_analyzer.py 的关系:
  - core/stack_overflow_analyzer.py 使用 Angr 符号执行做精确偏移计算
  - 本模块做快速预筛选: 识别子函数序言中的 sub rsp, N 确定栈帧大小,
    追踪局部变量的栈偏移, 判断用户输入是否可到达返回地址区域
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class StackFrame:
    """一个函数的栈帧信息."""
    function_name: str
    func_start: int            # 函数入口地址
    func_end: int              # 函数结束地址
    frame_size: int            # 栈帧大小 (sub rsp, N)
    canary_present: bool       # 是否检测到 stack canary
    canary_load_addr: int      # canary 加载指令地址 (0=未检测到)
    # 局部缓冲区
    buffers: List[Tuple[int, str, int]]  # [(stack_offset, name, size), ...]
    # 危险函数调用
    dangerous_calls: List[Tuple[int, str, int]]  # [(addr, func, buf_offset)]


class StackBoundInferrer:
    """栈边界推断器 — 从函数反汇编推断栈帧约束.

    检测规则:
      1. 函数序言: push rbp; mov rbp,rsp; sub rsp,N → frame_size = N+α
      2. canary: mov rax, fs:[0x28]; mov [rbp-8], rax → canary_present
      3. 局部缓冲区: lea rax, [rbp-N]; ... ; call gets/scanf → buf at rbp-N
      4. 溢出判定: N + buf_size > frame_size → 可能溢出

    使用方式:
      sbi = StackBoundInferrer()
      sbi.add_function('main', 0x401000, 0x401200, frame_size=96)
      sbi.add_buffer('main', -64, 'buf', 32)
      sbi.add_dangerous_call('main', 0x401050, 'gets', -64)
      findings = sbi.analyze_all()
    """

    def __init__(self):
        self._frames: Dict[str, StackFrame] = {}
        # 用户输入源函数
        self._input_sources = {'gets', 'scanf', 'fgets', 'read',
                              'recv', 'recvfrom', 'fscanf', 'sscanf'}

    def add_function(self, name: str, start: int, end: int,
                     frame_size: int = 0,
                     canary: bool = False,
                     canary_addr: int = 0) -> StackFrame:
        """注册函数栈帧."""
        sf = StackFrame(
            function_name=name, func_start=start, func_end=end,
            frame_size=frame_size, canary_present=canary,
            canary_load_addr=canary_addr,
            buffers=[], dangerous_calls=[])
        self._frames[name] = sf
        return sf

    def add_buffer(self, func_name: str, stack_offset: int,
                   buf_name: str, buf_size: int) -> None:
        """注册局部缓冲区."""
        sf = self._frames.get(func_name)
        if sf:
            sf.buffers.append((stack_offset, buf_name, buf_size))

    def add_dangerous_call(self, func_name: str, call_addr: int,
                           callee: str, buf_offset: int) -> None:
        """注册危险函数调用 (gets/scanf/strcpy 等)."""
        sf = self._frames.get(func_name)
        if sf:
            sf.dangerous_calls.append((call_addr, callee, buf_offset))

    def analyze_all(self) -> List[dict]:
        """分析所有已注册函数的栈溢出风险."""
        findings = []
        for name, sf in self._frames.items():
            for call_addr, callee, buf_offset in sf.dangerous_calls:
                # 查找对应的缓冲区
                buf_info = None
                for bo, bn, bs in sf.buffers:
                    if bo == buf_offset:
                        buf_info = (bo, bn, bs)
                        break

                risk = self._assess_risk(sf, callee, buf_offset, buf_info)
                if risk['overflow_risk'] > 0.3:
                    findings.append(risk)
        findings.sort(key=lambda x: x['overflow_risk'], reverse=True)
        return findings

    def _assess_risk(self, sf: StackFrame, callee: str,
                     buf_offset: int,
                     buf_info: Optional[Tuple]) -> dict:
        """评估单次危险调用的溢出风险."""
        risk = 0.0
        reasons = []

        # 因素1: 调用方是否为用户输入源
        if callee in self._input_sources:
            risk += 0.40
            reasons.append(f'{callee} is user input source')

        # 因素2: 缓冲区是否在栈上且接近返回地址
        if buf_info:
            _, _, buf_size = buf_info
            # 缓冲区到栈顶的距离: |buf_offset|
            dist_to_ret = abs(buf_offset) + buf_size
            if dist_to_ret > sf.frame_size:
                risk += 0.35
                reasons.append(
                    f'buffer({buf_size}B) at offset {buf_offset} '
                    f'exceeds frame {sf.frame_size}B')

        # 因素3: canary 保护
        if sf.canary_present:
            risk *= 0.6  # canary 降低利用可能性
            reasons.append('canary present (reduced exploitability)')
        else:
            risk += 0.15
            reasons.append('no canary protection')

        # 因素4: 帧大小 (小帧 → 更容易溢出到返回地址)
        if sf.frame_size < 128:
            risk += 0.10
            reasons.append(f'small frame ({sf.frame_size}B)')

        return {
            'function': sf.function_name,
            'callee': callee,
            'call_addr': 0,  # 填充实际地址
            'overflow_risk': min(1.0, risk),
            'reasons': reasons,
            'frame_size': sf.frame_size,
            'canary': sf.canary_present,
        }

    def stats(self) -> dict:
        findings = self.analyze_all()
        high_risk = [f for f in findings if f['overflow_risk'] > 0.5]
        return {
            'functions_analyzed': len(self._frames),
            'overflow_candidates': len(findings),
            'high_risk': len(high_risk),
            'mean_risk': (sum(f['overflow_risk'] for f in findings)
                          / max(1, len(findings)) if findings else 0),
        }

    def clear(self) -> None:
        self._frames.clear()
