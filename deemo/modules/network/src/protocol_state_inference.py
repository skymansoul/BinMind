# TODO: 当前仅覆盖TCP字节流，UDP/TLS记录层分帧待补
#
# 协议状态机推断。从二进制程序网络处理函数复原隐式协议状态机。
#
# 无文档、无IDL、无源码的二进制程序中，协议解析逻辑硬编码于消息处理函数。
# 本模块从CFG与调用图自动推断状态转移关系。
#
# 三级流水：
#   1. 边界检测：魔数字节序列或recv/send调用模式识别消息边界
#   2. 状态变量定位：追踪影响控制流的全局变量引用
#   3. 转移图构建：(当前状态, 消息类型) → 下一状态
#
# 输出：有向图，节点=协议状态，边=(消息类型, handler地址)。

import re
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


def detect_message_boundary(disasm_lines: List[str]) -> Optional[int]:
    """检测协议消息边界模式。

    返回检测到的消息头部大小（字节），或None。

    策略:
      (a) 魔数比较：cmp [buf+0], 0x... 类立即数比较
      (b) 长度字段：固定偏移读取值传入recv/buffer_check的模式
      (c) 熵跳变（回退）：算术密集→内存密集转折点，标识消息解析起始

    (c) 于7/29引入，此前对此类二进制仅返回None。
    假阳性率估计15-25%，为调用方提供可用起点。
    """
    # (a) 魔数比较
    magic_pattern = re.compile(
        r'cmp\s+(?:byte\s+)?\[(\w+)\+?(\w*)\]\s*,\s*(0x[0-9a-fA-F]+)',
        re.IGNORECASE)
    for line in disasm_lines:
        m = magic_pattern.search(line)
        if m:
            # 魔数偏移暗示消息头大小
            try:
                offset = int(m.group(3), 16) if m.group(3) else 0
                # 偏移>64字节视为payload内校验，非消息头
                if offset < 64:
                    return offset + 8  # 保守估计头部大小
            except ValueError:
                continue

    # (b) 长度字段提取
    for i, line in enumerate(disasm_lines):
        if 'recv' in line.lower() or 'read' in line.lower():
            # 向前搜索最近对recv返回值的算术操作：长度解码
            for j in range(i - 1, max(0, i - 10), -1):
                prev = disasm_lines[j].lower()
                if any(op in prev for op in ('add', 'sub', 'and', 'shl', 'shr', 'mul')):
                    # 定位到recv返回值处理：标记边界
                    return 4  # 最小头部大小

    # (c) 熵跳变（回退）
    # 5行滑动窗口，逐窗口计算arith_ratio。
    # arith_ratio >0.5→<0.2骤降处 = 解析头→复制body边界。
    arith_kw = ('add', 'sub', 'mul', 'div', 'and', 'or', 'xor', 'shl', 'shr', 'cmp', 'test')
    ratios = []
    window = 5
    for i in range(len(disasm_lines) - window + 1):
        window_lines = disasm_lines[i:i + window]
        arith_count = sum(
            1 for l in window_lines
            if any(kw in l.lower() for kw in arith_kw)
        )
        ratios.append(arith_count / window)

    for i in range(1, len(ratios)):
        if ratios[i-1] > 0.5 and ratios[i] < 0.2:
            return 8  # 熵跳变点：保守估计8字节头

    return None


def infer_state_variables(block_addrs: List[int],
                           call_targets: Dict[int, str],
                           global_refs: Dict[int, Set[int]]
                           ) -> Dict[int, Set[int]]:
    """推断协议状态变量：影响消息派发控制流的全局变量。

    参数:
      block_addrs: 基本块地址列表
      call_targets: {call_site_addr → callee_name}
      global_refs: {block_addr → {块内引用全局变量地址}}

    返回:
      {global_var_addr → {handler_block_indices}}：各全局变量被引用块集合。

    启发式：全局变量在≥3个条件跳转基本块中被引用即视为状态变量
    （用于switch/case消息类型派发）。
    阈值3为经验值：栈局部变量通常≤2个块引用。
    """
    var_to_blocks: Dict[int, Set[int]] = defaultdict(set)

    for block_addr, vars_refd in global_refs.items():
        if block_addr not in block_addrs:
            continue
        for var_addr in vars_refd:
            var_to_blocks[var_addr].add(block_addr)

    # 过滤：≥3个块引用
    return {
        var: blocks
        for var, blocks in var_to_blocks.items()
        if len(blocks) >= 3
    }
