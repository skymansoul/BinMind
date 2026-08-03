#
# EVM 重入漏洞检测器 — 基于 EVM 字节码静态数据流的重入模式识别。
#
# 重入（reentrancy）是智能合约最经典的漏洞类型——合约 A 调用合约 B，
# B 在 A 更新自身状态之前回调 A，导致 A 的状态不一致。
# EVM 层面的重入判断不依赖 Solidity 源码——仅从字节码的控制流和数据流即可识别。
#
# 检测逻辑——识别以下模式的同时出现：
#   (a) CALL 指令前有 SSTORE（状态变更）且 SSTORE 在 CALL 之后——
#       即"先外部调用，再更新状态"——违反了 check-effects-interactions 模式
#   (b) CALL 的目标地址受 CALLER 或 CALLDATALOAD 影响——
#       即外部调用目标是用户可控的（而非硬编码的已知地址）
#   (c) CALL 的 gas 参数为 ALL（gasleft() 的结果）或极大值——
#       给了被调用方足够的 gas 来执行回调
#
# 输出: {vulnerable_locations: [pc_offset, ...], severity: 'critical'|'high'|'medium'}

from typing import Dict, List, Set, Tuple, Optional


def detect_reentrancy(bytecode_hex: str) -> Dict:
    """检测 EVM 字节码中的重入漏洞模式。

    参数:
      bytecode_hex: EVM 字节码的十六进制字符串（不含 0x 前缀）

    返回:
      {vulnerable, locations, confidence, evidence}
    """
    # EVM 操作码定义——仅包含重入检测需要的子集
    OPCODES = {
        0x54: 'SLOAD', 0x55: 'SSTORE',
        0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf4: 'DELEGATECALL',
        0xfa: 'STATICCALL',
        0x33: 'CALLER', 0x35: 'CALLDATALOAD',
        0x5a: 'GAS',
        0x56: 'JUMP', 0x57: 'JUMPI',
        0x60: 'PUSH1', 0x61: 'PUSH2', 0x7f: 'PUSH32',
        0x5b: 'JUMPDEST',
    }

    # 将 hex 转为 bytes
    try:
        code = bytes.fromhex(bytecode_hex)
    except ValueError:
        return {'vulnerable': False, 'error': 'invalid hex bytecode'}

    # 两遍扫描：
    #   第一遍：定位所有 CALL 类指令、SSTORE 指令、和用户可控输入点
    #   第二遍：检查 CALL 和 SSTORE 之间的相对顺序，识别"先 CALL 后 SSTORE"模式

    call_locs: List[int] = []
    store_locs: List[int] = []
    user_controlled_locs: Set[int] = set()

    i = 0
    while i < len(code):
        op = code[i]
        opcode = OPCODES.get(op, '')

        if opcode in ('CALL', 'CALLCODE', 'DELEGATECALL'):
            call_locs.append(i)
        elif opcode == 'SSTORE':
            store_locs.append(i)
        elif opcode in ('CALLER', 'CALLDATALOAD'):
            user_controlled_locs.add(i)
        elif opcode == 'GAS':
            # GAS 出现在 CALL 的 gas 参数位置时是重入的高风险信号
            # 静态无法精确判断 GAS 的值流向哪个 CALL——
            # 保守处理：记录 GAS 位置，后续与 CALL 位置做邻近匹配
            user_controlled_locs.add(i)  # 复用 user_controlled set 追踪

        # 跳过 PUSH 的数据部分
        if 0x60 <= op <= 0x7f:
            push_size = op - 0x60 + 1
            i += push_size
        i += 1

    if not call_locs:
        return {'vulnerable': False, 'reason': 'no external calls found'}

    # 第二遍：检测"先 CALL 后 SSTORE"——即 SSTORE 的 PC 在 CALL 之后但仍在同一执行路径上
    # 静态无法精确判断执行路径——用启发式：同一基本块内或相邻基本块
    violations = []
    for call_pc in call_locs:
        for store_pc in store_locs:
            if store_pc > call_pc:
                # 粗粒度检查：SSTORE 在 CALL 之后不超过 50 条指令
                # 超过 50 条通常意味着已进入不同的逻辑块
                if store_pc - call_pc <= 50:
                    # 检查 CALL 的目标是否受用户输入影响
                    # 搜索 CALL 指令前 20 字节范围内是否有 CALLER/CALLDATALOAD/GAS
                    user_influenced = any(
                        uc in user_controlled_locs
                        and call_pc - 20 <= uc <= call_pc
                        for uc in user_controlled_locs
                    )
                    violations.append({
                        'call_at': call_pc,
                        'store_at': store_pc,
                        'user_influenced': user_influenced,
                        'distance': store_pc - call_pc,
                    })

    if violations:
        # 严重性判定——存在用户可控的 CALL → 后续 SSTORE → critical
        critical_violations = [v for v in violations if v['user_influenced']]
        return {
            'vulnerable': True,
            'confidence': 'high' if critical_violations else 'medium',
            'violations': violations,
            'critical_count': len(critical_violations),
            'total_call_sites': len(call_locs),
        }

    return {'vulnerable': False, 'reason': 'no reentrancy pattern detected'}
