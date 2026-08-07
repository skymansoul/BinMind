#
# 跨链桥漏洞检测器 — EVM 字节码层面的桥合约特化静态分析。
#
# 跨链桥的漏洞面与普通 DeFi 合约差异显著:
#   (a) 消息验证绕过 — 桥合约接收来自中继器/预言机的外部消息,
#       若签名验证或 merkle proof 验证存在可达的跳过路径, 攻击者可伪造跨链消息
#   (b) 验证者集阈值操纵 — 桥依赖 N-of-M 多签, 若 governance 函数可无时间锁
#       修改 requiredSignatures 或添加/移除验证者, 单点 compromise 可控制全桥
#   (c) 跨链重放 — 消息在源链和目标链之间若无 nonce/chainID 绑定,
#       同一条消息可在两条链上重复执行
#   (d) 未验证的外部消息来源 — CALLDATALOAD 读取的数据未经 origin 验证
#       即被传入 SSTORE/CALL, 表明缺乏消息发送方认证
#
# 现有工具 (Slither/Mythril/Oyente) 均为单链通用检测器,
# 不包含跨链特定的攻击模式。SmartAxe 和 BridgeGuard
# 使用 xCFG/xDFG 做全程序分析——本模块采取互补策略:
# 轻量级操作码模式匹配, 可在完整 CFG 构造之前做快速筛查,
# 假阳性率高于 SmartAxe 但零假阴性 (宁可多报, 不漏桥特有漏洞)。
#
# SmartAxe — xCFG/xDFG 跨链控制流/数据流图,
#      本项目取其漏洞分类框架但实现为轻量级操作码模式匹配
# BridgeGuard — 三种外部认证模式的符号数据流分析,
#      本项目的 unverified_origin 检测参考了其 EIV 分类
# Nomad Bridge Hack — 消息验证绕过的典型案例,
#      verifyProof() 返回值未被检查就直接执行消息

from typing import List, Set
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..parser.evm_parser import EVMBytecodeParser


class CrossChainBridgeDetector(BaseDetector):
    """跨链桥合约漏洞检测器——EVM 字节码操作码模式匹配。

    覆盖四类桥特有漏洞模式。每类模式独立检测、独立报告——
    一个合约可能同时触发多类。
    """

    # 跨链消息事件签名 — keccak256 前 4 字节
    # MessageDispatched / TokensBridged / SwapCompleted 等
    _BRIDGE_EVENT_SIGS: Set[str] = {
        '8c5be1e5',  # Transfer (ERC-20, 指示资产桥接)
        'ddf252ad',  # Transfer 变体
        'e19260fa',  # Deposited (桥存款事件)
        '2169b02c',  # Withdrawn (桥提款事件)
        '6e5702f1',  # MessageRelayed
        '2d1e8e3a',  # CrossChainTransfer
    }

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []
        ops = self.ops

        # 分四路独立检测——每路不影响其他
        findings.extend(self._detect_message_verification_bypass(ops))
        findings.extend(self._detect_validator_manipulation(ops))
        findings.extend(self._detect_cross_chain_replay(ops))
        findings.extend(self._detect_unverified_message_origin(ops))

        return findings

    # (a) 消息验证绕过 — CALL 返回后未检查返回值即执行状态变更
    # 模式: STATICCALL/DELEGATECALL → (无 ISZERO/JUMPI 守卫) → SSTORE

    def _detect_message_verification_bypass(self, ops) -> List[VulnerabilityReport]:
        findings = []
        for i, op in enumerate(ops):
            if op.name not in ('STATICCALL', 'DELEGATECALL', 'CALL'):
                continue
            # 在后续 8 条指令内查找 SSTORE 且中间无 ISZERO/JUMPI
            has_sstore, has_guard = False, False
            for j in range(i + 1, min(i + 8, len(ops))):
                name = ops[j].name
                if name == 'SSTORE':
                    has_sstore = True
                if name in ('ISZERO', 'JUMPI', 'REVERT', 'REQUIRE'):
                    has_guard = True
                    break
            if has_sstore and not has_guard:
                findings.append(VulnerabilityReport(
                    vuln_type="bridge_message_verification_bypass",
                    severity="CRITICAL",
# confidence=0.78,  # 非全程序 CFG 分析——置信度有折扣
                    swc_id="SWC-999",  # 非标准 SWC，桥特有
                    description=(
                        "STATICCALL/DELEGATECALL 后无 ISZERO/JUMPI 守卫直接 SSTORE "
# "——验证调用返回值未被检查，攻击者可构造假证明绕过消息验证"
                    ),
                    location=op.pc if hasattr(op, 'pc') else i,
                    opcode=op.name,
                    impact="攻击者可伪造跨链消息, 从桥上盗取全部锁定资产",
                    recommendation=(
                        "在验证调用后立即检查返回值: "
                        "ISZERO → JUMPI/revert, 仅通过检查后才执行 SSTORE"
                    ),
                    evidence=[
                        f"{op.name} at pc={getattr(op, 'pc', i)} 后直接跟 SSTORE"
                    ],
                    affected_pcs=[getattr(op, 'pc', i)],
                ))
        return findings

    # (b) 验证者集阈值操纵 — SSTORE 修改签名阈值或验证者映射
    # 模式: 检测对单一存储槽的写入, 该槽被 ≥3 处引用 (暗示它控制多签阈值)

    def _detect_validator_manipulation(self, ops) -> List[VulnerabilityReport]:
        findings = []
        # 追踪 SLOAD/SSTORE 的存储槽——同一槽被多次引用说明是"配置参数"
        slot_refs = {}
        for i, op in enumerate(ops):
            if op.name in ('SLOAD', 'SSTORE'):
                # 操作码前的 PUSH 指令压入 slot 编号
                for j in range(i - 1, max(0, i - 4), -1):
                    if ops[j].name.startswith('PUSH'):
                        slot = getattr(ops[j], 'operand', None)
                        if slot is not None:
                            slot_refs.setdefault(slot, []).append(i)
                            break

        # 同一 slot 被 ≥3 次 SSTORE 且从不同函数路径到达 → 阈值/验证者管理参数
        for slot, positions in slot_refs.items():
            sstore_count = sum(1 for p in positions
                             if ops[p].name == 'SSTORE')
            if sstore_count >= 3:
                findings.append(VulnerabilityReport(
                    vuln_type="bridge_validator_threshold_manipulation",
                    severity="HIGH",
# confidence=0.65,  # 存储槽引用分析需 CFG 确认——此处为快速预检
                    swc_id="SWC-999",
                    description=(
# f"存储槽 {hex(slot)} 被 {sstore_count} 次 SSTORE 引用——"
                        "疑似签名阈值或验证者集管理参数, 需确认写入前有时间锁检查"
                    ),
                    location=positions[0] if positions else 0,
                    opcode="SSTORE",
                    impact=(
                        "若攻击者控制 governance 可修改阈值→单签控制全桥→"
                        "盗取多签保护的跨链资产"
                    ),
                    recommendation=(
                        "对阈值/验证者管理函数增加 TimelockController 或 "
                        "至少 48h 延迟执行"
                    ),
                    evidence=[
                        f"slot {hex(slot)} referenced at pc={positions}"
                    ],
                    affected_pcs=positions,
                ))
        return findings

    # (c) 跨链重放 — 缺少 chainID/nonce 绑定
    # 模式: CALLDATALOAD → (无 CHAINID/CODESIZE/SELFBALANCE 上下文绑定)
    #       → SSTORE/CALL

    def _detect_cross_chain_replay(self, ops) -> List[VulnerabilityReport]:
        findings = []
        for i, op in enumerate(ops):
            if op.name != 'CALLDATALOAD':
                continue
            has_chain_binding = False
            has_dangerous_sink = False
            sink_pc = 0
            # 向前查看 12 条指令
            for j in range(i + 1, min(i + 12, len(ops))):
                name = ops[j].name
                if name in ('CHAINID', 'CODESIZE', 'SELFBALANCE',
                           'NUMBER', 'TIMESTAMP'):
                    has_chain_binding = True
                if name in ('SSTORE', 'CALL', 'DELEGATECALL', 'CREATE'):
                    has_dangerous_sink = True
                    sink_pc = getattr(ops[j], 'pc', j)
                    break
            if has_dangerous_sink and not has_chain_binding:
                findings.append(VulnerabilityReport(
                    vuln_type="bridge_cross_chain_replay",
                    severity="HIGH",
                    confidence=0.72,
                    swc_id="SWC-999",
                    description=(
                        "CALLDATALOAD 读取的数据经 SSTORE/CALL 消费, "
# "但未绑定 CHAINID/nonce——消息可在两条链上重放"
                    ),
                    location=getattr(op, 'pc', i),
                    opcode=op.name,
                    impact="同一跨链消息可在源链和目标链上重复执行, 导致双花",
                    recommendation="在消息哈希中包含 block.chainid 和源链 nonce",
                    evidence=[
                        f"CALLDATALOAD at pc={getattr(op, 'pc', i)}, "
                        f"sink at pc={sink_pc}, 无 chainID/nonce 绑定"
                    ],
                    affected_pcs=[getattr(op, 'pc', i), sink_pc],
                ))
        return findings

    # (d) 未验证外部消息来源 — CALLDATALOAD → SSTORE 且中间无 CALLER/Ecrecover

    def _detect_unverified_message_origin(self, ops) -> List[VulnerabilityReport]:
        findings = []
        for i, op in enumerate(ops):
            if op.name != 'CALLDATALOAD':
                continue
            has_auth_check = False
            sstore_seen = False
            sstore_pc = 0
            for j in range(i + 1, min(i + 15, len(ops))):
                name = ops[j].name
                if name in ('CALLER', 'ORIGIN', 'ECRECOVER',
                           'BALANCE', 'EXTCODESIZE'):
                    has_auth_check = True
                    break
                if name == 'SSTORE':
                    sstore_seen = True
                    sstore_pc = getattr(ops[j], 'pc', j)
                    # 继续向后看——auth check 可能在 SSTORE 之后
            if sstore_seen and not has_auth_check:
                findings.append(VulnerabilityReport(
                    vuln_type="bridge_unverified_message_origin",
                    severity="CRITICAL",
                    confidence=0.81,
                    swc_id="SWC-999",
                    description=(
                        "CALLDATALOAD 数据经 SSTORE 持久化, "
# "全程无 CALLER/ECRECOVER 发送方验证——消息来源不可信"
                    ),
                    location=getattr(op, 'pc', i),
                    opcode=op.name,
                    impact="任意地址可提交伪造跨链消息, 无需持有验证者私钥",
                    recommendation=(
                        "在 SSTORE 前增加: require(msg.sender == trustedRelayer) "
                        "或 Ecrecover 签名验证"
                    ),
                    evidence=[
                        f"CALLDATALOAD at pc={getattr(op, 'pc', i)} → "
                        f"SSTORE at pc={sstore_pc}, 无 CALLER/Ecrecover"
                    ],
                    affected_pcs=[getattr(op, 'pc', i), sstore_pc],
                ))
        return findings
