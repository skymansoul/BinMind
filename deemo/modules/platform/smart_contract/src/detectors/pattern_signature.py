# 模式签名检测器 — 类YARA的字节码签名匹配
# 从smart_contract_analyzer.py内联实现拆分
from typing import List, Callable
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..core.types import VulnerabilityType
from ..parser.evm_parser import EVMBytecodeParser, EVMOp
from pathlib import Path # 未使用


# 谓词类型别名：接受EVMOp，返回bool
OpPredicate = Callable[[EVMOp], bool]


# 遗留代码: 滑动窗口重构前的原始匹配循环
# def _match_all_rules(self, ops, rules):
#     matches = []
#     for rule_name, preds, sev, desc, rec, vt in rules:
#         for idx in range(len(ops)):
#             if all(p(op) for p, op in zip(preds, ops[idx:])):
#                 matches.append((rule_name, idx, ops[idx]))
#     return matches

class PatternSignatureDetector(BaseDetector):
    # 类YARA漏洞签名匹配器。使用谓词序列（非正则）搜索字节码，
    # 因SWAP/DUP可拉大指令间距，位置正则不可靠。
    # 每条规则: (name, predicates, severity, description, recommendation, vuln_type)。

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)
        self._rules: List[tuple] = []
        self._register_default_rules()

    def _register_default_rules(self):
        # 注册内置签名规则: SELFDESTRUCT、零地址、ABI、tx.origin

        self._rules.append((
            'unprotected_selfdestruct',
            [
                lambda op: op.is_push,
                lambda op: op.name == 'SELFDESTRUCT',
            ],
            'CRITICAL',
            'SELFDESTRUCT 紧跟在 PUSH 后且无调用者检查',
            '添加 onlyOwner 修饰符或等效的 CALLER 检查',
            VulnerabilityType.UNPROTECTED_SELFDESTRUCT,
        ))

        self._rules.append((
            'zero_address_transfer',
            [
                lambda op: op.is_push and op.push_data in (b'\x00', b''),
                lambda op: op.is_push and op.push_data in (b'\x00', b''),
                lambda op: op.is_push and op.push_data in (b'\x00', b''),
                lambda op: op.is_push and op.push_data in (b'\x00', b''),
                lambda op: op.name == 'CALL',
            ],
            'MEDIUM',
            '检测到标准 transfer 模式但目标地址为 0x0，资金可能被销毁',
            '添加地址有效性检查 require(to != address(0))',
            VulnerabilityType.UNCHECKED_SEND,
        ))

        self._rules.append((
            'abi_encode_packed_ambiguity',
            [
                lambda op: op.name in ('CALLDATALOAD', 'CALLDATACOPY'),
                lambda op: op.name in ('KECCAK256', 'SSTORE'),
            ],
            'LOW',
            '动态类型经 CALLDATA 直接传入 KECCAK256/SSTORE，存在 ABI 编码歧义风险',
            '当使用 abi.encodePacked 处理动态类型时产生哈希碰撞',
            VulnerabilityType.ABI_ENCODE_PACKED,
        ))

        self._rules.append((
            'tx_origin_auth',
            [
                lambda op: op.name == 'ORIGIN',
                lambda op: op.name in ('EQ', 'SUB', 'XOR'),
                lambda op: op.name == 'JUMPI',
            ],
            'HIGH',
            'tx.origin 参与身份验证断言，典型的钓鱼攻击入口',
            '替换 tx.origin 为 msg.sender',
            VulnerabilityType.TX_ORIGIN,
        ))

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []
        ops = self.ops
        n = len(ops)

        for rule_name, predicates, severity, desc, recommendation, vuln_override in self._rules:
            pattern_len = len(predicates)
            if n < pattern_len:
                continue

            i = 0
            while i <= n - pattern_len:
                matched = True
                for offset in range(pattern_len):
                    if not predicates[offset](ops[i + offset]):
                        matched = False
                        break

                if matched:
                    first_op = ops[i]
                    last_op = ops[i + pattern_len - 1]

                    vuln_type = vuln_override or VulnerabilityType.DEPRECATED_OPCODE

                    # 收集证据片段
                    evidence = [
                        f"  {ops[j].pc:#06x}: {ops[j].name}"
                        + (f" 0x{ops[j].push_data.hex()}" if ops[j].push_data else "")
                        for j in range(i, i + pattern_len)
                    ]
                    affected = [ops[j].pc for j in range(i, i + pattern_len)]

                    findings.append(VulnerabilityReport(
                        vuln_type=vuln_type,
                        severity=severity,
                        confidence=0.7,
                        description=desc,
                        location=first_op.pc,
                        opcode=last_op.name,
                        recommendation=recommendation,
                        evidence=evidence,
                        affected_pcs=affected,
                    ))
                    i += 1
                else:
                    i += 1

        return findings
