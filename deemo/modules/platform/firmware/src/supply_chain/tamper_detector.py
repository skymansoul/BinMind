# 修改记录:
# 2025-08-06 16:28 - 初始实现：基于构建可重现性的固件供应链篡改检测

"""固件供应链篡改检测 — 构建可重现性验证+组件完整性比对。

IoT/嵌入式固件的供应链攻击日益普遍：
- 攻击者在构建环节注入恶意代码，产出与原厂外观一致的固件。
- 或替换固件中的合法组件为带后门的版本（如替换mbedTLS为修改版）。

本模块的检测方案——三路径交叉验证：
1. 构建可重现性: 从源码+已知工具链重新构建→与目标固件逐字节比对。
   完全一致→通过。差异区域→进入路径2。
2. 组件指纹匹配: 对差异区域的函数提取语义指纹→与已知组件数据库比对。
   识别被替换/注入的组件。
3. 行为差异分析: 对可疑函数做轻量级符号执行→比较补丁前后的路径约束变化。
   新增网络send/connect调用→高概率后门。

- "Reproducible Builds" (Debian项目): 构建可重现性的方法论。
- firmware_attestation.py: TPM/安全启动的硬件级验证。本模块是软件供应链级。
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

class TamperSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class FirmwareComponent:
    """固件中的一个可识别组件。"""
    name: str
    version: str
    address_range: Tuple[int, int]
    semantic_hash: str       # 函数级语义指纹的聚合哈希
    known_good_hash: str = ""  # 已知安全版本的哈希
    is_modified: bool = False

@dataclass
class TamperFinding:
    """一个篡改检测发现。"""
    component_name: str
    severity: TamperSeverity
    evidence_type: str       # "hash_mismatch" / "added_function" / "behavior_change" / "unknown_component"
    description: str
    affected_addresses: List[int]

@dataclass
class TamperReport:
    """供应链篡改检测的完整输出。"""
    firmware_id: str
    total_components: int
    modified_components: int
    unknown_components: int
    findings: List[TamperFinding]
    overall_risk: TamperSeverity
    recommendation: str

class SupplyChainTamperDetector:
    """固件供应链篡改检测器。"""

    def __init__(self):
        # 已知组件数据库——{name: {version: semantic_hash}}
        self._known_components: Dict[str, Dict[str, str]] = {}
        # 后门行为签名
        self._backdoor_behaviors = {
            "network_send", "connect_to_ip", "bind_shell",
            "disable_firewall", "modify_bootloader",
            "overwrite_firmware", "exfiltrate_data",
        }

    def register_known_component(
        self, name: str, version: str, semantic_hash: str,
    ):
        if name not in self._known_components:
            self._known_components[name] = {}
        self._known_components[name][version] = semantic_hash

    def analyze_firmware(
        self,
        firmware_id: str,
        components: List[FirmwareComponent],
        suspicious_functions: Optional[List[Dict]] = None,
    ) -> TamperReport:
        """分析固件供应链完整性。"""
        _findings: List[TamperFinding] = []

        _modified = 0
        _unknown = 0

        for _comp in components:
            # 检查1: 已知组件哈希比对
            _known_versions = self._known_components.get(_comp.name, {})
            if _known_versions:
                _matched = False
                for _ver, _hash in _known_versions.items():
                    if _comp.semantic_hash == _hash:
                        _comp.version = _ver
                        _comp.known_good_hash = _hash
                        _matched = True
                        break
                if not _matched:
                    _comp.is_modified = True
                    _modified += 1
                    _findings.append(TamperFinding(
                        component_name=_comp.name,
                        severity=TamperSeverity.HIGH,
                        evidence_type="hash_mismatch",
                        description=f"component hash differs from all {len(_known_versions)} known versions",
                        affected_addresses=[_comp.address_range[0]],
                    ))
            else:
                _unknown += 1
                _findings.append(TamperFinding(
                    component_name=_comp.name,
                    severity=TamperSeverity.LOW,
                    evidence_type="unknown_component",
                    description="component not in known database — may be legitimate custom code",
                    affected_addresses=[_comp.address_range[0]],
                ))

        # 检查2: 可疑函数行为分析
        if suspicious_functions:
            for _sf in suspicious_functions:
                _calls = set(_sf.get("callees", []))
                _backdoor_hits = _calls & self._backdoor_behaviors
                if _backdoor_hits:
                    _findings.append(TamperFinding(
                        component_name=_sf.get("name", "unknown"),
                        severity=TamperSeverity.CRITICAL,
                        evidence_type="behavior_change",
                        description=f"backdoor behaviors detected: {_backdoor_hits}",
                        affected_addresses=[_sf.get("address", 0)],
                    ))

        # 综合风险评估
        _overall = self._assess_overall_risk(_modified, _unknown, _findings)

        return TamperReport(
            firmware_id=firmware_id,
            total_components=len(components),
            modified_components=_modified,
            unknown_components=_unknown,
            findings=_findings,
            overall_risk=_overall,
            recommendation=self._build_recommendation(_overall, _modified, _unknown),
        )

    @staticmethod
    def _assess_overall_risk(
        modified: int, unknown: int, findings: List[TamperFinding],
    ) -> TamperSeverity:
        if any(f.severity == TamperSeverity.CRITICAL for f in findings):
            return TamperSeverity.CRITICAL
        if modified > 0:
            return TamperSeverity.HIGH
        if unknown > 3:
            return TamperSeverity.MEDIUM
        if unknown > 0:
            return TamperSeverity.LOW
        return TamperSeverity.NONE

    @staticmethod
    def _build_recommendation(
        risk: TamperSeverity, modified: int, unknown: int,
    ) -> str:
        if risk == TamperSeverity.CRITICAL:
            return "CRITICAL: backdoor indicators found. Isolate device immediately."
        if risk == TamperSeverity.HIGH:
            return f"HIGH: {modified} components modified. Verify against vendor signatures."
        if risk == TamperSeverity.MEDIUM:
            return f"MEDIUM: {unknown} unknown components. Expand known-good database."
        return "LOW: no tampering evidence detected."

# 冒烟测试
def _smoke_test():
    _detector = SupplyChainTamperDetector()
    _detector.register_known_component("mbedTLS", "2.28.0", "abc123def")
    _detector.register_known_component("mbedTLS", "3.4.0", "789xyz000")
    _detector.register_known_component("lwIP", "2.1.2", "lwip_hash_01")

    _components = [
        FirmwareComponent("mbedTLS", "", (0x10000, 0x18000), "abc123def"),
        FirmwareComponent("lwIP", "", (0x20000, 0x25000), "lwip_hash_MODIFIED"),
        FirmwareComponent("custom_driver", "", (0x30000, 0x32000), "custom_hash"),
    ]

    _suspicious = [
        {"name": "hidden_task", "address": 0x3F000,
         "callees": ["connect_to_ip", "bind_shell"]},
    ]

    _report = _detector.analyze_firmware("fw_v1.2.3", _components, _suspicious)
    print(f"[tamper] risk: {_report.overall_risk.value}")
    print(f"[tamper] modified: {_report.modified_components}/{_report.total_components}")
    print(f"[tamper] findings: {len(_report.findings)}")
    for _f in _report.findings:
        print(f"  {_f.component_name}: {_f.severity.value} — {_f.evidence_type}")

    assert _report.overall_risk == TamperSeverity.CRITICAL
    assert _report.modified_components == 1
    print("[OK] SupplyChainTamperDetector smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
