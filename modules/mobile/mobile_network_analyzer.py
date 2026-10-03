from enum import StrEnum
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Any, Tuple

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class NetworkGeneration:
    """移动网络世代标识。"""
    GSM = "2g"
    UMTS = "3g"
    LTE = "4g"
    NR = "5g"

@dataclass
class ProtocolLayer:
    """协议层常量定义及消息数据载体。"""
    NAS = "nas"
    RRC = "rrc"
    PDCP = "pdcp"
    RLC = "rlc"
    MAC = "mac"
    PHY = "phy"
    SIP = "sip"
    DIAMETER = "diameter"
    GTP = "gtp"
    S1AP = "s1ap"
    NGAP = "ngap"

    message_type: Any = None
    protocol_discriminator: Any = None
    security_header_type: Any = None
    direction: Any = None
    length: int = 0
    ie_list: Any = None


class VulnSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NASMessage:
    message_type: str = ""
    protocol_discriminator: int = 0
    security_header_type: int = 0
    direction: str = ""
    length: int = 0
    ie_list: List[Any] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_type": self.message_type,
            "protocol_discriminator": hex(self.protocol_discriminator),
            "security_header_type": hex(self.security_header_type),
            "direction": self.direction,
            "length": self.length,
            "ie_list": self.ie_list,
        }


class ProtocolVulnerability:
    __slots__ = ('vulnerability_type', 'layer', 'generation', 'severity', 'description', 'cve_reference', 'detection_pattern', 'impacted_procedures',)

    def __init__(self, vulnerability_type, layer, generation, severity, description, cve_reference="", detection_pattern="", impacted_procedures=None):
        self.vulnerability_type = vulnerability_type
        self.layer = layer
        self.generation = generation
        self.severity = severity
        self.description = description
        self.cve_reference = cve_reference
        self.detection_pattern = detection_pattern
        self.impacted_procedures = impacted_procedures

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "layer": self.layer,
            "generation": self.generation,
            "severity": self.severity.value,
            "description": self.description,
            "cve_reference": self.cve_reference,
            "detection_pattern": self.detection_pattern,
            "impacted_procedures": self.impacted_procedures,
        }


class RRCState:
    __slots__ = ('state', 'encryption_algorithm', 'integrity_algorithm', 'is_encrypted', 'is_integrity_protected', 'key_refresh_counter',)

    def __init__(self, state, encryption_algorithm, integrity_algorithm, is_encrypted, is_integrity_protected, key_refresh_counter=0):
        self.state = state
        self.encryption_algorithm = encryption_algorithm
        self.integrity_algorithm = integrity_algorithm
        self.is_encrypted = is_encrypted
        self.is_integrity_protected = is_integrity_protected
        self.key_refresh_counter = key_refresh_counter

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "encryption_algorithm": self.encryption_algorithm,
            "integrity_algorithm": self.integrity_algorithm,
            "is_encrypted": self.is_encrypted,
            "is_integrity_protected": self.is_integrity_protected,
            "key_refresh_counter": self.key_refresh_counter,
        }


class MobileNetworkAnalysisResult:
    __slots__ = ('target_binary', 'generation', 'nas_messages', 'rrc_states', 'vulnerabilities', 'downgrade_attempts', 'ims_issues', 'risk_score',)

    def __init__(self, target_binary, generation, nas_messages=None, rrc_states=None, vulnerabilities=None, downgrade_attempts=None, ims_issues=None, risk_score=0.0):
        self.target_binary = target_binary
        self.generation = generation
        self.nas_messages = nas_messages if nas_messages is not None else []
        self.rrc_states = rrc_states if rrc_states is not None else []
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []
        self.downgrade_attempts = downgrade_attempts if downgrade_attempts is not None else []
        self.ims_issues = ims_issues if ims_issues is not None else []
        self.risk_score = risk_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_binary": self.target_binary,
            "generation": self.generation,
            "nas_messages": [m.to_dict() for m in self.nas_messages],
            "rrc_states": [s.to_dict() for s in self.rrc_states],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "downgrade_attempts": self.downgrade_attempts,
            "ims_issues": self.ims_issues,
            "risk_score": round(self.risk_score, 2),
        }


class MobileNetworkAnalyzer(BaseAnalyzer):
    """
    移动网络协议安全分析器。

    覆盖5G/4G协议栈安全审计——NAS消息解析、RRC状态检测、IMS漏洞识别。
    基于二进制指纹自动判断网络世代，计算综合风险评分。
    """

    WEAK_CIPHERING_ALGORITHMS: Dict[int, str] = {
        0: "EEA0 (??? - ????)",
        1: "EEA1 (SNOW 3G - ???)",
        2: "EEA2 (AES-CTR - ??)",
        3: "EEA3 (ZUC - ???)",
    }

    WEAK_INTEGRITY_ALGORITHMS: Dict[int, str] = {
        0: "EIA0 (?????? - ????)",
        1: "EIA1 (SNOW 3G - ???)",
        2: "EIA2 (AES-CMAC - ??)",
        3: "EIA3 (ZUC - ???)",
    }

    NAS_PROTOCOL_DISCRIMINATORS: Dict[int, str] = {
        0x02: "5GMM (5G Mobility Management)",
        0x07: "EPS Mobility Management",
        0x0A: "EPS Session Management",
        0x2E: "5GS Session Management",
    }

    IMS_VULN_PATTERNS: List[Tuple[str, str, str]] = [
        ("SIP REGISTER without Auth", "SIP ?????????", "HIGH"),
        ("SIP INVITE flooding", "SIP INVITE ???????", "MEDIUM"),
        ("Diameter CER/CEA race", "Diameter ??????????", "HIGH"),
        ("SIP digest nonce reuse", "SIP ???? nonce ????", "MEDIUM"),
        ("IMS emergency bypass", "???????? IMS ????", "HIGH"),
    ]

    def __init__(self):
        super().__init__()
        self._binary_data: bytes = b""
        self._file_path: str = ""

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """执行移动网络协议安全分析主流程。"""
        self._file_path = kwargs.get("binary_path", "")
        if not self._file_path:
            return {"success": False, "error": "binary_path ?????"}

        try:
            with open(self._file_path, "rb") as f:
                self._binary_data = f.read()
        except Exception as e:
            return {"success": False, "error": f"??????: {e}"}

        if len(self._binary_data) == 0:
            return {"success": False, "error": "???????"}

        generation = self._detect_generation()

        result = MobileNetworkAnalysisResult(
            target_binary=self._file_path,
            generation=generation,
        )

        result.nas_messages = self.parse_nas_message()
        result.rrc_states = self.analyze_radio_resource_control()

        if generation == NetworkGeneration.NR:
            result.vulnerabilities.extend(self.analyze_5g_nr_protocol())
        elif generation == NetworkGeneration.LTE:
            result.vulnerabilities.extend(self.analyze_lte_protocol())

        result.ims_issues = self.detect_ims_vulnerabilities()
        result.downgrade_attempts = self.detect_protocol_downgrade()

        result.risk_score = self._compute_risk_score(result)

        return {
            "success": True,
            "result": result.to_dict(),
        }

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="MobileNetworkAnalyzer",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="5G/4G??????????????NAS/RRC/IMS?????????",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"],
        )

    def analyze_5g_nr_protocol(self) -> List[ProtocolVulnerability]:
        """审计5G NR协议栈安全缺陷。"""
        vulns: List[ProtocolVulnerability] = []

        if b"5G-AKA" in self._binary_data or b"SUCI" in self._binary_data:
            if b"null-scheme" in self._binary_data:
                vulns.append(ProtocolVulnerability(
                    vulnerability_type="suci_null_scheme",
                    layer=ProtocolLayer.NAS,
                    generation=NetworkGeneration.NR,
                    severity=VulnSeverity.HIGH,
                    description="??? SUCI ??? (null-scheme)?SUPI ???????",
                    detection_pattern="null-scheme",
                    impacted_procedures=["Initial Registration", "Identification"],
                ))

        if b"NRF" in self._binary_data or b"Nnrf" in self._binary_data:
            if b"TLS" not in self._binary_data and b"OAuth" not in self._binary_data:
                vulns.append(ProtocolVulnerability(
                    vulnerability_type="sba_insecure_communication",
                    layer=ProtocolLayer.SIP,
                    generation=NetworkGeneration.NR,
                    severity=VulnSeverity.HIGH,
                    description="5G ??? SBA ????? TLS/OAuth2 ??",
                    impacted_procedures=["NF Discovery", "NF Service Request"],
                ))

        if b"5G-GUTI" in self._binary_data:
            if b"5G-S-TMSI" in self._binary_data:
                vulns.append(ProtocolVulnerability(
                    vulnerability_type="guti_reallocation_missing",
                    layer=ProtocolLayer.NAS,
                    generation=NetworkGeneration.NR,
                    severity=VulnSeverity.MEDIUM,
                    description="5G-GUTI ????????? IMSI ????",
                    impacted_procedures=["GUTI Reallocation"],
                ))

        if b"NGSetup" in self._binary_data:
            vulns.append(ProtocolVulnerability(
                vulnerability_type="ng_setup_no_mtls",
                layer=ProtocolLayer.NGAP,
                generation=NetworkGeneration.NR,
                severity=VulnSeverity.HIGH,
                description="gNB-CU ? gNB-DU ? NG ???????? TLS ??",
                impacted_procedures=["NG Setup", "gNB Configuration Update"],
            ))

        return vulns

    def analyze_lte_protocol(self) -> List[ProtocolVulnerability]:
        """审计LTE协议栈安全缺陷。"""
        vulns: List[ProtocolVulnerability] = []

        if b"EPS-AKA" in self._binary_data or b"AKA" in self._binary_data:
            if b"IMSI" in self._binary_data:
                vulns.append(ProtocolVulnerability(
                    vulnerability_type="imsi_exposure",
                    layer=ProtocolLayer.NAS,
                    generation=NetworkGeneration.LTE,
                    severity=VulnSeverity.CRITICAL,
                    description="IMSI ?????????? IMSI Catcher ??",
                    cve_reference="??? CVE-2019-0022",
                    impacted_procedures=["Attach Request", "Tracking Area Update"],
                ))

        if b"S1Setup" in self._binary_data:
            vulns.append(ProtocolVulnerability(
                vulnerability_type="s1ap_no_ipsec",
                layer=ProtocolLayer.S1AP,
                generation=NetworkGeneration.LTE,
                severity=VulnSeverity.HIGH,
                description="S1 ????? IPSec ?????????????",
                impacted_procedures=["S1 Setup", "eNB Configuration Update"],
            ))

        if b"GTPv1" in self._binary_data or b"GTPv2" in self._binary_data:
            vulns.append(ProtocolVulnerability(
                vulnerability_type="gtp_no_filtering",
                layer=ProtocolLayer.GTP,
                generation=NetworkGeneration.LTE,
                severity=VulnSeverity.HIGH,
                description="GTP ?????????????????????",
                impacted_procedures=["Create Session", "Modify Bearer"],
            ))

        if b"X2AP" in self._binary_data:
            vulns.append(ProtocolVulnerability(
                vulnerability_type="x2_handover_no_key_refresh",
                layer=ProtocolLayer.RRC,
                generation=NetworkGeneration.LTE,
                severity=VulnSeverity.MEDIUM,
                description="X2 ??????????? (key chaining)",
                impacted_procedures=["X2 Handover"],
            ))

        return vulns

    def detect_ims_vulnerabilities(self) -> List[str]:
        """检测IMS(IP多媒体子系统)安全漏洞。"""
        issues: List[str] = []

        for pattern, description, severity in self.IMS_VULN_PATTERNS:
            search_pattern = pattern.split(" ")[0].encode("utf-8")
            if search_pattern in self._binary_data:
                issues.append(f"[{severity}] {description} - ????: {pattern}")

        if b"SIP" in self._binary_data or b"sip" in self._binary_data:
            has_tls = b"TLS" in self._binary_data or b"sips:" in self._binary_data
            has_ipsec = b"IPSEC" in self._binary_data or b"ipsec" in self._binary_data

            if not has_tls and not has_ipsec:
                issues.append("[CRITICAL] SIP ????? TLS/IPSec ????")
            if has_tls and b"TLS 1.0" in self._binary_data:
                issues.append("[HIGH] SIP ?????? TLS 1.0 ??")

            if b"AKAv1-MD5" in self._binary_data:
                issues.append("[HIGH] ?? AKAv1-MD5 ?????????")

        if b"Diameter" in self._binary_data or b"DIAMETER" in self._binary_data:
            if b"CER" in self._binary_data and b"TLS" not in self._binary_data:
                issues.append("[HIGH] Diameter ????????????")

        return issues

    def parse_nas_message(self) -> List[NASMessage]:
        """解析NAS(非接入层)消息结构。"""
        messages: List[NASMessage] = []

        nas_header_pattern = re.compile(
            rb'[\x02\x07\x0A\x2E]'
            rb'[\x00\x01\x02\x03\x04]'
        )

        for match in nas_header_pattern.finditer(self._binary_data):
            offset = match.start()
            if offset + 2 > len(self._binary_data):
                continue

            pd_byte = self._binary_data[offset]
            protocol_discriminator = pd_byte & 0x0F
            security_header_type = (pd_byte >> 4) & 0x0F

            msg_type = self._binary_data[offset + 1]
            msg_type_name = self._get_nas_message_type(protocol_discriminator, msg_type)

            ie_list = self._parse_nas_information_elements(
                self._binary_data[offset + 2:offset + min(256, len(self._binary_data) - offset - 2)]
            )

            messages.append(NASMessage(
                message_type=msg_type_name,
                protocol_discriminator=protocol_discriminator,
                security_header_type=security_header_type,
                direction="unknown",
                length=min(256, len(self._binary_data) - offset),
                ie_list=ie_list,
            ))

            if len(messages) >= 20:
                break

        return messages

    def analyze_radio_resource_control(self) -> List[RRCState]:
        """分析RRC(无线资源控制)安全状态。"""
        states: List[RRCState] = []

        for algo_id, algo_desc in self.WEAK_CIPHERING_ALGORITHMS.items():
            algo_marker = struct.pack("B", algo_id)
            if algo_marker in self._binary_data:
                offset = self._binary_data.find(algo_marker)
                is_encrypted = (algo_id != 0)
                is_integrity = False

                states.append(RRCState(
                    state="CONNECTED" if self._is_likely_connected(offset) else "IDLE",
                    encryption_algorithm=algo_desc,
                    integrity_algorithm=self.WEAK_INTEGRITY_ALGORITHMS.get(algo_id, "??"),
                    is_encrypted=is_encrypted,
                    is_integrity_protected=is_integrity,
                ))

        for algo_id, algo_desc in self.WEAK_INTEGRITY_ALGORITHMS.items():
            search_bytes = b"integrity" + struct.pack("B", algo_id)
            if search_bytes in self._binary_data.lower():
                states.append(RRCState(
                    state="CONNECTED",
                    encryption_algorithm="??",
                    integrity_algorithm=algo_desc,
                    is_encrypted=False,
                    is_integrity_protected=(algo_id != 0),
                ))

        return states

    def detect_protocol_downgrade(self) -> List[str]:
        """检测协议降级攻击向量。"""
        downgrades: List[str] = []

        if b"5G" in self._binary_data or b"5GS" in self._binary_data:
            if b"LTE" in self._binary_data or b"EUTRA" in self._binary_data:
                if b"fallback" in self._binary_data.lower() or b"inter-RAT" in self._binary_data:
                    downgrades.append(
                        "??? 5G?4G ? inter-RAT ??????????????"
                    )

        if b"LTE" in self._binary_data:
            if b"UMTS" in self._binary_data or b"GERAN" in self._binary_data:
                downgrades.append(
                    "??? LTE?UMTS/GERAN ? inter-RAT ????????????????"
                )

        if b"EEA0" in self._binary_data or b"EIA0" in self._binary_data:
            downgrades.append(
                "??????/????? (EEA0/EIA0)??????????????"
            )

        if b"NSA" in self._binary_data and b"EN-DC" in self._binary_data:
            downgrades.append(
                "EN-DC ???????LTE ?????? 5G ???????"
            )

        return downgrades

    def _detect_generation(self) -> NetworkGeneration:
        """基于二进制指纹检测目标网络世代。"""
        score_5g = sum(1 for p in [b"5G", b"NR", b"gNB", b"5GC", b"NGAP", b"XnAP"]
                      if p in self._binary_data)
        score_4g = sum(1 for p in [b"LTE", b"EPC", b"eNB", b"S1AP", b"X2AP", b"MME"]
                      if p in self._binary_data)
        score_3g = sum(1 for p in [b"UMTS", b"UTRAN", b"RNC", b"NodeB", b"RNSAP"]
                      if p in self._binary_data)

        if score_5g > score_4g and score_5g > score_3g:
            return NetworkGeneration.NR
        elif score_4g > score_3g:
            return NetworkGeneration.LTE
        elif score_3g > 0:
            return NetworkGeneration.UMTS
        return NetworkGeneration.GSM

    def _get_nas_message_type(self, pd: int, msg_type: int) -> str:
        """将NAS消息类型码映射为可读协议名称。"""
        emm_messages = {
            0x41: "Attach Request", 0x42: "Attach Accept", 0x43: "Attach Complete",
            0x44: "Attach Reject", 0x45: "Detach Request", 0x46: "Detach Accept",
            0x48: "Tracking Area Update Request", 0x49: "Tracking Area Update Accept",
            0x4C: "Service Request", 0x60: "Authentication Request",
            0x61: "Authentication Response", 0x62: "Authentication Reject",
            0x63: "Identity Request", 0x64: "Identity Response",
            0x70: "Security Mode Command", 0x71: "Security Mode Complete",
        }
        return emm_messages.get(msg_type, f"Unknown-0x{msg_type:02X}")

    def _parse_nas_information_elements(self, data: bytes) -> List[Dict[str, Any]]:
        """解析NAS信息元素(IE)的TLV结构。"""
        ies: List[Dict[str, Any]] = []
        pos = 0

        while pos < len(data) and len(ies) < 20:
            if pos + 1 >= len(data):
                break
            iei = data[pos]
            pos += 1

            if iei & 0x0F == 0x0F and pos < len(data):
                length = data[pos]
                pos += 1
                value = data[pos:pos + length]
                pos += length
                ies.append({
                    "iei": hex(iei),
                    "length": length,
                    "value_hex": value[:16].hex(),
                })
            elif iei <= 0x7F and pos < len(data):
                length = data[pos]
                pos += 1
                value = data[pos:pos + length]
                pos += length
                ies.append({
                    "iei": hex(iei),
                    "length": length,
                    "value_hex": value[:16].hex(),
                })
            else:
                ies.append({"iei": hex(iei), "type": "type1_or_type3"})

        return ies

    def _is_likely_connected(self, offset: int) -> bool:
        """基于上下文字节模式推断RRC连接状态。"""
        nearby = self._binary_data[max(0, offset - 64):offset + 64]
        return any(kw in nearby for kw in [b"CONN", b"ACTIVE", b"ESTABLISH"])

    def _compute_risk_score(self, result: MobileNetworkAnalysisResult) -> float:
        """综合漏洞严重性、降级风险与加密状态计算加权风险评分。"""
        score = 0.0
        severity_weights = {
            VulnSeverity.CRITICAL: 10.0,
            VulnSeverity.HIGH: 7.0,
            VulnSeverity.MEDIUM: 4.0,
            VulnSeverity.LOW: 2.0,
            VulnSeverity.INFO: 0.5,
        }

        for vuln in result.vulnerabilities:
            score += severity_weights.get(vuln.severity, 1.0)

        score += len(result.downgrade_attempts) * 5.0
        score += len(result.ims_issues) * 3.0

        for state in result.rrc_states:
            if "EEA0" in state.encryption_algorithm or "EIA0" in state.integrity_algorithm:
                score += 10.0

        return min(score, 100.0)

__all__ = ["MobileNetworkAnalyzer", "MobileNetworkAnalysisResult", "NASMessage",
           "RRCState", "ProtocolVulnerability", "NetworkGeneration", "ProtocolLayer"]
