# MITRE ATT&CK技术映射表
# CWE→Technique表 + 多标签分类（主技术+辅助技术）
# 经CAPEC桥接覆盖主要CWE Top 25

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
import re


@dataclass
class TechniqueMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = 0.0
    is_primary: bool = True


# CWE→ATT&CK技术映射——基于MITRE CWE-ATT&CK交叉引用与CAPEC桥接
CWE_ATTACK_MAP: Dict[str, List[Tuple[str, str, str, float]]] = {
    "CWE-787": [
        ("T1203", "Exploitation for Client Execution", "Execution", 0.80),
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.65),
    ],
    "CWE-79": [
        ("T1189", "Drive-by Compromise", "Initial Access", 0.85),
        ("T1059.007", "JavaScript", "Execution", 0.70),
    ],
    "CWE-89": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.90),
        ("T1505", "Server Software Component", "Persistence", 0.40),
    ],
    "CWE-416": [
        ("T1203", "Exploitation for Client Execution", "Execution", 0.75),
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.70),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement", 0.50),
    ],
    "CWE-78": [
        ("T1059.004", "Unix Shell", "Execution", 0.92),
        ("T1059.003", "Windows Command Shell", "Execution", 0.85),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.75),
    ],
    "CWE-20": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.70),
        ("T1055", "Process Injection", "Privilege Escalation", 0.40),
    ],
    "CWE-125": [
        ("T1082", "System Information Discovery", "Discovery", 0.50),
        ("T1005", "Data from Local System", "Collection", 0.35),
    ],
    "CWE-22": [
        ("T1005", "Data from Local System", "Collection", 0.80),
        ("T1083", "File and Directory Discovery", "Discovery", 0.60),
        ("T1560", "Archive Collected Data", "Exfiltration", 0.40),
    ],
    "CWE-352": [
        ("T1204", "User Execution", "Execution", 0.75),
        ("T1505", "Server Software Component", "Persistence", 0.35),
    ],
    "CWE-434": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.85),
        ("T1505.003", "Web Shell", "Persistence", 0.60),
        ("T1059", "Command and Scripting Interpreter", "Execution", 0.50),
    ],
    "CWE-862": [
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", 0.70),
        ("T1078", "Valid Accounts", "Defense Evasion", 0.45),
    ],
    "CWE-476": [
        ("T1499", "Endpoint Denial of Service", "Impact", 0.60),
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.35),
    ],
    "CWE-502": [
        ("T1059", "Command and Scripting Interpreter", "Execution", 0.85),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.80),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement", 0.55),
    ],
    "CWE-77": [
        ("T1059.004", "Unix Shell", "Execution", 0.90),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.70),
    ],
    "CWE-119": [
        ("T1203", "Exploitation for Client Execution", "Execution", 0.82),
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.72),
        ("T1189", "Drive-by Compromise", "Initial Access", 0.50),
    ],
    "CWE-918": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.75),
        ("T1027", "Obfuscated Files or Information", "Defense Evasion", 0.40),
    ],
    "CWE-94": [
        ("T1059", "Command and Scripting Interpreter", "Execution", 0.88),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.75),
    ],
    "CWE-190": [
        ("T1203", "Exploitation for Client Execution", "Execution", 0.60),
        ("T1499", "Endpoint Denial of Service", "Impact", 0.45),
    ],
    "CWE-287": [
        ("T1078", "Valid Accounts", "Defense Evasion", 0.80),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", 0.55),
    ],
    "CWE-798": [
        ("T1078", "Valid Accounts", "Defense Evasion", 0.75),
        ("T1552", "Unsecured Credentials", "Credential Access", 0.65),
    ],
    "CWE-306": [
        ("T1078", "Valid Accounts", "Defense Evasion", 0.70),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", 0.55),
    ],
    "CWE-269": [
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.75),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", 0.60),
    ],
    "CWE-362": [
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.55),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement", 0.30),
    ],
}


def _normalize_cwe(raw: str) -> str:
    m = re.search(r'CWE-?\s*(\d+)', raw, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    return raw.upper().strip().replace(" ", "-")


def map_vulnerability(cve_entry: Dict) -> List[TechniqueMapping]:
    """CVE到MITRE ATT&CK技术映射。

    输入dict应含cve_id、cwe_ids（可选）、description（可选，启发式补充）。
    返回TechniqueMapping列表，多标签分类——主技术+辅助技术。
    """
    cve_id = cve_entry.get("cve_id", "")
    raw_cwes = cve_entry.get("cwe_ids", [])
    desc = cve_entry.get("description", "").lower()
    cwes = [_normalize_cwe(c) for c in raw_cwes] if raw_cwes else []

    mappings: Dict[str, TechniqueMapping] = {}
    for cwd in cwes:
        entries = CWE_ATTACK_MAP.get(cwd, [])
        for i, (tid, tname, tactic, conf) in enumerate(entries):
            is_primary = i == 0
            if tid not in mappings or (is_primary and not mappings[tid].is_primary):
                mappings[tid] = TechniqueMapping(
                    technique_id=tid, technique_name=tname,
                    tactic=tactic, confidence=conf, is_primary=is_primary)

    # 无CWE时从描述文本启发式推断
    if not mappings and desc:
        heuristic_rules = [
            ("overflow|buffer|stack|heap|segfault", "T1203", "Exploitation for Client Execution", "Execution", 0.55),
            ("injection|sql|command|shell|exec|popen", "T1059", "Command and Scripting Interpreter", "Execution", 0.60),
            ("xss|cross.site|javascript|script", "T1189", "Drive-by Compromise", "Initial Access", 0.50),
            ("path.traversal|directory|traversal|../", "T1083", "File and Directory Discovery", "Discovery", 0.45),
            ("deserializ|unserialize|pickle|marshal", "T1059", "Command and Scripting Interpreter", "Execution", 0.55),
            ("privilege|elevation|escalat|root|admin", "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.50),
        ]
        for pattern, tid, tname, tactic, conf in heuristic_rules:
            if re.search(pattern, desc):
                mappings[tid] = TechniqueMapping(
                    technique_id=tid, technique_name=tname,
                    tactic=tactic, confidence=conf, is_primary=len(mappings) == 0)

    return sorted(mappings.values(),
                  key=lambda m: (m.is_primary, m.confidence), reverse=True)


def map_batch(vuln_list: List[Dict]) -> Dict[str, List[TechniqueMapping]]:
    return {v.get("cve_id", f"item_{i}"): map_vulnerability(v)
            for i, v in enumerate(vuln_list)}


def aggregate_tactics(mappings: List[TechniqueMapping]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for m in mappings:
        counts[m.tactic] = counts.get(m.tactic, 0) + 1
    return counts


def to_mitre_matrix(mappings: List[TechniqueMapping]) -> Dict[str, List[Dict]]:
    matrix: Dict[str, List[Dict]] = {}
    for m in mappings:
        matrix.setdefault(m.tactic, []).append({
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "confidence": m.confidence,
            "is_primary": m.is_primary,
        })
    return matrix


def lookup_technique(technique_id: str) -> Optional[Dict]:
    for cwe_id, techniques in CWE_ATTACK_MAP.items():
        for tid, tname, tactic, conf in techniques:
            if tid == technique_id or tid.rsplit(".", 1)[0] == technique_id:
                return {"cwe_id": cwe_id, "technique_id": tid,
                        "technique_name": tname, "tactic": tactic,
                        "confidence": conf}
    return None


def list_all_tactics() -> List[str]:
    tactics = set()
    for techniques in CWE_ATTACK_MAP.values():
        for _, _, tactic, _ in techniques:
            tactics.add(tactic)
    return sorted(tactics)
