from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

@dataclass
class AttackTechnique:
    technique_id: str = ""
    technique_name: str = ""
    description: str = ""
    tactics: List[str] = field(default_factory=list)

ATTACKTechnique = AttackTechnique

class AttackTactic(Enum):
    EXECUTION = "execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"

ATTACKTactic = AttackTactic

@dataclass
class VulnerabilityMappingClass:
    vulnerability_type: str = ""
    primary_technique: Optional[AttackTechnique] = None
    secondary_techniques: List[AttackTechnique] = field(default_factory=list)
    mapped_techniques: List[AttackTechnique] = field(default_factory=list)
    confidence: float = 0.0
    impact_type: str = ""
    target_type: str = ""
    reasoning: str = ""

    def to_dict(self):
        return {
            'vulnerability_type': self.vulnerability_type,
            'primary_technique': self.primary_technique.technique_id if self.primary_technique else None,
            'secondary_techniques': [t.technique_id for t in self.secondary_techniques],
            'confidence': self.confidence,
            'reasoning': self.reasoning,
        }

AttackMapping = VulnerabilityMappingClass
VulnerabilityMapping = VulnerabilityMappingClass

_TECH_DB = {
    "T1190": AttackTechnique("T1190", "Exploit Public-Facing Application", "Exploit software vulnerabilities", ["Initial Access"]),
    "T1203": AttackTechnique("T1203", "Exploitation for Client Execution", "Exploit client software", ["Execution"]),
    "T1068": AttackTechnique("T1068", "Exploitation for Privilege Escalation", "Exploit to escalate privileges", ["Privilege Escalation"]),
    "T1059": AttackTechnique("T1059", "Command and Scripting Interpreter", "Abuse command interpreters", ["Execution"]),
    "T1499": AttackTechnique("T1499", "Endpoint Denial of Service", "Denial of service attacks", ["Impact"]),
    "T1055": AttackTechnique("T1055", "Process Injection", "Inject code into processes", ["Defense Evasion", "Privilege Escalation"]),
    "T1592": AttackTechnique("T1592", "Gather Victim Host Information", "Gather host information", ["Reconnaissance"]),
}

_VULN_MAP = {
    "buffer_overflow": "T1055",
    "command_injection": "T1059",
    "format_string": "T1055",
    "heap_overflow": "T1203",
    "information_disclosure": "T1592",
    "privilege_escalation": "T1068",
    "remote_code_execution": "T1190",
    "sql_injection": "T1190",
    "use_after_free": "T1055",
    "denial_of_service": "T1499",
}

class AttackMapper:
    def __init__(self, custom_mapping_file=None):
        self.custom_mapping_file = custom_mapping_file
        self.techniques = dict(_TECH_DB)
        self.mappings = {}
        self.vulnerability_mapping = {}

    def map_vulnerability(self, vuln_type="", context=None, cwe_id=None,
                          impact_type=None, target_type=None, **kwargs):
        lookup = impact_type if impact_type else vuln_type
        if lookup is None:
            lookup = ""
        vt_lower = lookup.lower()
        tid = None
        for key in _VULN_MAP:
            if vt_lower == key.lower():
                tid = _VULN_MAP[key]
                break
        if not tid:
            for key in _VULN_MAP:
                keywords = key.replace('_', ' ')
                if any(w in vt_lower for w in keywords.split() if len(w) > 2):
                    tid = _VULN_MAP[key]
                    break
        if not tid:
            for key in _VULN_MAP:
                for word in key.split('_'):
                    if len(word) > 2 and word in vt_lower:
                        tid = _VULN_MAP[key]
                        break
                if tid:
                    break
        if not tid:
            if "stack" in vt_lower and "buffer" in vt_lower:
                tid = "T1055"
            elif "heap" in vt_lower:
                tid = "T1203"
            elif "overflow" in vt_lower:
                tid = "T1190"
            else:
                tid = "T1203"
        pri = _TECH_DB.get(tid, _TECH_DB["T1203"])
        sec = [t for k, t in _TECH_DB.items() if k != tid][:2]
        m = AttackMapping(
            vulnerability_type=vuln_type,
            primary_technique=pri,
            secondary_techniques=sec,
            mapped_techniques=[pri] + sec,
            confidence=0.85 if impact_type else 0.7,
            impact_type=impact_type or "",
            target_type=target_type or "",
        )
        return m

    def map_vulnerabilities(self, vulns):
        results = []
        for v in (vulns or []):
            vt = v.get('vulnerability_type', v.get('type', ''))
            m = self.map_vulnerability(vt)
            results.append({
                'vulnerability_type': vt,
                'mapping': m,
            })
        return results

    def get_technique_details(self, technique_id):
        return _TECH_DB.get(technique_id)

    def get_related_techniques(self, technique_id):
        t = _TECH_DB.get(technique_id)
        if not t:
            return []
        return [v for k, v in _TECH_DB.items() if k != technique_id][:3]

    def get_tactics_for_technique(self, technique_id):
        t = _TECH_DB.get(technique_id)
        return t.tactics if t else []

    def get_techniques_for_tactic(self, tactic):
        return [t for t in _TECH_DB.values() if tactic in t.tactics]

    def get_mitigations(self, technique):
        return ["Input validation", "Least privilege"]

    def export_attack_navigator(self):
        return {"name": "layer", "techniques": []}

ATTACKMapper = AttackMapper

def map_vulnerability_to_attack(vuln):
    mapper = AttackMapper()
    if isinstance(vuln, dict):
        return mapper.map_vulnerability(**vuln)
    return mapper.map_vulnerability(str(vuln))

def map_vulnerabilities_to_attack(vulns):
    mapper = AttackMapper()
    return mapper.map_vulnerabilities(vulns)
