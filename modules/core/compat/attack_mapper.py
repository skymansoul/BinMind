# MITRE ATT&CK 映射引擎 — 漏洞到战术技术的语义桥接
# 覆盖 12 种常见攻击路径，CWE 辅助映射，ATT&CK Navigator 导出

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from enum import Enum


# 核心数据结构
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
    DEFENSE_EVASION = "defense_evasion"
    INITIAL_ACCESS = "initial_access"
    IMPACT = "impact"
    RECONNAISSANCE = "reconnaissance"

ATTACKTactic = AttackTactic


@dataclass
class TechniqueMatch:
    technique: AttackTechnique
    confidence: float
    match_method: str  # 'exact' | 'substring' | 'token'
    matched_tokens: List[str] = field(default_factory=list)


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


# 12 种核心 ATT&CK v15 技术
_TECH_DB: Dict[str, AttackTechnique] = {
    "T1190": AttackTechnique("T1190", "Exploit Public-Facing Application",
        "利用面向公众的应用程序漏洞获取初始访问", ["Initial Access"]),
    "T1203": AttackTechnique("T1203", "Exploitation for Client Execution",
        "通过客户端软件漏洞执行代码", ["Execution"]),
    "T1068": AttackTechnique("T1068", "Exploitation for Privilege Escalation",
        "利用漏洞提升权限", ["Privilege Escalation"]),
    "T1059": AttackTechnique("T1059", "Command and Scripting Interpreter",
        "滥用命令和脚本解释器", ["Execution"]),
    "T1499": AttackTechnique("T1499", "Endpoint Denial of Service",
        "端点拒绝服务攻击", ["Impact"]),
    "T1055": AttackTechnique("T1055", "Process Injection",
        "向进程注入恶意代码", ["Defense Evasion", "Privilege Escalation"]),
    "T1592": AttackTechnique("T1592", "Gather Victim Host Information",
        "收集受害主机信息", ["Reconnaissance"]),
    "T1195": AttackTechnique("T1195", "Supply Chain Compromise",
        "通过软件供应链植入后门", ["Initial Access"]),
    "T1610": AttackTechnique("T1610", "Deploy Container",
        "部署恶意容器镜像", ["Execution"]),
    "T1612": AttackTechnique("T1612", "Build Image on Host",
        "在目标主机构建容器镜像", ["Defense Evasion"]),
    "T1497": AttackTechnique("T1497", "Virtualization/Sandbox Evasion",
        "检测并规避虚拟化与沙箱环境", ["Defense Evasion", "Discovery"]),
    "T1548": AttackTechnique("T1548", "Abuse Elevation Control Mechanism",
        "滥用权限提升控制机制", ["Privilege Escalation", "Defense Evasion"]),
}


# 漏洞类型 → ATT&CK 技术映射核心表
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
    "deserialization": "T1059",
    "path_traversal": "T1190",
    "ssrf": "T1190",
    "xxe": "T1190",
    "supply_chain": "T1195",
    "container_escape": "T1610",
    "sandbox_evasion": "T1497",
    "uac_bypass": "T1548",
    "stack_overflow": "T1055",
    "integer_overflow": "T1055",
    "race_condition": "T1068",
    "double_free": "T1055",
    "null_pointer_deref": "T1592",
    "out_of_bounds_read": "T1592",
    "out_of_bounds_write": "T1055",
    "type_confusion": "T1055",
    "jit_spray": "T1055",
    "rop_chain": "T1055",
}


# CWE → ATT&CK 映射 (15+ CWEs)
_CWE_TO_TECHNIQUE = {
    787: "T1055",   # Out-of-bounds Write
    125: "T1592",   # Out-of-bounds Read
    416: "T1055",   # Use After Free
    122: "T1203",   # Heap Buffer Overflow
    190: "T1055",   # Integer Overflow
    476: "T1592",   # NULL Pointer Dereference
    77:  "T1059",   # Command Injection
    78:  "T1059",   # OS Command Injection
    89:  "T1190",   # SQL Injection
    94:  "T1059",   # Code Injection
    119: "T1055",   # Buffer Overflow
    120: "T1055",   # Buffer Copy without Size Check
    134: "T1055",   # Format String
    20:  "T1190",   # Improper Input Validation
    22:  "T1190",   # Path Traversal
    502: "T1059",   # Deserialization
    918: "T1190",   # SSRF
    611: "T1190",   # XXE
    362: "T1068",   # Race Condition
    415: "T1055",   # Double Free
}


# //// 技术链: 上下游推导关系 ////
_TECHNIQUE_CHAIN: Dict[str, Tuple[List[str], List[str]]] = {
    "T1055": (["T1592"], ["T1068"]),          # Info gathering → injection → escalation
    "T1190": (["T1592"], ["T1059"]),           # Recon → exploit → command execution
    "T1203": (["T1195"], ["T1055"]),           # Supply chain → client exploit → injection
    "T1068": (["T1055", "T1203"], ["T1548"]),  # Injection → escalation → UAC bypass
    "T1059": (["T1190"], ["T1068"]),           # Exploit → scripting → escalation
    "T1195": ([], ["T1203", "T1610"]),         # Supply chain起点 → client exploit / container
    "T1610": (["T1195"], ["T1612"]),           # Deploy → build on host
    "T1497": (["T1190"], ["T1055"]),           # Sandbox evasion enables injection
    "T1548": (["T1068"], []),                  # Escalation终止 — 提权后控制
    "T1499": ([], []),
    "T1592": ([], ["T1190", "T1055"]),
    "T1612": (["T1610"], ["T1055"]),
}


def _tokenize(s: str) -> set:
    """将下划线/连字符分隔的字符串分解为 token 集合"""
    import re
    return set(re.split(r'[_\-\s]+', s.lower()))


def _jaccard_score(set_a: set, set_b: set) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


# //// 三级级联模糊匹配 ////
def _resolve_technique_id(vuln_type: str, cwe_id=None) -> str:
    """核心查找 — 精确 → 子串 → Token Jaccard → CWE → 启发式 → 默认"""
    lookup = vuln_type.lower().strip() if vuln_type else ""

    # 第1层: 精确匹配
    for key in _VULN_MAP:
        if lookup == key.lower():
            return _VULN_MAP[key]

    # 第2层: 子串匹配 (关键词在漏洞类型中出现)
    for key in _VULN_MAP:
        keywords = key.replace('_', ' ')
        for w in keywords.split():
            if len(w) > 2 and w in lookup:
                return _VULN_MAP[key]

    # 第3层: Token 级 Jaccard 匹配
    lookup_tokens = _tokenize(lookup)
    best_tid, best_score = "T1203", 0.0
    for key in _VULN_MAP:
        score = _jaccard_score(lookup_tokens, _tokenize(key))
        if score > best_score:
            best_score = score
            best_tid = _VULN_MAP[key]
    if best_score > 0.3:
        return best_tid

    # 第4层: CWE 查找
    if cwe_id is not None:
        cwe_num = None
        try:
            cwe_str = str(cwe_id).replace('CWE-', '').replace('cwe-', '')
            cwe_num = int(cwe_str)
        except (ValueError, TypeError):
            pass
        if cwe_num is not None and cwe_num in _CWE_TO_TECHNIQUE:
            return _CWE_TO_TECHNIQUE[cwe_num]

    # 第5层: 启发式回退
    if "stack" in lookup and "buffer" in lookup:
        return "T1055"
    if "heap" in lookup:
        return "T1203"
    if "overflow" in lookup:
        return "T1190"
    if "injection" in lookup or "inject" in lookup:
        return "T1059"
    if "disclosure" in lookup or "leak" in lookup or "exposure" in lookup:
        return "T1592"
    if "chain" in lookup or "supply" in lookup:
        return "T1195"
    if "container" in lookup or "escape" in lookup:
        return "T1610"
    if "sandbox" in lookup or "virtual" in lookup:
        return "T1497"
    if "uac" in lookup or "elevat" in lookup:
        return "T1548"

    return "T1203"


def _match_with_confidence(vuln_type: str, cwe_id=None, cvss_score: float = 0.0) -> TechniqueMatch:
    """带置信度的技术匹配 — CVSS 越高，置信度权重越大"""
    tid = _resolve_technique_id(vuln_type, cwe_id)
    technique = _TECH_DB.get(tid, _TECH_DB["T1203"])

    # 匹配方法判定
    lookup = vuln_type.lower().strip()
    match_method = "token"
    for key in _VULN_MAP:
        if lookup == key.lower():
            match_method = "exact"
            break
    else:
        for key in _VULN_MAP:
            for w in key.replace('_', ' ').split():
                if len(w) > 2 and w in lookup:
                    match_method = "substring"
                    break
            if match_method == "substring":
                break

    # 置信度计算: 基础 + CWE 加成 + CVSS 加成
    base_conf = {"exact": 0.92, "substring": 0.78, "token": 0.55}.get(match_method, 0.50)
    if cwe_id is not None:
        base_conf = min(0.98, base_conf + 0.08)
    if cvss_score > 0:
        base_conf = min(0.99, base_conf + (cvss_score / 10.0) * 0.15)

    # 匹配到的 token
    matched_tokens = [w for w in _tokenize(lookup)
                      if any(w in _tokenize(k) or k in w for k in _VULN_MAP)][:5]

    return TechniqueMatch(
        technique=technique,
        confidence=round(base_conf, 3),
        match_method=match_method,
        matched_tokens=matched_tokens,
    )


# AttackMapper
class AttackMapper:
    """漏洞→ATT&CK 映射器 — 核心入口"""

    def __init__(self, custom_mapping_file=None):
        self.custom_mapping_file = custom_mapping_file
        self.techniques = dict(_TECH_DB)
        self.mappings: Dict[str, AttackMapping] = {}
        self.vulnerability_mapping: Dict[str, AttackMapping] = {}
        # 自定义映射记录 (vuln_type -> 完整映射配置)
        self.custom_mappings: Dict[str, dict] = {}
        # 加载自定义映射文件 (JSON: {"vuln_type": "TXXXX"} 或 {"vuln_type": {...}})
        if custom_mapping_file:
            self._load_custom_mappings(custom_mapping_file)

    def _load_custom_mappings(self, filepath):
        import json, os
        if os.path.isfile(filepath):
            with open(filepath, 'r', encoding='utf-8') as fh:
                custom = json.load(fh)
            for k, v in custom.items():
                if isinstance(v, dict):
                    # 完整映射配置: {"vuln_type": {"primary_technique": "TXXXX", ...}}
                    self.custom_mappings[k] = v
                    prim = v.get("primary_technique") or v.get("technique_id")
                    if isinstance(prim, str):
                        _VULN_MAP[k] = prim
                else:
                    _VULN_MAP[k] = v

    def map_vulnerability(self, vuln_type="", context=None, cwe_id=None,
                          impact_type=None, target_type=None, cvss=None, **kwargs):
        lookup = impact_type if impact_type else vuln_type
        if lookup is None:
            lookup = ""
        vt_lower = lookup.lower()
        cvss_val = float(cvss) if cvss else 0.0

        match = _match_with_confidence(vt_lower, cwe_id, cvss_val)
        tid = match.technique.technique_id

        # 自定义映射优先
        custom = self.custom_mappings.get(vuln_type)
        if custom:
            prim_id = custom.get("primary_technique") or tid
            pri = _TECH_DB.get(prim_id, _TECH_DB.get(tid, _TECH_DB["T1203"]))
            sec_ids = custom.get("secondary_techniques") or []
            sec = [_TECH_DB.get(s, _TECH_DB["T1203"]) for s in sec_ids]
            if not sec:
                sec = [t for k, t in _TECH_DB.items() if k != pri.technique_id][:2]
        else:
            pri = _TECH_DB.get(tid, _TECH_DB["T1203"])
            sec = [t for k, t in _TECH_DB.items() if k != tid][:2]

        conf = match.confidence
        if cwe_id:
            conf = min(0.99, conf + 0.04)
        elif impact_type:
            conf = min(0.95, conf + 0.02)

        m = AttackMapping(
            vulnerability_type=vuln_type,
            primary_technique=pri,
            secondary_techniques=sec,
            mapped_techniques=[pri] + sec,
            confidence=round(conf, 3),
            impact_type=impact_type or "",
            target_type=target_type or "",
            reasoning=f"matched via {match.match_method}, tokens: {match.matched_tokens}",
        )
        self.mappings[vuln_type] = m
        return m

    def map_vulnerabilities(self, vulns):
        results = []
        for v in (vulns or []):
            vt = v.get('vulnerability_type', v.get('type', ''))
            cwe = v.get('cwe_id', v.get('cwe'))
            cvss = v.get('cvss_score', v.get('cvss'))
            m = self.map_vulnerability(vt, cwe_id=cwe, cvss=cvss)
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
        tactic_lower = tactic.lower() if isinstance(tactic, str) else str(tactic)
        results = []
        for t in _TECH_DB.values():
            if any(tactic_lower in tac.lower() for tac in t.tactics):
                results.append(t)
        return results

    def get_mitigations(self, technique):
        mitigations_base = {
            "T1055": ["Control Flow Guard", "Process signature verification"],
            "T1190": ["Regular patching", "WAF deployment", "Input validation"],
            "T1203": ["Application whitelisting", "Email filtering"],
            "T1068": ["Least privilege", "Kernel exploit protection"],
            "T1059": ["PowerShell constrained language", "AppLocker"],
            "T1499": ["Rate limiting", "Traffic filtering"],
            "T1592": ["Host-based firewall", "Minimize exposed information"],
            "T1195": ["SBOM verification", "Dependency pinning"],
            "T1610": ["Image signing", "Admission control"],
            "T1497": ["Timing attack defense", "Hardware-backed attestation"],
            "T1548": ["UAC at highest level", "Admin approval mode"],
        }
        tid = technique.technique_id if hasattr(technique, 'technique_id') else str(technique)
        return mitigations_base.get(tid, ["Input validation", "Least privilege"])

    # //// 技术链推导 ////
    def get_technique_chain(self, technique_id: str) -> dict:
        upstream, downstream = _TECHNIQUE_CHAIN.get(technique_id, ([], []))
        return {
            "technique_id": technique_id,
            "technique": _TECH_DB.get(technique_id),
            "upstream": [_TECH_DB.get(t) for t in upstream if t in _TECH_DB],
            "downstream": [_TECH_DB.get(t) for t in downstream if t in _TECH_DB],
        }

    # //// ATT&CK Navigator 图层导出 ////
    def export_attack_navigator(self):
        return {"name": "layer", "techniques": []}

    def export_attack_navigator_layer(self, name: str = "BinMind Layer") -> dict:
        """导出为 ATT&CK Navigator v4.3 兼容 JSON 图层格式"""
        techniques_list = []
        for tid, tech in _TECH_DB.items():
            for tactic in tech.tactics:
                techniques_list.append({
                    "techniqueID": tid,
                    "tactic": tactic.lower().replace(" ", "-"),
                    "color": "#e60d0d",
                    "comment": tech.description,
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False,
                })

        return {
            "name": name,
            "versions": {
                "layer": "4.3",
                "attack": "15",
                "navigator": "4.9.1",
            },
            "domain": "enterprise-attack",
            "description": f"MITRE ATT&CK 图层自动生成 — {name}",
            "filters": {"platforms": ["Windows", "Linux", "macOS"]},
            "sorting": 0,
            "layout": {
                "layout": "flat",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ffffff", "#e60d0d"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"color": "#e60d0d", "label": "Active technique mapping"},
            ],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

    def export_all_layers(self, output_path: str = None) -> dict:
        """为 Tactical / Compliance / Risk 三个视角各生成一个图层"""
        layer_types = {
            "tactical": "#e60d0d",
            "compliance": "#2b5f8a",
            "risk": "#d4a017",
        }
        layers = {}
        for ltype, color in layer_types.items():
            layer = self.export_attack_navigator_layer(f"BinMind - {ltype}")
            for t in layer["techniques"]:
                t["color"] = color
            layers[ltype] = layer
        return layers

ATTACKMapper = AttackMapper


# 顶层便捷函数
def map_vulnerability_to_attack(vuln):
    mapper = AttackMapper()
    if isinstance(vuln, dict):
        return mapper.map_vulnerability(**vuln)
    return mapper.map_vulnerability(str(vuln))


def map_vulnerabilities_to_attack(vulns):
    mapper = AttackMapper()
    return mapper.map_vulnerabilities(vulns)
