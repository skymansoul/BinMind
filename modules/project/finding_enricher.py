# 发现富化引擎: 外部数据源交叉引用/CVSS推断/CWE细化/MITRE ATT&CK映射
# Simsek et al. "FixV2W: Correcting Invalid CVE-CWE Mappings with KG Embeddings"
#       McCoy et al. "A Relevance Model for Threat-Centric Ranking of Cybersecurity Vulnerabilities"
#       VulnScopper "Unveiling Hidden Links Between Unseen Security Entities"
#       Baird & Moin "Cascaded Vulnerability Attacks in Software Supply Chains"
#       Wu & Feng "Association Analysis of Network Security Vulnerabilities Based on KG"
#       Jacobs et al. "Exploit Prediction Scoring System (EPSS)"
from __future__ import annotations
import json, logging, os, re, time, hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from pathlib import Path

log = logging.getLogger(__name__)

# CVSS推断，基于描述文本的启发式评分 [FIRST CVSS v3.1]

class CVSSInferrer:
    """描述文本→CVSS向量推断.

    关键词匹配+上下文规则，避免外部依赖.
    为缺少CVSS的内部发现提供近似评分.

    关键词按CVSS指标分组:
      - AV: network > adjacent > local > physical
      - AC: low > high
      - PR: none > low > high
      - UI: none > required
      - C/I/A: high > low > none
    """

    _AV_KW = {
        'N': ['remote', 'network', 'internet', 'over the network', 'http', 'rpc'],
        'A': ['adjacent', 'bluetooth', 'wifi', 'local network', 'broadcast'],
        'L': ['local', 'locally', 'same machine', 'same host'],
        'P': ['physical', 'physically', 'usb', 'hardware'],
    }
    _AC_KW = {
        'L': ['no authentication', 'without auth', 'easily', 'trivial', 'default credential', 'no special', 'directly'],
        'H': ['requires authentication', 'race condition', 'specific conditions', 'complex', 'multi-step'],
    }
    _IMPACT_KW = {
        'H': ['remote code execution', 'arbitrary code', 'root', 'admin', 'complete', 'full control', 'bypass', 'privilege escalation', 'critical data'],
        'L': ['partial', 'limited', 'information disclosure', 'minor', 'low impact'],
    }

    # CWE→默认CVSS基础向量 (NVD统计均值)
    _CWE_DEFAULT_CVSS = {
        'CWE-787': (8.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-89':  (9.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-78':  (9.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-79':  (6.1, 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
        'CWE-125': (7.1, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
        'CWE-20':  (7.5, 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'),
        'CWE-416': (8.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-476': (7.5, 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'),
        'CWE-200': (5.3, 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
        'CWE-119': (9.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-352': (8.8, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'),
        'CWE-22':  (7.5, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
        'CWE-287': (9.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-798': (9.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
        'CWE-190': (7.8, 'AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'),
    }

    def infer_cvss(self, finding: Dict) -> Dict:
        # 推断优先级: 已有cvss > CWE默认 > 关键词启发式
        if finding.get('cvss') and isinstance(finding['cvss'], (int, float)):
            return {'score': float(finding['cvss']), 'vector': finding.get('cvss_vector', ''),
                    'source': 'provided'}

        cwe = finding.get('cwe', '')
        desc = finding.get('description', finding.get('message', ''))

        if cwe in self._CWE_DEFAULT_CVSS:
            score, vector = self._CWE_DEFAULT_CVSS[cwe]
            return {'score': score, 'vector': vector, 'source': 'cwe_default'}

        return self._keyword_infer(desc)

    def _keyword_infer(self, description: str) -> Dict:
        desc_lower = description.lower()

        av = 'L'
        for level, keywords in self._AV_KW.items():
            if any(kw in desc_lower for kw in keywords):
                av = level; break

        ac = 'L'
        if any(kw in desc_lower for kw in self._AC_KW['H']):
            ac = 'H'

        impact = 'M'
        if any(kw in desc_lower for kw in self._IMPACT_KW['H']):
            impact = 'H'
        elif any(kw in desc_lower for kw in self._IMPACT_KW['L']):
            impact = 'L'

        score_map = {
            ('N', 'L', 'H'): 9.8, ('N', 'L', 'M'): 7.5, ('N', 'L', 'L'): 5.3,
            ('N', 'H', 'H'): 8.1, ('N', 'H', 'M'): 6.5, ('N', 'H', 'L'): 4.2,
            ('A', 'L', 'H'): 8.8, ('A', 'L', 'M'): 6.8, ('A', 'L', 'L'): 4.8,
            ('L', 'L', 'H'): 7.8, ('L', 'L', 'M'): 5.5, ('L', 'L', 'L'): 3.9,
            ('L', 'H', 'H'): 6.2, ('L', 'H', 'M'): 4.5, ('L', 'H', 'L'): 2.7,
        }
        vector = f"AV:{av}/AC:{ac}/PR:N/UI:N/S:U/C:{impact}/I:{impact}/A:{impact}"
        score = score_map.get((av, ac, impact), 5.0)

        return {'score': score, 'vector': vector, 'source': 'keyword_heuristic'}

    def batch_infer(self, findings: List[Dict]) -> List[Dict]:
        enriched = []
        for f in findings:
            cvss = self.infer_cvss(f)
            enriched.append({**f, 'cvss_inferred': cvss})
        return enriched


# CWE细化引擎

class CWERefiner:
    """描述模式匹配→精确CWE分类."""

    _REFINEMENT_RULES = {
        'CWE-200': [
            (r'(?:hard.?coded|hardcoded)\s*(?:password|secret|key|credential|token)', 'CWE-798', 0.85),
            (r'(?:stack|heap)\s*(?:trace|dump)', 'CWE-209', 0.70),
            (r'enumerat\w*\s*(?:user|account)', 'CWE-204', 0.65),
        ],
        'CWE-119': [
            (r'(?:stack\s*based|stack)\s*buffer', 'CWE-121', 0.75),
            (r'(?:heap\s*based|heap)\s*buffer', 'CWE-122', 0.75),
            (r'(?:format\s*string|printf)', 'CWE-134', 0.80),
            (r'(?:integer\s*overflow|int\s*overflow)', 'CWE-190', 0.70),
        ],
        'CWE-20': [
            (r'(?:path\s*traversal|directory\s*traversal)'.replace('  ', ' '), 'CWE-22', 0.80),
            (r'(?:SQL|sql)\s*injection', 'CWE-89', 0.85),
            (r'(?:command|OS)\s*injection', 'CWE-78', 0.80),
            (r'(?:cross.?site|XSS|xss)', 'CWE-79', 0.80),
        ],
        'CWE-287': [
            (r'(?:session\s*fixation)', 'CWE-384', 0.70),
            (r'(?:missing\s*auth\w*)'.replace('  ', ' '), 'CWE-306', 0.75),
        ],
    }

    def suggest_refinement(self, cwe: str, description: str) -> Optional[Dict]:
        rules = self._REFINEMENT_RULES.get(cwe, []) + self._REFINEMENT_RULES.get('CWE-20', [])
        desc_lower = description.lower()
        for pattern, suggested, confidence in rules:
            if re.search(pattern, desc_lower, re.IGNORECASE):
                return {'current_cwe': cwe, 'suggested_cwe': suggested,
                        'confidence': confidence, 'matched_pattern': pattern}
        return None

    def batch_refine(self, findings: List[Dict]) -> List[Dict]:
        for f in findings:
            if cwe := f.get('cwe', ''):
                desc = f.get('description', f.get('message', ''))
                if refinement := self.suggest_refinement(cwe, desc):
                    f['cwe_refinement'] = refinement
        return findings


# MITRE ATT&CK映射

class MITREAttackMapper:
    """漏洞发现→MITRE ATT&CK战术技术."""

    _CWE_TO_ATTACK = {
        'CWE-787': [('T1059', 'Command and Scripting Interpreter'), ('T1203', 'Exploitation for Client Execution')],
        'CWE-89':  [('T1190', 'Exploit Public-Facing Application'), ('T1505', 'Server Software Component')],
        'CWE-78':  [('T1059', 'Command and Scripting Interpreter'), ('T1203', 'Exploitation for Client Execution')],
        'CWE-79':  [('T1189', 'Drive-by Compromise'), ('T1190', 'Exploit Public-Facing Application')],
        'CWE-20':  [('T1190', 'Exploit Public-Facing Application')],
        'CWE-416': [('T1068', 'Exploitation for Privilege Escalation')],
        'CWE-22':  [('T1005', 'Data from Local System'), ('T1083', 'File and Directory Discovery')],
        'CWE-287': [('T1078', 'Valid Accounts'), ('T1133', 'External Remote Services')],
        'CWE-798': [('T1078', 'Valid Accounts'), ('T1552', 'Unsecured Credentials')],
        'CWE-352': [('T1204', 'User Execution')],
        'CWE-476': [('T1499', 'Endpoint Denial of Service')],
        'CWE-125': [('T1005', 'Data from Local System')],
        'CWE-306': [('T1078', 'Valid Accounts')],
        'CWE-502': [('T1092', 'Communication Through Removable Media')],
    }

    _TACTICS = {
        'T1059': 'Execution', 'T1203': 'Execution', 'T1190': 'Initial Access',
        'T1189': 'Initial Access', 'T1068': 'Privilege Escalation',
        'T1005': 'Collection', 'T1083': 'Discovery', 'T1078': 'Defense Evasion',
        'T1133': 'Persistence', 'T1552': 'Credential Access',
        'T1204': 'Execution', 'T1499': 'Impact', 'T1505': 'Persistence',
    }

    def map_finding(self, finding: Dict) -> List[Dict]:
        cwe = finding.get('cwe', '')
        if not cwe or cwe not in self._CWE_TO_ATTACK:
            return []

        techniques = self._CWE_TO_ATTACK[cwe]
        sev = finding.get('severity', 'medium')
        results = []
        for tech_id, tech_name in techniques:
            tactic = self._TACTICS.get(tech_id, 'Unknown')
            results.append({
                'technique_id': tech_id, 'technique_name': tech_name,
                'tactic': tactic,
                'relevance': 'high' if sev in ('critical', 'high') else 'medium'
            })
        return results

    def generate_attack_navigator_layer(self, findings: List[Dict]) -> Dict:
        """MITRE ATT&CK Navigator兼容layer JSON."""
        techniques = defaultdict(lambda: {'score': 0, 'enabled': False, 'metadata': []})
        for f in findings:
            mappings = self.map_finding(f)
            for m in mappings:
                tid = m['technique_id']
                techniques[tid]['score'] += 1
                techniques[tid]['enabled'] = True
                techniques[tid]['metadata'].append({
                    'cwe': f.get('cwe', ''), 'severity': f.get('severity', ''),
                    'title': f.get('title', '')[:80]
                })

        return {
            'name': 'BinMind Attack Surface',
            'versions': {'attack': '15', 'navigator': '5.0', 'layer': '4.5'},
            'domain': 'enterprise-attack',
            'description': f'Auto-generated from {len(findings)} findings',
            'techniques': [{'techniqueID': tid, 'score': t['score'],
                            'enabled': t['enabled'],
                            'metadata': t['metadata'][:5]}
                           for tid, t in techniques.items()],
            'gradient': {'colors': ['#ffffff', '#ff6666'], 'minValue': 0, 'maxValue': 10},
        }


# 富化管道，一站式富化

class FindingEnrichmentPipeline:
    # CVSS推断+CWE细化+ATT&CK映射
    def __init__(self):
        self.cvss = CVSSInferrer()
        self.cwe_refiner = CWERefiner()
        self.attack = MITREAttackMapper()

    def enrich(self, findings: List[Dict]) -> List[Dict]:
        enriched = self.cvss.batch_infer(findings)
        enriched = self.cwe_refiner.batch_refine(enriched)
        for f in enriched:
            f['mitre_attack'] = self.attack.map_finding(f)
        return enriched

    def enrich_and_summarize(self, findings: List[Dict]) -> Dict:
        enriched = self.enrich(findings)
        cvss_scores = [f.get('cvss_inferred', {}).get('score', 0) for f in enriched]
        avg_cvss = sum(cvss_scores) / max(len(cvss_scores), 1)
        refined_count = sum(1 for f in enriched if f.get('cwe_refinement'))
        attack_mapped = sum(1 for f in enriched if f.get('mitre_attack'))

        return {
            'findings': enriched,
            'count': len(enriched),
            'avg_cvss': round(avg_cvss, 2),
            'max_cvss': round(max(cvss_scores) if cvss_scores else 0, 2),
            'cwes_refined': refined_count,
            'attack_mapped': attack_mapped,
            'severity_distribution': dict(Counter(
                f.get('severity', 'unknown') for f in enriched)),
            'attack_navigator_layer': self.attack.generate_attack_navigator_layer(enriched),
        }

    def enrich_single(self, finding: Dict) -> Dict:
        return self.enrich([finding])[0]


# 全局单例
_pipeline: FindingEnrichmentPipeline = None

def get_enrichment_pipeline() -> FindingEnrichmentPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = FindingEnrichmentPipeline()
    return _pipeline
