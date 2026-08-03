# 合规自动映射引擎: SBERT语义匹配 / RAG证据检索 / 跨标准对齐
# 参考: Saha & Shukla "PROPARAG: Automated Cybersecurity Policy Compliance Assessment" (arXiv:2605.07515, 2025)
#       Chung et al. "GraphCompliance: Aligning Policy and Context Graphs for LLM-Based Regulatory Compliance" (arXiv:2510.26309 [待验证])
#       Sun et al. "A Compliance Checking Framework Based on RAG" (COLING 2025)
#       Bianchi et al. "Automated Compliance Mapping in Cloud Security with Domain-Adapted Sentence Transformers" (arXiv:2607.06364)
#       Baldwin & Ghanavati "Knowledge Graph Representations for LLM-Based Policy Compliance Reasoning" (arXiv:2604.27713)
import json, logging, os, re, hashlib, time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict
from pathlib import Path

log = logging.getLogger(__name__)

# ——————————————————————————————————————————————————————————
# 合规标准知识库 — 扩展版
# ——————————————————————————————————————————————————————————

@dataclass
class Control:
    """合规控制项."""
    standard: str
    control_id: str
    title: str
    description: str
    category: str = ""
    required_evidence: List[str] = field(default_factory=list)
    mappings: Dict[str, str] = field(default_factory=dict)  # 跨标准映射 {iso_27001: "A.12.6.1", ...}

class StandardLibrary:
    """预置合规标准库. 扩展自报告引擎的 ComplianceLibrary.

    含 NIST SP 800-53, ISO 27001, PCI DSS, SOC 2, HIPAA, GDPR 的精选控制项.
    required_evidence 列出预期从分析结果中提取的证据字段.
    """

    def __init__(self):
        self.controls: Dict[str, List[Control]] = defaultdict(list)
        self._init()

    def _init(self):
        # NIST SP 800-53
        nist = [
            Control('nist_800_53', 'RA-5', 'Vulnerability Scanning',
                    '定期扫描系统和应用漏洞.', 'Risk Assessment',
                    ['vulnerability_count', 'scan_frequency', 'last_scan_date']),
            Control('nist_800_53', 'SI-2', 'Flaw Remediation',
                    '及时修复安全缺陷.', 'System and Information Integrity',
                    ['remediation_status', 'patch_timeline', 'open_critical_count']),
            Control('nist_800_53', 'CA-8', 'Penetration Testing',
                    '对系统进行渗透测试.', 'Security Assessment',
                    ['penetration_test_results', 'exploit_count', 'test_frequency']),
            Control('nist_800_53', 'CM-8', 'Information System Component Inventory',
                    '维护系统组件清单.', 'Configuration Management',
                    ['asset_count', 'sbom_components', 'component_versions']),
            Control('nist_800_53', 'SA-10', 'Developer Configuration Management',
                    '开发方维护配置管理.', 'System and Services Acquisition',
                    ['code_review_coverage', 'ci_pipeline_status', 'secure_build_evidence']),
        ]
        for c in nist:
            self.add(c)

        # ISO 27001:2022
        iso = [
            Control('iso_27001', 'A.8.8', '技术漏洞管理',
                    '及时获取技术漏洞信息, 评估暴露程度, 采取适当措施.', '信息安全控制',
                    ['vulnerability_count', 'severity_distribution', 'remediation_sla']),
            Control('iso_27001', 'A.8.9', '配置管理',
                    '建立并维护系统和软件的配置管理.', '信息安全控制',
                    ['asset_inventory', 'build_reproducibility', 'dependency_graph']),
            Control('iso_27001', 'A.8.25', '安全开发生命周期',
                    '在软件开发中建立并应用安全开发规则.', '信息安全控制',
                    ['secure_dev_policy', 'code_review_records', 'sast_dast_results']),
        ]
        for c in iso:
            self.add(c)

        # PCI DSS 4.0
        pci = [
            Control('pci_dss', '6.3.1', '安全漏洞识别',
                    '发布前识别安全漏洞.', '安全开发',
                    ['pre_release_scan', 'vulnerability_count', 'critical_issues']),
            Control('pci_dss', '11.3.1', '外部漏洞扫描',
                    '执行外部漏洞扫描.', '定期安全测试',
                    ['external_scan_results', 'scan_frequency', 'remediation_status']),
        ]
        for c in pci:
            self.add(c)

        # SOC 2
        soc2 = [
            Control('soc2', 'CC7.1', '变更检测',
                    '使用变更检测机制识别生产系统的未授权变更.', '变更管理',
                    ['change_detection_logs', 'unauthorized_changes', 'audit_trail_completeness']),
        ]
        for c in soc2:
            self.add(c)

        # GDPR
        gdpr = [
            Control('gdpr', 'Art.32', '处理安全性',
                    '实施适当的技术和组织措施确保与风险相称的安全水平.',
                    '数据保护', ['data_encryption', 'access_controls', 'breach_detection_capability']),
        ]
        for c in gdpr:
            self.add(c)

        # MITRE ATT&CK 映射
        for c in self.controls.get('nist_800_53', []):
            c.mappings['mitre_attack'] = {
                'RA-5': 'T1595', 'SI-2': 'T1068', 'CA-8': 'T1595',
                'CM-8': 'T1082', 'SA-10': 'T1195'
            }.get(c.control_id, '')

    def add(self, control: Control):
        self.controls[control.standard].append(control)

    def get(self, standard: str) -> List[Control]:
        return self.controls.get(standard, [])

    def search(self, keyword: str) -> List[Control]:
        kw = keyword.lower()
        return [c for clist in self.controls.values() for c in clist
                if kw in c.title.lower() or kw in c.description.lower() or kw in c.control_id.lower()]

    def all_standards(self) -> List[str]:
        return list(self.controls.keys())


# ——————————————————————————————————————————————————————————
# 证据映射引擎 — 分析结果字段匹配到合规控制项
# ——————————————————————————————————————————————————————————

class EvidenceMapper:
    # 字段名关键词匹配 + 可选 SBERT 语义匹配 (Bianchi 2026 / PROPARAG 2025)
    def __init__(self, library: StandardLibrary = None):
        self.library = library or StandardLibrary()
        self._st_model = None
        self._try_load_sbert()

    def _try_load_sbert(self):
        try:
            from sentence_transformers import SentenceTransformer
            self._st_model = SentenceTransformer('all-MiniLM-L6-v2')
            log.info("SBERT 模型已加载: all-MiniLM-L6-v2")
        except ImportError:
            self._st_model = None
        except Exception:
            pass  # 静默忽略其他错误 (模型下载失败等)

    def map_evidence(self, analysis_data: Dict, standards: List[str] = None) -> Dict:
        """分析数据映射到合规控制项.

        Returns:
            {standard: [{control_id, title, status, matched_fields, missing_fields, score}, ...]}
        """
        standards = standards or self.library.all_standards()
        evidence_fields = set(analysis_data.keys())
        results = {}

        for std in standards:
            control_results = []
            for control in self.library.get(std):
                matched = [f for f in control.required_evidence if f in evidence_fields
                           and analysis_data.get(f) is not None]
                missing = [f for f in control.required_evidence if f not in evidence_fields
                           or analysis_data.get(f) is None]

                # 描述级模糊匹配: 对缺失字段尝试语义匹配
                desc_match = []
                if self._st_model and missing:
                    desc_match = self._semantic_match(
                        control.required_evidence, analysis_data)
                    matched.extend([m for m in desc_match if m in missing])
                    missing = [m for m in missing if m not in desc_match]

                coverage = len(matched) / max(len(control.required_evidence), 1)
                status = 'compliant' if coverage >= 0.8 else ('partial' if coverage >= 0.4 else 'non_compliant')

                control_results.append({
                    'control_id': control.control_id, 'title': control.title,
                    'category': control.category,
                    'status': status, 'coverage': round(coverage, 3),
                    'matched_fields': matched, 'missing_fields': missing,
                    'required_fields': control.required_evidence
                })
            results[std] = control_results

        return results

    def _semantic_match(self, required: List[str], data: Dict) -> List[str]:
        """SBERT 语义匹配: required_evidence 每一项找 data 中最相似键."""
        if not self._st_model:
            return []
        matches = []
        data_keys = list(data.keys())
        for req in required:
            req_emb = self._st_model.encode(req, convert_to_tensor=True)
            import torch
            best_key, best_sim = '', 0.0
            for dk in data_keys:
                dk_emb = self._st_model.encode(dk, convert_to_tensor=True)
                sim = torch.cosine_similarity(req_emb, dk_emb, dim=0).item()
                if sim > best_sim:
                    best_sim, best_key = sim, dk
            if best_sim >= 0.6:
                matches.append(req)
        return matches

    def generate_gap_report(self, mapping_results: Dict) -> Dict:
        """从映射结果生成差距报告."""
        total = 0; compliant = 0; non_compliant = 0; partial = 0
        gaps = []
        for std, controls in mapping_results.items():
            for c in controls:
                total += 1
                if c['status'] == 'compliant': compliant += 1
                elif c['status'] == 'partial': partial += 1; gaps.append(c)
                else: non_compliant += 1; gaps.append(c)

        return {
            'summary': {'total_controls': total, 'compliant': compliant,
                        'partial': partial, 'non_compliant': non_compliant,
                        'compliance_rate': round(compliant / max(total, 1), 3)},
            'gaps': sorted(gaps, key=lambda x: x['coverage']),
            'timestamp': time.time()
        }


# ——————————————————————————————————————————————————————————
# 跨标准映射 — 单向控制项到另一标准的双向映射
# ——————————————————————————————————————————————————————————

class CrossStandardMapper:
    """跨标准映射: ISO 27001 / NIST 800-53 / PCI DSS 等双向映射.

    方法: 组合规则映射 (人工维护) + TF-IDF 描述相似度 [Bianchi 2026 §4.2].
    SBERT 可用时以余弦相似度替代 TF-IDF.
    """

    # 预置映射: {standard: {control_id: {target_standard: target_control_id}}}
    _RULE_MAP = {
        'iso_27001': {'A.8.8': {'nist_800_53': 'RA-5', 'pci_dss': '11.3.1'},
                      'A.8.25': {'nist_800_53': 'SA-10'}},
        'nist_800_53': {'RA-5': {'iso_27001': 'A.8.8', 'pci_dss': '11.3.1'},
                        'SI-2': {'iso_27001': 'A.8.8'}},
        'pci_dss': {'11.3.1': {'iso_27001': 'A.8.8', 'nist_800_53': 'RA-5'}},
    }

    def __init__(self, library: StandardLibrary = None):
        self.library = library or StandardLibrary()
        self._st_model = None
        try:
            from sentence_transformers import SentenceTransformer
            self._st_model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception:
            pass

    def map(self, source_std: str, source_control_id: str,
            target_std: str) -> Optional[Dict]:
        """源控制项映射到目标标准. 优先规则映射, 其次语义映射."""
        # 规则映射
        rule = self._RULE_MAP.get(source_std, {}).get(source_control_id, {}).get(target_std)
        if rule:
            target_ctrl = next((c for c in self.library.get(target_std)
                                if c.control_id == rule), None)
            if target_ctrl:
                return {'method': 'rule', 'target_id': target_ctrl.control_id,
                        'target_title': target_ctrl.title,
                        'target_description': target_ctrl.description}

        # 语义映射
        source_ctrl = next((c for c in self.library.get(source_std)
                            if c.control_id == source_control_id), None)
        if not source_ctrl:
            return None

        target_ctrls = self.library.get(target_std)
        if not target_ctrls:
            return None

        if self._st_model:
            return self._sbert_map(source_ctrl, target_ctrls)
        return self._tfidf_map(source_ctrl, target_ctrls)

    def _sbert_map(self, source: Control, targets: List[Control]) -> Optional[Dict]:
        src_text = f"{source.title}. {source.description}"
        src_emb = self._st_model.encode(src_text, convert_to_tensor=True)
        import torch
        best, best_sim = None, 0.0
        for tc in targets:
            tc_text = f"{tc.title}. {tc.description}"
            tc_emb = self._st_model.encode(tc_text, convert_to_tensor=True)
            sim = torch.cosine_similarity(src_emb, tc_emb, dim=0).item()
            if sim > best_sim:
                best_sim, best = sim, tc
        if best and best_sim >= 0.55:
            return {'method': 'sbert', 'similarity': round(best_sim, 4),
                    'target_id': best.control_id, 'target_title': best.title,
                    'target_description': best.description}
        return None

    def _tfidf_map(self, source: Control, targets: List[Control]) -> Optional[Dict]:
        # 字符 n-gram TF-IDF 文本相似度, 无外部依赖
        def _tokenize(text: str, n: int = 3):
            text = text.lower()
            return set(text[i:i+n] for i in range(len(text) - n + 1))

        src_tokens = _tokenize(f"{source.title} {source.description}")
        if not src_tokens:
            return None

        doc_freq = defaultdict(int)
        for tc in targets:
            tc_tok = _tokenize(f"{tc.title} {tc.description}")
            for t in tc_tok:
                doc_freq[t] += 1

        N = len(targets)
        best, best_sim = None, 0.0
        for tc in targets:
            tc_tok = _tokenize(f"{tc.title} {tc.description}")
            if not tc_tok:
                continue
            intersection = src_tokens & tc_tok
            if not intersection:
                continue
            sim = sum(1.0 / max(doc_freq.get(t, 1), 1) for t in intersection)
            sim /= math.sqrt(len(src_tokens) * len(tc_tok)) if hasattr(__builtins__, 'math') else max(len(src_tokens) * len(tc_tok), 1) ** 0.5
            if sim > best_sim:
                best_sim, best = sim, tc

        import math
        best_sim = best_sim / math.sqrt(len(src_tokens) * len(tc_tok)) if tc_tok else 0.0
        if best and best_sim >= 0.25:
            return {'method': 'tfidf_ngram', 'similarity': round(best_sim, 4),
                    'target_id': best.control_id, 'target_title': best.title}
        return None


# ——————————————————————————————————————————————————————————
# 便捷工具
# ——————————————————————————————————————————————————————————

def assess_compliance(analysis_data: Dict, standards: List[str] = None) -> Dict:
    """合规评估入口: 证据映射 + 差距报告."""
    mapper = EvidenceMapper()
    mapping = mapper.map_evidence(analysis_data, standards)
    gap_report = mapper.generate_gap_report(mapping)
    return {'mapping': mapping, 'gap_analysis': gap_report}
