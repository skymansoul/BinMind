#!/usr/bin/env python3
import logging
import os
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


from enum import StrEnum as _StrEnum

class CVSSSeverity(_StrEnum):
    CRITICAL = 'Critical'
    HIGH     = 'High'
    MEDIUM   = 'Medium'
    LOW      = 'Low'
    INFO     = 'Info'


class CVEStatus(_StrEnum):
    DRAFT     = 'Draft'
    SUBMITTED = 'Submitted'
    ASSIGNED  = 'Assigned'
    PUBLISHED = 'Published'
    REJECTED  = 'Rejected'


@dataclass
class VulnerabilityDetail:
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None
    title: str = ''
    desc: str = ''
    products: List[str] = field(default_factory=list)
    versions: List[str] = field(default_factory=list)
    av: str = 'NETWORK'
    ac: str = 'LOW'
    pr: str = 'NONE'
    ui: str = 'NONE'
    scope: str = 'UNCHANGED'
    conf: str = 'NONE'
    integ: str = 'NONE'
    avail: str = 'NONE'


class CVEReporter:

    _AV_WEIGHTS = {'NETWORK': 0.85, 'ADJACENT': 0.62, 'LOCAL': 0.55, 'PHYSICAL': 0.2}
    _AC_WEIGHTS = {'LOW': 0.77, 'HIGH': 0.44}
    _PR_WEIGHTS = {'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27}
    _UI_WEIGHTS = {'NONE': 0.85, 'REQUIRED': 0.62}
    _S_WEIGHTS  = {'UNCHANGED': 6.42, 'CHANGED': 7.52}
    _CI_WEIGHTS = {'NONE': 0.0, 'LOW': 0.22, 'HIGH': 0.56}

    def __init__(self):
        self.__key = os.environ.get('CVE_API_KEY', '')
        self.__url = os.environ.get('CVE_API_URL', 'https://cveawg.mitre.org/api')

    def calc_cvss(self, detail):
        if detail is None:
            return 0.0
        av = self._AV_WEIGHTS.get(detail.av.upper(), 0.85)
        ac = self._AC_WEIGHTS.get(detail.ac.upper(), 0.77)
        pr = self._PR_WEIGHTS.get(detail.pr.upper(), 0.85)
        ui = self._UI_WEIGHTS.get(detail.ui.upper(), 0.85)
        s  = self._S_WEIGHTS.get(detail.scope.upper(), 6.42)
        c  = self._CI_WEIGHTS.get(detail.conf.upper(), 0.56)
        i  = self._CI_WEIGHTS.get(detail.integ.upper(), 0.56)
        a  = self._CI_WEIGHTS.get(detail.avail.upper(), 0.56)
        base = s * (8.22 * av * ac * pr * ui + (c + i + a))
        if base > 10.0:
            base = 10.0
        return round(base, 1)

    def severity(self, score):
        if score is None:
            return CVSSSeverity.INFO
        if score >= 9.0:
            return CVSSSeverity.CRITICAL
        if score >= 7.0:
            return CVSSSeverity.HIGH
        if score >= 4.0:
            return CVSSSeverity.MEDIUM
        if score >= 0.1:
            return CVSSSeverity.LOW
        return CVSSSeverity.INFO

    def validate(self, detail):
        if detail is None:
            return ['details is None']
        checks = [
            (detail.title, 'Title required'),
            (detail.desc,  'Description required'),
            (detail.cwe_id, 'CWE ID required'),
            (detail.av,    'Attack vector required'),
        ]
        out = []
        for val, msg in checks:
            if not val:
                out.append(msg)
        return out

    def _sev_str(self, detail):
        if detail is None or detail.severity is None:
            return 'Not evaluated'
        return str(detail.severity)

    def _score_str(self, detail):
        if detail is None or detail.cvss_score is None:
            return 'Not evaluated'
        return str(detail.cvss_score)

    def short_rpt(self, detail):
        lines = [
            'Vulnerability Report',
            f"ID: {detail.cve_id or 'Not assigned'}",
            f"Title: {detail.title}",
            f"Severity: {self._sev_str(detail)}",
            f"CVSS: {self._score_str(detail)}",
            f"CWE: {detail.cwe_id or ''}",
            '',
            f"Description: {detail.desc}",
        ]
        return '\n'.join(lines)

    def full_rpt(self, detail):
        prods = ', '.join(detail.products) if detail.products else 'Not specified'
        vers  = ', '.join(detail.versions) if detail.versions else 'Not specified'
        lines = [
            'Full Vulnerability Report',
            '=========================',
            '',
            '1. Basic Information',
            '--------------------',
            f"CVE ID: {detail.cve_id or 'Not assigned'}",
            f"Title: {detail.title}",
            f"Severity: {self._sev_str(detail)}",
            f"CVSS Score: {self._score_str(detail)}",
            f"CWE ID: {detail.cwe_id or 'Not specified'}",
            '',
            '2. Vulnerability Description',
            '---------------------------',
            detail.desc,
            '',
            '3. Affected Products',
            '--------------------',
            f"Products: {prods}",
            f"Versions: {vers}",
        ]
        return '\n'.join(lines)

    def cve_req(self, detail):
        prods = ', '.join(detail.products) if detail.products else 'TBD'
        vers  = ', '.join(detail.versions) if detail.versions else 'TBD'
        lines = [
            f"CVE Request: {detail.title}",
            '=================================',
            '',
            '[Basic Information]',
            f"Title: {detail.title}",
            f"CWE ID: {detail.cwe_id or 'Not specified'}",
            f"Severity: {self._sev_str(detail)}",
            f"CVSS Score: {self._score_str(detail)}",
            '',
            '[Vulnerability Description]',
            detail.desc,
            '',
            '[Affected Products]',
            f"- Products: {prods}",
            f"- Versions: {vers}",
        ]
        return '\n'.join(lines)

    def json_rpt(self, detail):
        data = {
            'cve_id': detail.cve_id,
            'title': detail.title,
            'description': detail.desc,
            'cwe_id': detail.cwe_id,
            'cvss_score': detail.cvss_score,
            'severity': str(detail.severity) if detail.severity else None,
            'affected_products': detail.products,
            'affected_versions': detail.versions,
            'generated_at': datetime.now().isoformat(),
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save(self, content, path):
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(content)
            return True
        except Exception as e:
            logger.error(f"save failed: {e}")
            return False


def _to_dict(detail):
    return {
        'cve_id': detail.cve_id, 'cwe_id': detail.cwe_id,
        'cvss_score': detail.cvss_score, 'cvss_vector': detail.cvss_vector,
        'severity': detail.severity, 'title': detail.title,
        'description': detail.desc,
        'affected_products': detail.products,
        'affected_versions': detail.versions,
        'attack_vector': detail.av, 'attack_complexity': detail.ac,
        'privileges_required': detail.pr, 'user_interaction': detail.ui,
        'scope': detail.scope,
        'confidentiality_impact': detail.conf,
        'integrity_impact': detail.integ,
        'availability_impact': detail.avail,
    }


def generate_cve_report(title, desc, cwe,
                        products=None, versions=None,
                        av='NETWORK', ac='LOW',
                        pr='NONE', ui='NONE',
                        scope='UNCHANGED', conf='NONE',
                        integ='NONE', avail='NONE'):
    r = CVEReporter()
    det = VulnerabilityDetail(
        title=title, desc=desc, cwe_id=cwe,
        products=products or [], versions=versions or [],
        av=av, ac=ac, pr=pr, ui=ui,
        scope=scope, conf=conf, integ=integ, avail=avail,
    )
    det.cvss_score = r.calc_cvss(det)
    det.severity = r.severity(det.cvss_score)
    return {
        'success': True,
        'cvss_score': det.cvss_score,
        'severity': str(det.severity),
        'reports': {
            'short': r.short_rpt(det),
            'full': r.full_rpt(det),
            'json': r.json_rpt(det),
            'cve_request': r.cve_req(det),
        },
        'details': _to_dict(det),
    }


# 兼容桥 — 为测试与旧调用方保留的字段/方法别名
# 旧接口字段名与重构后内部名不一致, 此处逐一映射。

VulnerabilityDetail.description = property(
    lambda s: s.desc, lambda s, v: setattr(s, 'desc', v))
VulnerabilityDetail.affected_products = property(
    lambda s: s.products, lambda s, v: setattr(s, 'products', v))
VulnerabilityDetail.affected_versions = property(
    lambda s: s.versions, lambda s, v: setattr(s, 'versions', v))
VulnerabilityDetail.attack_vector = property(
    lambda s: s.av, lambda s, v: setattr(s, 'av', v))
VulnerabilityDetail.attack_complexity = property(
    lambda s: s.ac, lambda s, v: setattr(s, 'ac', v))
VulnerabilityDetail.privileges_required = property(
    lambda s: s.pr, lambda s, v: setattr(s, 'pr', v))
VulnerabilityDetail.user_interaction = property(
    lambda s: s.ui, lambda s, v: setattr(s, 'ui', v))
VulnerabilityDetail.scope_impact = property(
    lambda s: s.scope, lambda s, v: setattr(s, 'scope', v))
VulnerabilityDetail.confidentiality_impact = property(
    lambda s: s.conf, lambda s, v: setattr(s, 'conf', v))
VulnerabilityDetail.integrity_impact = property(
    lambda s: s.integ, lambda s, v: setattr(s, 'integ', v))
VulnerabilityDetail.availability_impact = property(
    lambda s: s.avail, lambda s, v: setattr(s, 'avail', v))

# 构造参数兼容层: VulnerabilityDetail 内部使用缩写字段(ac/pr/ui/conf 等),
# 旧调用方按全称传入; 通过 _KWARG_MAP 将全称参数归一化到缩写字段,
# 使新旧两种参数名均可用, 避免破坏既有调用点。
_orig_init = VulnerabilityDetail.__init__

_KWARG_MAP = {
    'description': 'desc', 'affected_products': 'products',
    'affected_versions': 'versions', 'attack_vector': 'av',
    'attack_complexity': 'ac', 'privileges_required': 'pr',
    'user_interaction': 'ui', 'scope_impact': 'scope',
    'confidentiality_impact': 'conf', 'integrity_impact': 'integ',
    'availability_impact': 'avail',
}

def _compat_init(self, **kwargs):
    remapped = {_KWARG_MAP.get(k, k): v for k, v in kwargs.items()}
    _orig_init(self, **remapped)

VulnerabilityDetail.__init__ = _compat_init

CVEReporter.calculate_cvss_score = CVEReporter.calc_cvss
CVEReporter.determine_severity = CVEReporter.severity
CVEReporter.validate_details = CVEReporter.validate
CVEReporter.generate_short_report = CVEReporter.short_rpt
CVEReporter.generate_full_report = CVEReporter.full_rpt
CVEReporter.generate_cve_request = CVEReporter.cve_req
CVEReporter.generate_json_report = CVEReporter.json_rpt

_orig_save = CVEReporter.save

def _compat_save(self, content, path, fmt=None):
    return _orig_save(self, content, path)

CVEReporter.save_report = _compat_save

_orig_generate = generate_cve_report

def generate_cve_report(title, description=None, desc=None, cwe=None,
                        cwe_id=None, products=None, affected_products=None,
                        versions=None, affected_versions=None,
                        attack_vector='NETWORK', av=None,
                        attack_complexity='LOW', ac=None,
                        privileges_required='NONE', pr=None,
                        user_interaction='NONE', ui=None,
                        scope_impact='UNCHANGED', scope=None,
                        confidentiality_impact='NONE', conf=None,
                        integrity_impact='NONE', integ=None,
                        availability_impact='NONE', avail=None,
                        **kwargs):
    _desc = description or desc or ''
    _cwe = cwe or cwe_id or ''
    _prods = products or affected_products or []
    _vers = versions or affected_versions or []
    return _orig_generate(
        title=title,
        desc=_desc,
        cwe=_cwe,
        products=_prods, versions=_vers,
        av=av or attack_vector,
        ac=ac or attack_complexity,
        pr=pr or privileges_required,
        ui=ui or user_interaction,
        scope=scope or scope_impact,
        conf=conf or confidentiality_impact,
        integ=integ or integrity_impact,
        avail=avail or availability_impact,
    )
