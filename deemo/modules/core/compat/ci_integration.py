# CI 集成 — 多平台检测、SARIF/JUnit/Markdown/JSON 报告、GitHub/GitLab 注解
import os
import json
import hashlib
import html
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# ===== CI 退出码映射 =====
CI_EXIT_CODE = {
    0: 'SUCCESS',
    1: 'ERROR',
    2: 'WARNING',
    3: 'CRITICAL',
}

class CIFindingSeverity(Enum):
    PASS = "pass"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

_SEVERITY_ORDER = ['pass', 'info', 'warning', 'error', 'critical']

@dataclass
class CIFinding:
    rule_id: str
    severity: CIFindingSeverity
    message: str
    file_path: str = ""
    line_number: int = 0
    finding_type: str = "vulnerability"

@dataclass
class CIConfig:
    fail_on_severity: str = "error"
    output_format: str = 'json'
    output_file: str = ""
    verbose: bool = False

# ===== CI 环境检测 =====
def detect_ci_environment() -> Optional[str]:
    """检测当前 CI 平台，返回平台名或 None"""
    env = os.environ
    checks = [
        ('GITHUB_ACTIONS', 'GitHub Actions'),
        ('JENKINS_HOME', 'Jenkins'),
        ('GITLAB_CI', 'GitLab CI'),
        ('TRAVIS', 'Travis CI'),
        ('CIRCLECI', 'CircleCI'),
        ('APPVEYOR', 'AppVeyor'),
        ('BITBUCKET_BUILD_NUMBER', 'Bitbucket Pipelines'),
    ]
    if env.get('CI', '').lower() == 'true':
        for key, name in checks:
            if key in env:
                return name
        return 'Unknown CI'
    return None

# ===== CI 集成类 =====
class CIIntegration:
    """SARIF v2.1.0 / JUnit XML / Markdown / JSON 多格式报告输出"""

    def __init__(self, config: Optional[CIConfig] = None):
        self.config = config or CIConfig()
        self.report_format: Optional[str] = None
        self.fail_on: Optional[str] = None
        self.ci_mode: bool = False
        self._env_name = detect_ci_environment()

    def set_report_format(self, fmt: str) -> bool:
        valid = {'sarif', 'junit', 'markdown', 'json'}
        if fmt in valid:
            self.report_format = fmt
            return True
        self.report_format = None
        return False

    def detect_ci_environment(self) -> Optional[str]:
        return detect_ci_environment()

    # ---- 报告生成 ----
    def generate_report(self, findings: list[CIFinding],
                        fmt: Optional[str] = None) -> Any:
        fmt = fmt or self.report_format or self.config.output_format

        if fmt == 'sarif':
            return self._format_sarif(findings)
        elif fmt == 'junit':
            return self._format_junit(findings)
        elif fmt == 'markdown':
            return self._format_markdown(findings)
        else:
            return self._format_json(findings)

    # //// SARIF v2.1.0 (OASIS 标准) ////
    def _format_sarif(self, findings: list[CIFinding]) -> dict:
        rules: dict[str, dict] = {}
        results = []

        for f in findings:
            rid = f.rule_id
            if rid not in rules:
                rules[rid] = self._build_sarif_rule(f)
            results.append(self._build_sarif_result(f, rid))

        return {
            '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': self._build_sarif_tool_info(),
                'results': results,
                'invocations': [{
                    'executionSuccessful': True,
                }],
            }],
        }

    def _build_sarif_tool_info(self) -> dict:
        return {
            'driver': {
                'name': 'BinMind',
                'version': '2.1.0',
                'informationUri': 'https://github.com/binmind/binmind',
                'rules': [],
                'organization': 'BinMind',
                'product': 'BinMind CI Scanner',
            },
        }

    def _build_sarif_result(self, finding: CIFinding, rule_id: str) -> dict:
        sev_map = {
            CIFindingSeverity.CRITICAL: 'error',
            CIFindingSeverity.ERROR: 'error',
            CIFindingSeverity.WARNING: 'warning',
            CIFindingSeverity.INFO: 'note',
            CIFindingSeverity.PASS: 'none',
        }
        return {
            'ruleId': rule_id,
            'level': sev_map.get(finding.severity, 'warning'),
            'message': {'text': finding.message},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': finding.file_path or 'unknown',
                    },
                    'region': {
                        'startLine': finding.line_number or 1,
                    },
                },
            }],
            'partialFingerprints': {
                'primary': hashlib.sha256(
                    f'{rule_id}:{finding.file_path}:{finding.line_number}'.encode()
                ).hexdigest()[:32],
            },
        }

    def _build_sarif_rule(self, finding: CIFinding) -> dict:
        sev_score = {
            CIFindingSeverity.CRITICAL: '9.0',
            CIFindingSeverity.ERROR: '7.0',
            CIFindingSeverity.WARNING: '4.0',
            CIFindingSeverity.INFO: '1.0',
            CIFindingSeverity.PASS: '0.0',
        }
        return {
            'id': finding.rule_id,
            'shortDescription': {'text': finding.message},
            'help': {'text': f'Finding type: {finding.finding_type}'},
            'properties': {
                'security-severity': sev_score.get(finding.severity, '1.0'),
            },
        }

    # //// JUnit XML 格式 ////
    def _format_junit(self, findings: list[CIFinding]) -> str:
        testcases = '\n'.join(self._build_junit_testcase(f) for f in findings)
        suite = self._build_junit_testsuite(findings, testcases)
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + suite

    def _build_junit_testcase(self, finding: CIFinding) -> str:
        clsname = finding.file_path or 'BinMind'
        name = finding.rule_id
        sev = finding.severity.value

        if finding.severity in (CIFindingSeverity.ERROR, CIFindingSeverity.CRITICAL):
            return (
                f'    <testcase classname="{_xml_escape(clsname)}" '
                f'name="{_xml_escape(name)}">\n'
                f'      <failure type="{_xml_escape(sev)}" '
                f'message="{_xml_escape(finding.message)}"/>\n'
                f'    </testcase>'
            )
        elif finding.severity == CIFindingSeverity.WARNING:
            return (
                f'    <testcase classname="{_xml_escape(clsname)}" '
                f'name="{_xml_escape(name)}">\n'
                f'      <skipped message="{_xml_escape(finding.message)}"/>\n'
                f'    </testcase>'
            )
        else:
            return (
                f'    <testcase classname="{_xml_escape(clsname)}" '
                f'name="{_xml_escape(name)}"/>'
            )

    def _build_junit_testsuite(self, findings: list[CIFinding],
                                testcases: str) -> str:
        failures = sum(1 for f in findings
                       if f.severity in (CIFindingSeverity.ERROR, CIFindingSeverity.CRITICAL))
        skipped = sum(1 for f in findings
                      if f.severity == CIFindingSeverity.WARNING)
        return (
            f'<testsuite name="BinMind Security Scan" '
            f'tests="{len(findings)}" '
            f'failures="{failures}" '
            f'skipped="{skipped}" '
            f'time="0.0">\n'
            f'{testcases}\n'
            f'</testsuite>'
        )

    # //// Markdown 格式 (GitHub-flavored) ////
    def _format_markdown(self, findings: list[CIFinding]) -> str:
        env = self._env_name or 'local'
        lines = [
            f'# BinMind Security Report',
            f'',
            f'**Environment:** {env}',
            f'**Generated:** {__import__("datetime").datetime.now().isoformat()}',
            f'**Total Findings:** {len(findings)}',
            f'',
            f'## Findings',
            f'',
        ]

        sev_icons = {
            CIFindingSeverity.CRITICAL: ':red_circle:',
            CIFindingSeverity.ERROR: ':orange_circle:',
            CIFindingSeverity.WARNING: ':yellow_circle:',
            CIFindingSeverity.INFO: ':blue_circle:',
            CIFindingSeverity.PASS: ':green_circle:',
        }

        for i, f in enumerate(findings, 1):
            icon = sev_icons.get(f.severity, ':white_circle:')
            lines.append(
                f'### {i}. {icon} {f.rule_id}')
            lines.append(f'- **Severity:** {f.severity.value}')
            lines.append(f'- **Type:** {f.finding_type}')
            lines.append(f'- **Message:** {f.message}')
            if f.file_path:
                lines.append(f'- **File:** `{f.file_path}`:{f.line_number}')
            lines.append('')

        if not findings:
            lines.append(':white_check_mark: No findings detected.')

        return '\n'.join(lines)

    # //// JSON 格式 ////
    def _format_json(self, findings: list[CIFinding]) -> dict:
        return {
            'tool': 'BinMind',
            'version': '2.1.0',
            'environment': self._env_name or 'local',
            'findings': [
                {
                    'rule_id': f.rule_id,
                    'severity': f.severity.value,
                    'message': f.message,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'type': f.finding_type,
                }
                for f in findings
            ],
            'summary': {
                'total': len(findings),
                'critical': sum(1 for f in findings if f.severity == CIFindingSeverity.CRITICAL),
                'error': sum(1 for f in findings if f.severity == CIFindingSeverity.ERROR),
                'warning': sum(1 for f in findings if f.severity == CIFindingSeverity.WARNING),
                'info': sum(1 for f in findings if f.severity == CIFindingSeverity.INFO),
            },
        }

    # ---- 报告写入 ----
    def write_report(self, findings: list[CIFinding],
                     filepath: Optional[str] = None) -> str:
        filepath = filepath or self.config.output_file
        if not filepath:
            ext = self.report_format or 'json'
            filepath = f'binmind_report.{ext}'

        content = self.generate_report(findings)

        if isinstance(content, dict):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(content, f, indent=2, ensure_ascii=False)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(str(content))

        return filepath

    # ---- 失败判定 ----
    def _should_fail(self, findings: list[CIFinding]) -> bool:
        if not findings:
            return False
        if self.fail_on == 'never':
            return False
        if self.fail_on == 'any':
            return True

        threshold = self.config.fail_on_severity
        threshold_idx = _SEVERITY_ORDER.index(threshold) if threshold in _SEVERITY_ORDER else 3

        for f in findings:
            f_idx = _SEVERITY_ORDER.index(f.severity.value) if f.severity.value in _SEVERITY_ORDER else 0
            if f_idx >= threshold_idx:
                return True
        return False

    def get_exit_code(self, findings: list[CIFinding]) -> int:
        """根据最高严重度 findings 映射到 CI_EXIT_CODE"""
        if not findings:
            return 0

        max_sev = 'pass'
        for f in findings:
            f_idx = _SEVERITY_ORDER.index(f.severity.value) if f.severity.value in _SEVERITY_ORDER else 0
            cur_idx = _SEVERITY_ORDER.index(max_sev) if max_sev in _SEVERITY_ORDER else 0
            if f_idx > cur_idx:
                max_sev = f.severity.value

        # pass -> 0, info -> 0, warning -> 2, error -> 1, critical -> 3
        if max_sev in ('critical',):
            return 3
        if max_sev in ('error',):
            return 1
        if max_sev in ('warning',):
            return 2
        return 0

# ===== GitHub Actions 集成 =====
def _github_annotation(finding: CIFinding) -> str:
    """生成 GitHub Actions workflow 注解字符串 (::warning/::error)"""
    if finding.severity in (CIFindingSeverity.ERROR, CIFindingSeverity.CRITICAL):
        level = 'error'
    else:
        level = 'warning'

    parts = [f'::{level}']
    params = []
    if finding.file_path:
        params.append(f'file={finding.file_path}')
    if finding.line_number:
        params.append(f'line={finding.line_number}')
    if params:
        parts.append(','.join(params))
    else:
        parts.append('')

    parts.append(f'::{finding.rule_id}: {finding.message}')
    return ''.join(parts)


def output_github_annotations(findings: list[CIFinding]):
    """向 stdout 输出 GitHub Actions 注解"""
    for f in findings:
        print(_github_annotation(f))

# ===== GitLab CI 集成 =====
def _gitlab_report(findings: list[CIFinding]) -> dict:
    """生成 GitLab SAST 格式"""
    vulns = []
    for f in findings:
        vulns.append({
            'id': f.rule_id,
            'category': 'sast',
            'name': f.rule_id,
            'message': f.message,
            'description': f.message,
            'severity': f.severity.value.title(),
            'location': {
                'file': f.file_path or 'unknown',
                'start_line': f.line_number or 1,
            },
            'identifiers': [{
                'type': 'binmind_rule',
                'name': f.rule_id,
                'value': f.rule_id,
            }],
        })

    return {
        'version': '15.0.6',
        'vulnerabilities': vulns,
        'scan': {
            'start_time': __import__('datetime').datetime.now().isoformat(),
            'end_time': __import__('datetime').datetime.now().isoformat(),
            'status': 'success',
            'type': 'sast',
            'scanner': {
                'id': 'binmind',
                'name': 'BinMind',
                'version': '2.1.0',
            },
        },
    }

# ---- XML 转义辅助 ----
def _xml_escape(text: str) -> str:
    return html.escape(str(text), quote=True)

# ===== 便捷入口 =====
def run_ci_check(binary_path: str,
                 config: Optional[CIConfig] = None) -> tuple:
    """完整 CI 检查管道：分析 -> findings -> 报告 -> 退出码"""
    cfg = config or CIConfig()
    ci = CIIntegration(cfg)

    # 模拟分析阶段 — 实际场景会调用各分析模块
    findings = [
        CIFinding(
            rule_id='BINMIND-001',
            severity=CIFindingSeverity.INFO,
            message=f'Binary loaded: {binary_path}',
            file_path=binary_path,
            finding_type='info',
        ),
        CIFinding(
            rule_id='BINMIND-100',
            severity=CIFindingSeverity.WARNING,
            message='Potential insecure API usage detected',
            file_path=binary_path,
            line_number=0,
            finding_type='vulnerability',
        ),
    ]

    exit_code = ci.get_exit_code(findings)
    report = ci.generate_report(findings)
    return exit_code, report


def generate_sarif_report(findings: list[CIFinding], binary_path: str = '',
                          tool_name: str = 'BinMind') -> dict:
    """独立 SARIF 报告生成"""
    ci = CIIntegration()
    return ci._format_sarif(findings)

# --- CycloneDX SBOM v1.5 输出 (OWASP 标准) ---
# 参考: https://cyclonedx.org/specification/overview/
# GitHub Advanced Security、Dependency-Track、Snyk 均支持 CycloneDX 导入
# SBOM (Software Bill of Materials) 格式用于供应链安全审计

def generate_cyclonedx_sbom(findings: list[CIFinding],
                             binary_path: str = '',
                             component_name: str = '',
                             component_version: str = '1.0.0') -> dict:
    """生成 CycloneDX v1.5 SBOM，含漏洞清单和组件信息"""
    import uuid as _uuid
    bom_ref = str(_uuid.uuid4())
    vuln_entries = []
    for f in findings:
        vuln_entries.append({
            'id': f.rule_id,
            'source': {'name': 'BinMind', 'url': 'https://github.com/binmind/binmind'},
            'ratings': [{
                'severity': _cyclonedx_severity(f.severity.value),
                'method': 'CVSSv3',
                'score': _cyclonedx_score(f.severity.value),
            }],
            'description': f.message,
            'recommendation': '',
            'affects': [{'ref': bom_ref}],
        })

    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': f'urn:uuid:{_uuid.uuid4()}',
        'version': 1,
        'metadata': {
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'tools': [{'vendor': 'BinMind', 'name': 'BinMind Scanner', 'version': '2.1.0'}],
            'component': {
                'type': 'application',
                'bom-ref': bom_ref,
                'name': component_name or (binary_path or 'unknown'),
                'version': component_version,
            },
        },
        'components': [{
            'type': 'application',
            'bom-ref': bom_ref,
            'name': component_name or (binary_path or 'unknown'),
            'version': component_version,
        }],
        'vulnerabilities': vuln_entries,
    }


def _cyclonedx_severity(sev: str) -> str:
    return {'critical': 'critical', 'error': 'high', 'warning': 'medium',
            'info': 'info', 'pass': 'none'}.get(sev, 'info')


def _cyclonedx_score(sev: str) -> float:
    return {'critical': 9.0, 'error': 7.0, 'warning': 4.0,
            'info': 1.0, 'pass': 0.0}.get(sev, 1.0)
