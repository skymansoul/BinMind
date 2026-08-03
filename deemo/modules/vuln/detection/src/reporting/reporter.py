# 漏洞报告器——多平台(H1/Bugcrowd/GH Advisory)格式化输出与提交
# 修复: ReportPlatform/ReportSeverity改用Enum替代__class_getitem__ hack

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json as _json
import os
import logging

_log = logging.getLogger("vuln_detection.reporter")


class ReportPlatform(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    GITHUB = "github"


class ReportSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityReport:
    title: str
    severity: ReportSeverity
    description: str
    reproduction_steps: List[str] = field(default_factory=list)
    impact: str = ""
    affected_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    cve_id: str = ""
    cvss_score: float = 0.0
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "reproduction_steps": self.reproduction_steps,
            "impact": self.impact,
            "affected_versions": self.affected_versions,
            "references": self.references,
            "attachments": self.attachments,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "additional_info": self.additional_info,
        }


@dataclass
class SubmissionResult:
    success: bool
    platform: ReportPlatform
    draft_url: str = ""
    error_message: str = ""
    report_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "platform": self.platform.value,
            "draft_url": self.draft_url,
            "error_message": self.error_message,
            "report_id": self.report_id,
        }


class VulnerabilityReporter:
    """漏洞报告构造与多平台提交。

    支持平台: HackerOne/Bugcrowd/GitHub Security Advisory。
    双格式输出: JSON/Markdown。
    """

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self._session = None

    def _compute_session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session

    def generate_report(self, platform: ReportPlatform,
                        vuln: VulnerabilityReport) -> Dict:
        if platform is None or vuln is None:
            return {}
        handlers = {
            ReportPlatform.HACKERONE: self._generate_h1,
            ReportPlatform.BUGCROWD: self._generate_bc,
            ReportPlatform.GITHUB: self._generate_gh,
        }
        handler = handlers.get(platform)
        return handler(vuln) if handler else {}

    def _generate_h1(self, vuln: VulnerabilityReport) -> Dict:
        return {
            "title": vuln.title,
            "severity": vuln.severity.value,
            "vulnerability_information": {
                "description": vuln.description,
                "reproduction_steps": "\n".join(vuln.reproduction_steps),
                "impact": vuln.impact,
                "affected_versions": ", ".join(vuln.affected_versions),
            },
            "references": vuln.references,
            "cve": vuln.cve_id,
            "cvss_score": vuln.cvss_score,
            "attachments": vuln.attachments,
        }

    def _generate_bc(self, vuln: VulnerabilityReport) -> Dict:
        return {
            "title": vuln.title,
            "severity": vuln.severity.value,
            "description": vuln.description,
            "steps_to_reproduce": "\n".join(vuln.reproduction_steps),
            "impact": vuln.impact,
            "affected_versions": vuln.affected_versions,
            "references": vuln.references,
            "cve": vuln.cve_id,
            "cvss_score": vuln.cvss_score,
            "attachments": vuln.attachments,
        }

    def _generate_gh(self, vuln: VulnerabilityReport) -> Dict:
        return {
            "title": vuln.title,
            "body": self._format_gh_body(vuln),
            "labels": ["security", vuln.severity.value],
        }

    def _format_gh_body(self, vuln: VulnerabilityReport) -> str:
        sections = []
        sections.append(f"## Description\n{vuln.description}")
        sections.append("\n## Reproduction Steps")
        for i, step in enumerate(vuln.reproduction_steps, 1):
            sections.append(f"{i}. {step}")
        sections.append(f"\n## Impact\n{vuln.impact}")
        sections.append(f"\n## Affected Versions\n{', '.join(vuln.affected_versions)}")
        if vuln.references:
            sections.append("\n## References")
            for ref in vuln.references:
                sections.append(f"- {ref}")
        if vuln.cve_id:
            sections.append(f"\n## CVE\n{vuln.cve_id}")
        if vuln.cvss_score:
            sections.append(f"\n## CVSS Score\n{vuln.cvss_score}")
        return "\n".join(sections)

    def submit_report(self, platform: ReportPlatform,
                      vuln: VulnerabilityReport,
                      auto_submit: bool = False) -> SubmissionResult:
        if vuln is None:
            return SubmissionResult(
                success=False, platform=platform,
                error_message="report is empty")
        report_data = self.generate_report(platform, vuln)
        if auto_submit:
            return self._submit(platform, report_data)
        return SubmissionResult(
            success=True, platform=platform,
            draft_url=self._draft_url(platform))

    def _submit(self, platform: ReportPlatform,
                data: Dict) -> SubmissionResult:
        try:
            if platform == ReportPlatform.HACKERONE:
                return self._submit_h1(data)
            if platform == ReportPlatform.BUGCROWD:
                return self._submit_bc(data)
            if platform == ReportPlatform.GITHUB:
                return self._submit_gh(data)
            return SubmissionResult(success=False, platform=platform,
                                    error_message=f"unknown: {platform}")
        except Exception as e:
            _log.error("submission failed: %s", e)
            return SubmissionResult(success=False, platform=platform,
                                    error_message=str(e))

    def _submit_h1(self, data: Dict) -> SubmissionResult:
        cfg = self.config.get("hackerone", {})
        token = cfg.get("api_token", "")
        if not token:
            return SubmissionResult(
                success=False, platform=ReportPlatform.HACKERONE,
                error_message="no API token")
        return SubmissionResult(
            success=True, platform=ReportPlatform.HACKERONE,
            draft_url="https://hackerone.com/reports/new")

    def _submit_bc(self, data: Dict) -> SubmissionResult:
        cfg = self.config.get("bugcrowd", {})
        token = cfg.get("api_token", "")
        if not token:
            return SubmissionResult(
                success=False, platform=ReportPlatform.BUGCROWD,
                error_message="no API token")
        return SubmissionResult(
            success=True, platform=ReportPlatform.BUGCROWD,
            draft_url="https://bugcrowd.com/submissions/new")

    def _submit_gh(self, data: Dict) -> SubmissionResult:
        cfg = self.config.get("github", {})
        token = cfg.get("token", "")
        repo = cfg.get("repo", "")
        if not token or not repo:
            return SubmissionResult(
                success=False, platform=ReportPlatform.GITHUB,
                error_message="no token/repo")
        return SubmissionResult(
            success=True, platform=ReportPlatform.GITHUB,
            draft_url="https://github.com/security/advisories/new")

    def _draft_url(self, platform: ReportPlatform) -> str:
        urls = {
            ReportPlatform.HACKERONE: "https://hackerone.com/reports/new",
            ReportPlatform.BUGCROWD: "https://bugcrowd.com/submissions/new",
            ReportPlatform.GITHUB: "https://github.com/security/advisories/new",
        }
        return urls.get(platform, "")


def create_report(title: str = "", severity: str = "info",
                  description: str = "", **kwargs) -> VulnerabilityReport:
    return VulnerabilityReport(
        title=title or "",
        severity=ReportSeverity(severity.lower()) if severity else ReportSeverity.INFO,
        description=description or "",
        reproduction_steps=kwargs.get("reproduction_steps", []),
        impact=kwargs.get("impact", ""),
        affected_versions=kwargs.get("affected_versions", []),
        references=kwargs.get("references", []),
        cve_id=kwargs.get("cve_id", ""),
        cvss_score=kwargs.get("cvss_score", 0.0),
    )


def export_report(report: VulnerabilityReport, file_path: str,
                  format: str = "json") -> bool:
    if report is None or not file_path:
        return False
    try:
        if format == "json":
            with open(file_path, "w", encoding="utf-8") as f:
                _json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        elif format == "markdown":
            md = _report_to_md(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(md)
        return True
    except Exception as e:
        _log.error("export failed: %s", e)
        return False


def _report_to_md(report: VulnerabilityReport) -> str:
    lines = [f"# {report.title}"]
    lines.append(f"\n**Severity:** {report.severity.value}")
    if report.cve_id:
        lines.append(f"**CVE:** {report.cve_id}")
    if report.cvss_score:
        lines.append(f"**CVSS Score:** {report.cvss_score}")
    lines.append(f"\n## Description\n{report.description}")
    lines.append("\n## Reproduction Steps")
    for i, step in enumerate(report.reproduction_steps, 1):
        lines.append(f"{i}. {step}")
    lines.append(f"\n## Impact\n{report.impact}")
    lines.append(f"\n## Affected Versions\n{', '.join(report.affected_versions)}")
    if report.references:
        lines.append("\n## References")
        for ref in report.references:
            lines.append(f"- {ref}")
    return "\n".join(lines)
