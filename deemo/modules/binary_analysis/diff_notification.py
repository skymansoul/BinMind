import os
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class ChangeType(str, Enum):
    NEW_VULNERABILITY = "new_vulnerability"
    VULNERABILITY_CHANGED = "vulnerability_changed"
    VULNERABILITY_FIXED = "vulnerability_fixed"
    FUNCTION_CHANGED = "function_changed"
    NEW_FUNCTION = "new_function"
    FUNCTION_DELETED = "function_deleted"
    CONFIG_CHANGED = "config_changed"
    ANALYSIS_COMPLETED = "analysis_completed"

class NotificationLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    DEBUG = "debug"


@dataclass
class AnalysisResult:
    analysis_id: str
    timestamp: float
    vulnerabilities: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class DiffChange:
    change_type: str
    level: str
    description: str
    details: dict = field(default_factory=dict)
    affected_items: list = field(default_factory=list)


@dataclass
class DiffReport:
    analysis_id: str
    previous_id: Optional[str]
    changes: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class DiffAnalyzer:

    def __init__(self):
        self._vulnerability_key_fields = ["cve_id", "function_name", "address"]
        self._function_key_fields = ["name", "address"]

    def compare(self, previous: AnalysisResult, current: AnalysisResult) -> DiffReport:
        changes = []

        vuln_changes = self._compare_vulnerabilities(previous, current)
        func_changes = self._compare_functions(previous, current)

        changes.extend(vuln_changes)
        changes.extend(func_changes)

        summary = self._generate_summary(changes)

        return DiffReport(
            analysis_id=current.analysis_id,
            previous_id=previous.analysis_id if previous else None,
            changes=changes,
            summary=summary
        )

    def _compare_vulnerabilities(self, previous: AnalysisResult, current: AnalysisResult) -> list:
        changes = []

        prev_vulns = self._index_vulnerabilities(previous.vulnerabilities)
        curr_vulns = self._index_vulnerabilities(current.vulnerabilities)

        prev_keys = set(prev_vulns.keys())
        curr_keys = set(curr_vulns.keys())
        new_vulns = curr_keys - prev_keys
        fixed_vulns = prev_keys - curr_keys
        existing_vulns = prev_keys & curr_keys

        for key in new_vulns:
            vuln = curr_vulns[key]
            changes.append(DiffChange(
                change_type=ChangeType.NEW_VULNERABILITY,
                level=NotificationLevel.CRITICAL,
                description=f"发现新漏洞: {vuln.get('cve_id', 'Unknown')}",
                details=vuln,
                affected_items=[vuln.get('function_name', '')]
            ))

        for key in fixed_vulns:
            vuln = prev_vulns[key]
            changes.append(DiffChange(
                change_type=ChangeType.VULNERABILITY_FIXED,
                level=NotificationLevel.INFO,
                description=f"漏洞已修复: {vuln.get('cve_id', 'Unknown')}",
                details=vuln,
                affected_items=[vuln.get('function_name', '')]
            ))

        for key in existing_vulns:
            prev_vuln = prev_vulns[key]
            curr_vuln = curr_vulns[key]
            if self._vulnerability_changed(prev_vuln, curr_vuln):
                changes.append(DiffChange(
                    change_type=ChangeType.VULNERABILITY_CHANGED,
                    level=NotificationLevel.WARNING,
                    description=f"漏洞状态变更: {curr_vuln.get('cve_id', 'Unknown')}",
                    details={
                        "previous": prev_vuln,
                        "current": curr_vuln
                    },
                    affected_items=[curr_vuln.get('function_name', '')]
                ))

        return changes

    def _compare_functions(self, previous: AnalysisResult, current: AnalysisResult) -> list:
        changes = []

        prev_funcs = self._index_functions(previous.functions)
        curr_funcs = self._index_functions(current.functions)

        prev_keys = set(prev_funcs.keys())
        curr_keys = set(curr_funcs.keys())
        new_funcs = curr_keys - prev_keys
        deleted_funcs = prev_keys - curr_keys
        existing_funcs = prev_keys & curr_keys

        for key in new_funcs:
            func = curr_funcs[key]
            changes.append(DiffChange(
                change_type=ChangeType.NEW_FUNCTION,
                level=NotificationLevel.INFO,
                description=f"new function: {func.get('name', 'Unknown')}",
                details=func,
                affected_items=[func.get('name', '')]
            ))

        for key in deleted_funcs:
            func = prev_funcs[key]
            changes.append(DiffChange(
                change_type=ChangeType.FUNCTION_DELETED,
                level=NotificationLevel.WARNING,
                description=f"函数已删除: {func.get('name', 'Unknown')}",
                details=func,
                affected_items=[func.get('name', '')]
            ))

        for key in existing_funcs:
            prev_func = prev_funcs[key]
            curr_func = curr_funcs[key]
            if self._function_changed(prev_func, curr_func):
                changes.append(DiffChange(
                    change_type=ChangeType.FUNCTION_CHANGED,
                    level=NotificationLevel.WARNING,
                    description=f"函数内容变更: {curr_func.get('name', 'Unknown')}",
                    details={
                        "previous": prev_func,
                        "current": curr_func
                    },
                    affected_items=[curr_func.get('name', '')]
                ))

        return changes

    def _index_vulnerabilities(self, vulnerabilities: list) -> Dict[str, Dict]:
        index = {}
        for vuln in vulnerabilities:
            key = self._get_vulnerability_key(vuln)
            index[key] = vuln
        return index

    def _get_vulnerability_key(self, vuln: Dict) -> str:
        parts = []
        for field_name in self._vulnerability_key_fields:
            value = vuln.get(field_name, "")
            if value:
                parts.append(str(value))
        return ":".join(parts) if parts else str(id(vuln))

    def _index_functions(self, functions: list) -> Dict[str, Dict]:
        index = {}
        for func in functions:
            key = self._get_function_key(func)
            index[key] = func
        return index

    def _get_function_key(self, func: Dict) -> str:
        parts = []
        for field_name in self._function_key_fields:
            value = func.get(field_name, "")
            if value:
                parts.append(str(value))
        return ":".join(parts) if parts else str(id(func))

    def _vulnerability_changed(self, prev: Dict, curr: Dict) -> bool:
        fields_to_check = ["severity", "status", "confidence", "description"]
        for field_name in fields_to_check:
            if prev.get(field_name) != curr.get(field_name):
                return True
        return False

    def _function_changed(self, prev: Dict, curr: Dict) -> bool:
        fields_to_check = ["size", "hash", "complexity", "is_vulnerable"]
        for field_name in fields_to_check:
            if prev.get(field_name) != curr.get(field_name):
                return True
        return False

    def _generate_summary(self, changes: list) -> Dict[str, int]:
        summary = {
            "new_vulnerabilities": 0,
            "fixed_vulnerabilities": 0,
            "changed_vulnerabilities": 0,
            "new_functions": 0,
            "deleted_functions": 0,
            "changed_functions": 0,
            "total_changes": len(changes)
        }

        for change in changes:
            if change.change_type == ChangeType.NEW_VULNERABILITY:
                summary["new_vulnerabilities"] += 1
            elif change.change_type == ChangeType.VULNERABILITY_FIXED:
                summary["fixed_vulnerabilities"] += 1
            elif change.change_type == ChangeType.VULNERABILITY_CHANGED:
                summary["changed_vulnerabilities"] += 1
            elif change.change_type == ChangeType.NEW_FUNCTION:
                summary["new_functions"] += 1
            elif change.change_type == ChangeType.FUNCTION_DELETED:
                summary["deleted_functions"] += 1
            elif change.change_type == ChangeType.FUNCTION_CHANGED:
                summary["changed_functions"] += 1

        return summary


class NotificationChannel:

    def send(self, report: DiffReport) -> bool:
        raise NotImplementedError


class ConsoleChannel(NotificationChannel):

    def send(self, report: DiffReport) -> bool:
        print("\n" + "="*60)
        print(f"分析diff报告 - {report.analysis_id}")
        print("="*60)

        for change in report.changes:
            level_color = {
                NotificationLevel.INFO: "\033[92m",
                NotificationLevel.WARNING: "\033[93m",
                NotificationLevel.CRITICAL: "\033[91m",
                NotificationLevel.DEBUG: "\033[94m"
            }.get(change.level, "\033[0m")

            print(f"\n{level_color}[{change.level.upper()}] {change.description}\033[0m")
            if change.affected_items:
                print(f"  影响项: {', '.join(change.affected_items)}")

        print("\nsummary:")
        for key, value in report.summary.items():
            if value > 0:
                print(f"  {key}: {value}")

        print("="*60)
        return True


class WebhookChannel(NotificationChannel):

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url

    def send(self, report: DiffReport) -> bool:
        try:
            import requests
            payload = {
                "analysis_id": report.analysis_id,
                "previous_id": report.previous_id,
                "changes": [
                    {
                        "type": change.change_type,
                        "level": change.level,
                        "description": change.description,
                        "details": change.details
                    }
                    for change in report.changes
                ],
                "summary": report.summary
            }
            response = requests.post(self._webhook_url, json=payload)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False


class FileChannel(NotificationChannel):

    def __init__(self, output_dir: str):
        self._output_dir = output_dir

    def send(self, report: DiffReport) -> bool:
        try:
            os.makedirs(self._output_dir, exist_ok=True)
            filename = f"diff_report_{report.analysis_id}.json"
            filepath = os.path.join(self._output_dir, filename)

            with open(filepath, 'w') as f:
                json.dump({
                    "analysis_id": report.analysis_id,
                    "previous_id": report.previous_id,
                    "changes": [
                        {
                            "type": change.change_type,
                            "level": change.level,
                            "description": change.description,
                            "details": change.details,
                            "affected_items": change.affected_items
                        }
                        for change in report.changes
                    ],
                    "summary": report.summary
                }, f, indent=2)

            logger.info(f"Diff report saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False



class NotificationManager:

    def __init__(self):
        self._channels: list = []

    def add_channel(self, channel: NotificationChannel) -> None:
        self._channels.append(channel)

    def remove_channel(self, channel: NotificationChannel) -> None:
        if channel in self._channels:
            self._channels.remove(channel)

    def notify(self, report: DiffReport) -> None:
        for channel in self._channels:
            try:
                channel.send(report)
            except Exception as e:
                logger.error(f"Failed to send notification via channel: {e}")


_global_manager: Optional[NotificationManager] = None


def get_notification_manager() -> NotificationManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = NotificationManager()
    return _global_manager


def analyze_and_notify(previous: AnalysisResult, current: AnalysisResult) -> DiffReport:
    analyzer = DiffAnalyzer()
    report = analyzer.compare(previous, current)

    if report.summary["total_changes"] > 0:
        manager = get_notification_manager()
        manager.notify(report)

    return report
