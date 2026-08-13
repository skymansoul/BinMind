import logging
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)



class PersistenceType(Enum):
    REGISTRY_RUN_KEY = "registry_run_key"
    SCHEDULED_TASK = "scheduled_task"
    WINDOWS_SERVICE = "windows_service"
    STARTUP_FOLDER = "startup_folder"
    WMI_SUBSCRIPTION = "wmi_subscription"
    LOGON_SCRIPT = "logon_script"
    CRONTAB = "crontab"
    SYSTEMD_SERVICE = "systemd_service"
    INITD_SCRIPT = "initd_script"
    BASH_PROFILE = "bash_profile"
    LD_PRELOAD = "ld_preload"
    LAUNCH_AGENT = "launch_agent"
    LAUNCH_DAEMON = "launch_daemon"

class PersistenceFinding:
    __slots__ = ('finding_id', 'persistence_type', 'severity', 'description', 'evidence', 'registry_key', 'file_path', 'command', 'mitre_technique',)

    def __init__(self, finding_id, persistence_type, severity, description, evidence="", registry_key="", file_path="", command="", mitre_technique=""):
        self.finding_id = finding_id
        self.persistence_type = persistence_type
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.registry_key = registry_key
        self.file_path = file_path
        self.command = command
        self.mitre_technique = mitre_technique

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'persistence_type': self.persistence_type.value,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence[:150],
            'registry_key': self.registry_key,
            'file_path': self.file_path,
            'command': self.command[:100],
            'mitre_technique': self.mitre_technique
        }


class PersistenceDetector:
    """跨平台持久化机制检测 — 注册表、文件系统、任务计划三层覆盖。"""

    WINDOWS_RUN_KEYS = [
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
    ]

    LINUX_PERSISTENCE_INDICATORS = [
        ('crontab', 'T1053.003', 'scheduled_task'),
        ('/etc/cron', 'T1053.003', 'scheduled_task'),
        ('/etc/systemd/system/', 'T1543.002', 'systemd_service'),
        ('/etc/init.d/', 'T1037.004', 'initd_script'),
        ('~/.bashrc', 'T1546.004', 'bash_profile'),
        ('~/.bash_profile', 'T1546.004', 'bash_profile'),
        ('LD_PRELOAD', 'T1574.006', 'ld_preload'),
        ('/etc/ld.so.preload', 'T1574.006', 'ld_preload'),
    ]

    MACOS_PERSISTENCE_INDICATORS = [
        ('LaunchAgents', 'T1543.001', 'launch_agent'),
        ('LaunchDaemons', 'T1543.004', 'launch_daemon'),
        ('loginwindow.plist', 'T1547.011', 'login_item'),
    ]

    def __init__(self):
        self._findings: List[PersistenceFinding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"PERSIST-{self._counter:04d}"

    def scan_windows(self, registry_keys: Optional[List[str]] = None,
                     strings_data: Optional[List[str]] = None) -> List[PersistenceFinding]:
        findings = []
        regs_lower = {r.lower() for r in (registry_keys or [])}
        strs_lower = {s.lower() for s in (strings_data or [])}

        for run_key in self.WINDOWS_RUN_KEYS:
            for reg in regs_lower:
                if run_key.lower() in reg:
                    findings.append(PersistenceFinding(
                        finding_id=self._next_id(),
                        persistence_type=PersistenceType.REGISTRY_RUN_KEY,
                        severity='high',
                        description=f'Run 键持久化: {run_key}',
                        registry_key=run_key, mitre_technique='T1547.001'))

        if any('schtasks' in s or 'RegisterTaskDefinition' in s for s in strs_lower):
            findings.append(PersistenceFinding(
                finding_id=self._next_id(),
                persistence_type=PersistenceType.SCHEDULED_TASK,
                severity='high',
                description='计划任务持久化机制',
                mitre_technique='T1053.005'))

        if any('CreateService' in s or 'StartService' in s for s in strs_lower):
            findings.append(PersistenceFinding(
                finding_id=self._next_id(),
                persistence_type=PersistenceType.WINDOWS_SERVICE,
                severity='high',
                description='Windows 服务持久化机制',
                mitre_technique='T1543.003'))

        return findings

    def scan_linux(self, strings_data: List[str]) -> List[PersistenceFinding]:
        findings = []
        strs_lower = ' '.join(s.lower() for s in strings_data)
        for indicator, mitre, ptype in self.LINUX_PERSISTENCE_INDICATORS:
            if indicator.lower() in strs_lower:
                findings.append(PersistenceFinding(
                    finding_id=self._next_id(),
                    persistence_type=PersistenceType(ptype),
                    severity='high' if ptype != 'bash_profile' else 'medium',
                    description=f'Linux 持久化: {indicator}',
                    evidence=indicator, mitre_technique=mitre))
        return findings

    def scan_macos(self, strings_data: List[str]) -> List[PersistenceFinding]:
        findings = []
        strs_lower = ' '.join(s.lower() for s in strings_data)
        for indicator, mitre, ptype in self.MACOS_PERSISTENCE_INDICATORS:
            if indicator.lower() in strs_lower:
                findings.append(PersistenceFinding(
                    finding_id=self._next_id(),
                    persistence_type=PersistenceType(ptype),
                    severity='high',
                    description=f'macOS 持久化: {indicator}',
                    mitre_technique=mitre))
        return findings

    def analyze(self, platform: str = "auto",
                strings_data: Optional[List[str]] = None,
                registry_keys: Optional[List[str]] = None,
                **kwargs) -> Dict[str, Any]:
        strings_data = strings_data or []
        registry_keys = registry_keys or []

        all_findings = []
        if platform in ('auto', 'windows'):
            all_findings.extend(self.scan_windows(registry_keys, strings_data))
        if platform in ('auto', 'linux'):
            all_findings.extend(self.scan_linux(strings_data))
        if platform in ('auto', 'macos'):
            all_findings.extend(self.scan_macos(strings_data))

        self._findings = all_findings
        return {
            'success': True,
            'total_findings': len(all_findings),
            'findings': [f.to_dict() for f in all_findings],
            'techniques': list(set(f.persistence_type.value for f in all_findings))
        }


def detect_persistence(platform: str = "auto",
                       strings_data: Optional[List[str]] = None,
                       registry_keys: Optional[List[str]] = None,
                       **kwargs) -> Dict[str, Any]:
    """便捷入口：实例化检测器并执行全平台持久化扫描。"""
    detector = PersistenceDetector()
    return detector.analyze(platform=platform, strings_data=strings_data,
                           registry_keys=registry_keys)

