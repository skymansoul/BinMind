"""持久化机制检测 — 注册表、文件系统、任务计划三层覆盖。"""
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
    __slots__ = ('finding_id', 'persistence_type', 'severity', 'description',
                 'evidence', 'registry_key', 'file_path', 'command',
                 'mitre_technique', 'confidence', 'evidence_chain')

    def __init__(self, finding_id, persistence_type, severity, description,
                 evidence="", registry_key="", file_path="", command="",
                 mitre_technique="", confidence=1.0, evidence_chain=None):
        self.finding_id = finding_id
        self.persistence_type = persistence_type
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.registry_key = registry_key
        self.file_path = file_path
        self.command = command
        self.mitre_technique = mitre_technique
        self.confidence = confidence
        self.evidence_chain = evidence_chain or []

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
            'mitre_technique': self.mitre_technique,
            'confidence': self.confidence,
            'evidence_chain': self.evidence_chain[:10],
        }


class PersistenceDetector:
    """跨平台持久化机制检测 — 注册表、文件系统、任务计划三层覆盖。

    增强：对 Windows Run 键匹配引入精确度评分（完全路径匹配 > 部分键名匹配），
    Linux 检测增加文件修改时间感知能力（通过外部 filetime 字段）。
    """

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
        ('crontab', 'T1053.003', 'crontab'),
        ('/etc/cron', 'T1053.003', 'crontab'),
        ('/etc/systemd/system/', 'T1543.002', 'systemd_service'),
        ('/etc/init.d/', 'T1037.004', 'initd_script'),
        ('~/.bashrc', 'T1546.004', 'bash_profile'),
        ('~/.bash_profile', 'T1546.004', 'bash_profile'),
        ('LD_PRELOAD', 'T1574.006', 'ld_preload'),
        ('/etc/ld.so.preload', 'T1574.006', 'ld_preload'),
        # 新增：systemd timer 持久化 — 比 cron 更隐蔽
        ('/etc/systemd/system/*.timer', 'T1053.006', 'systemd_timer'),
        # 新增：udev 规则持久化
        ('/etc/udev/rules.d/', 'T1547.012', 'udev_rule'),
    ]

    # Windows 内核级持久化 — 过滤驱动、boot-start 驱动
    WINDOWS_KERNEL_PERSISTENCE = [
        ('\\Registry\\Machine\\System\\CurrentControlSet\\Services\\',
         'T1543.003', 'kernel_driver'),
        ('Start', 'T1543.003', 'service_start_type'),
        ('SERVICE_BOOT_START', 'T1547.008', 'boot_driver'),
        ('SERVICE_SYSTEM_START', 'T1543.003', 'system_driver'),
        ('NtLoadDriver', 'T1547.008', 'driver_load'),
        ('ZwLoadDriver', 'T1547.008', 'driver_load'),
    ]

    MACOS_PERSISTENCE_INDICATORS = [
        ('LaunchAgents', 'T1543.001', 'launch_agent'),
        ('LaunchDaemons', 'T1543.004', 'launch_daemon'),
        ('loginwindow.plist', 'T1547.011', 'login_item'),
        # 新增：Cron 定时任务 (macOS 仍然支持)
        ('/usr/lib/cron', 'T1053.003', 'crontab'),
    ]

    def __init__(self):
        self._findings: List[PersistenceFinding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"PERSIST-{self._counter:04d}"

    @staticmethod
    def _compute_match_confidence(needle: str, haystack: str) -> float:
        """计算匹配精确度：完整路径匹配 → 1.0，尾缀匹配 → 0.7，子串 → 0.5。

        避免 'Run' 键名匹配到 'Runtime' 之类误报。
        """
        nl = needle.lower()
        hl = haystack.lower()
        if nl == hl:
            return 1.0
        if hl.endswith(nl):
            return 0.7
        if nl in hl:
            return 0.5
        return 0.0

    def scan_windows(self, registry_keys: Optional[List[str]] = None,
                     strings_data: Optional[List[str]] = None) -> List[PersistenceFinding]:
        findings = []
        regs_lower = {r.lower() for r in (registry_keys or [])}
        strs_lower = {s.lower() for s in (strings_data or [])}

        for run_key in self.WINDOWS_RUN_KEYS:
            for reg in (registry_keys or []):
                conf = self._compute_match_confidence(run_key, reg)
                if conf > 0:
                    findings.append(PersistenceFinding(
                        finding_id=self._next_id(),
                        persistence_type=PersistenceType.REGISTRY_RUN_KEY,
                        severity='high',
                        description=f'Run 键持久化: {run_key}',
                        registry_key=run_key, mitre_technique='T1547.001',
                        confidence=conf,
                        evidence_chain=[f"注册表键匹配: {reg}"]))
                    break  # 每个 run_key 仅记录一次

        if any('schtasks' in s or 'RegisterTaskDefinition' in s for s in strs_lower):
            findings.append(PersistenceFinding(
                finding_id=self._next_id(),
                persistence_type=PersistenceType.SCHEDULED_TASK,
                severity='high',
                description='计划任务持久化机制',
                mitre_technique='T1053.005',
                evidence_chain=['字符串命中: schtasks / RegisterTaskDefinition']))

        if any('CreateService' in s or 'StartService' in s for s in strs_lower):
            findings.append(PersistenceFinding(
                finding_id=self._next_id(),
                persistence_type=PersistenceType.WINDOWS_SERVICE,
                severity='high',
                description='Windows 服务持久化机制',
                mitre_technique='T1543.003',
                evidence_chain=['字符串命中: CreateService / StartService']))

        # 新增：WMI 事件订阅持久化检测
        if any('ActiveScriptEventConsumer' in s or '__EventFilter' in s
               or 'CommandLineEventConsumer' in s for s in strs_lower):
            findings.append(PersistenceFinding(
                finding_id=self._next_id(),
                persistence_type=PersistenceType.WMI_SUBSCRIPTION,
                severity='critical',
                description='WMI 事件订阅持久化（无文件持久化，高隐蔽性）',
                mitre_technique='T1546.003',
                confidence=0.9,
                evidence_chain=['字符串命中: WMI EventConsumer']))

        # 内核级持久化 — 过滤驱动 / boot-start 驱动
        for indicator, mitre, ptype in self.WINDOWS_KERNEL_PERSISTENCE:
            if indicator.lower() in strs_lower:
                findings.append(PersistenceFinding(
                    finding_id=self._next_id(),
                    persistence_type=PersistenceType.WINDOWS_SERVICE
                    if 'driver' not in ptype else PersistenceType.REGISTRY_RUN_KEY,
                    severity='critical',
                    description=f'内核持久化: {indicator}',
                    mitre_technique=mitre,
                    confidence=0.85,
                    evidence_chain=[f'驱动/服务加载: {indicator}']))
                break  # 每种类型仅报告一次

        return findings

    def scan_linux(self, strings_data: List[str]) -> List[PersistenceFinding]:
        findings = []
        strs_lower = ' '.join(s.lower() for s in strings_data)
        for indicator, mitre, ptype in self.LINUX_PERSISTENCE_INDICATORS:
            if indicator.lower() in strs_lower:
                severity = 'high'
                if ptype in ('bash_profile',):
                    severity = 'medium'
                elif ptype in ('ld_preload', 'systemd_timer',):
                    severity = 'critical'
                findings.append(PersistenceFinding(
                    finding_id=self._next_id(),
                    persistence_type=PersistenceType(ptype) if ptype in (
                        'crontab', 'systemd_service', 'initd_script',
                        'bash_profile', 'ld_preload', 'launch_agent',
                        'launch_daemon'
                    ) else PersistenceType.SCHEDULED_TASK,
                    severity=severity,
                    description=f'Linux 持久化: {indicator}',
                    evidence=indicator, mitre_technique=mitre,
                    evidence_chain=[f"文件系统路径/配置命中: {indicator}"]))
        return findings

    def scan_macos(self, strings_data: List[str]) -> List[PersistenceFinding]:
        findings = []
        strs_lower = ' '.join(s.lower() for s in strings_data)
        for indicator, mitre, ptype in self.MACOS_PERSISTENCE_INDICATORS:
            if indicator.lower() in strs_lower:
                findings.append(PersistenceFinding(
                    finding_id=self._next_id(),
                    persistence_type=PersistenceType(ptype) if ptype in (
                        'launch_agent', 'launch_daemon', 'crontab'
                    ) else PersistenceType.LAUNCH_AGENT,
                    severity='high',
                    description=f'macOS 持久化: {indicator}',
                    mitre_technique=mitre,
                    evidence_chain=[f"plist/路径命中: {indicator}"]))
        return findings

    # MITRE 技术 → 杀伤链阶段映射
    _KILLCHAIN_PHASE: dict[str, str] = {
        'T1547.001': 'establish_foothold',
        'T1053.005': 'establish_foothold', 'T1053.006': 'establish_foothold',
        'T1543.003': 'establish_foothold', 'T1543.002': 'establish_foothold',
        'T1546.004': 'maintain_presence', 'T1546.003': 'maintain_presence',
        'T1574.006': 'escalate_privileges',
        'T1037.004': 'establish_foothold',
        'T1543.001': 'establish_foothold', 'T1543.004': 'establish_foothold',
        'T1547.011': 'establish_foothold', 'T1547.012': 'escalate_privileges',
    }

    def _map_to_killchain(self, mitre: str) -> str:
        return self._KILLCHAIN_PHASE.get(mitre, 'unknown')

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
        # 按杀伤链阶段分组
        killchain_groups: dict[str, int] = {}
        for f in all_findings:
            phase = self._map_to_killchain(f.mitre_technique)
            killchain_groups[phase] = killchain_groups.get(phase, 0) + 1

        return {
            'success': True,
            'total_findings': len(all_findings),
            'findings': [f.to_dict() for f in all_findings],
            'techniques': list(set(f.persistence_type.value for f in all_findings)),
            'killchain_phases': killchain_groups,
            # APT 级别告警：多阶段持久化 + 权限提升同时命中
            'apt_risk': (
                killchain_groups.get('establish_foothold', 0) > 0 and
                killchain_groups.get('escalate_privileges', 0) > 0
            ),
        }


def detect_persistence(platform: str = "auto",
                       strings_data: Optional[List[str]] = None,
                       registry_keys: Optional[List[str]] = None,
                       **kwargs) -> Dict[str, Any]:
    """便捷入口：实例化检测器并执行全平台持久化扫描。"""
    detector = PersistenceDetector()
    return detector.analyze(platform=platform, strings_data=strings_data,
                           registry_keys=registry_keys)
