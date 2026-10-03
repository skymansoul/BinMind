from enum import StrEnum
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class MovementTechnique(StrEnum):
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    REMOTE_EXECUTION = "remote_execution"
    WMI_EXECUTION = "wmi_execution"
    RDP_HIJACKING = "rdp_hijacking"
    SSH_TUNNELING = "ssh_tunneling"
    PSREMOTING = "psremoting"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE_CREATION = "service_creation"
    DCOM = "dcom"


@dataclass
class MovementIndicator:
    indicator_id: Any = None
    technique: Any = None
    severity: Any = None
    api_calls: Any = None
    description: str = ""
    confidence: float = 0.0
    mitre_technique: Any = None
def to_dict(self) -> Dict[str, Any]:
        return {
            'indicator_id': self.indicator_id,
            'technique': self.technique.value,
            'severity': self.severity,
            'api_calls': self.api_calls[:10],
            'description': self.description,
            'confidence': self.confidence,
            'mitre_technique': self.mitre_technique
        }

class LateralMovementDetector:
    """基于 API 调用与字符串签名匹配检测横向移动技术。"""

    TECHNIQUE_SIGNATURES = {
        MovementTechnique.PASS_THE_HASH: {
            'apis': ['LogonUser', 'ImpersonateLoggedOnUser', 'Lsass', 'NTLM',
                     'MSV1_0', 'CryptProtectData', 'CryptUnprotectData'],
            'severity': 'critical',
            'mitre': 'T1550.002',
            'description': 'Pass-the-Hash: NTLM 哈希直接认证'
        },
        MovementTechnique.PASS_THE_TICKET: {
            'apis': ['LsaCallAuthenticationPackage', 'LsaLogonUser',
                     'Kerberos', 'TGT', 'TGS', 'klist'],
            'severity': 'critical',
            'mitre': 'T1550.003',
            'description': 'Pass-the-Ticket: Kerberos 票据认证'
        },
        MovementTechnique.REMOTE_EXECUTION: {
            'apis': ['CreateService', 'StartService', 'OpenSCManager',
                     'OpenService', 'ControlService',
                     'WNetAddConnection2', 'NetUseAdd', 'NetShareEnum'],
            'severity': 'high',
            'mitre': 'T1021.002',
            'description': '远程执行: SMB/PsExec 模式'
        },
        MovementTechnique.WMI_EXECUTION: {
            'apis': ['IWbemServices', 'ConnectServer', 'ExecMethod',
                     'Win32_Process', 'Create', 'CoInitializeSecurity'],
            'severity': 'high',
            'mitre': 'T1047',
            'description': 'WMI 远程执行'
        },
        MovementTechnique.RDP_HIJACKING: {
            'apis': ['WTSConnectSession', 'WTSEnumerateSessions',
                     'mstscax', 'MsRdpClient', 'RDP'],
            'severity': 'medium',
            'mitre': 'T1563.001',
            'description': 'RDP 会话劫持'
        },
        MovementTechnique.SSH_TUNNELING: {
            'apis': ['ssh', 'sftp', 'scp', 'ssh_connect', 'ssh_channel',
                     'libssh2', 'socket', 'connect', 'port_forward'],
            'severity': 'medium',
            'mitre': 'T1572',
            'description': 'SSH 隧道: 协议级防火墙绕过'
        },
        MovementTechnique.PSREMOTING: {
            'apis': ['WSMan', 'New-PSSession', 'Enter-PSSession',
                     'Invoke-Command', 'WinRM'],
            'severity': 'high',
            'mitre': 'T1021.006',
            'description': 'PowerShell Remoting (WinRM)'
        },
        MovementTechnique.SCHEDULED_TASK: {
            'apis': ['ITaskScheduler', 'RegisterTask', 'schtasks',
                     'CreateProcess', 'Cmd.exe', '/c'],
            'severity': 'high',
            'mitre': 'T1053.005',
            'description': '计划任务远程执行'
        },
        MovementTechnique.SERVICE_CREATION: {
            'apis': ['CreateService', 'OpenSCManager', 'StartService',
                     'ChangeServiceConfig', 'QueryServiceConfig'],
            'severity': 'high',
            'mitre': 'T1543.003',
            'description': 'Windows 服务创建/修改'
        },
        MovementTechnique.DCOM: {
            'apis': ['CoCreateInstance', 'CLSID', 'DCOM', 'CoInitializeEx',
                     'CoGetClassObject', 'IRemoteDispatch'],
            'severity': 'high',
            'mitre': 'T1021.003',
            'description': 'DCOM 远程执行 (MMC20, ShellWindows 等)'
        },
    }

    CREDENTIAL_DUMP_APIS = {
        'Mimikatz': ['sekurlsa', 'LogonPasswords', 'lsadump::sam',
                     'lsadump::secrets', 'privilege::debug'],
        'ProcDump_LSASS': ['MiniDumpWriteDump', 'lsass.exe', 'PROCESS_VM_READ',
                           'PROCESS_QUERY_INFORMATION', 'OpenProcess'],
        'SAM_Dump': ['SAM', 'samdump2', 'pwdump', 'fgdump',
                     'RegSaveKey', 'HKLM\\SAM', 'HKLM\\SYSTEM'],
        'NTDS_Dump': ['ntdsutil', 'dsquery', 'NTDS.dit',
                      'Directory Replication', 'DRSGetNCChanges'],
    }

def __init__(self):
        self._findings: List[MovementIndicator] = []
        self._counter = 0

def _next_id(self) -> str:
        self._counter += 1
        return f"LM-{self._counter:04d}"

def detect_api_patterns(self, api_calls: List[str],
                           strings_in_binary: Optional[List[str]] = None
                           ) -> List[MovementIndicator]:
        findings = []
        api_set = set(c.lower() for c in api_calls)
        str_set = set(s.lower() for s in (strings_in_binary or []))

        for technique, sig in self.TECHNIQUE_SIGNATURES.items():
            sig_apis_lower = {s.lower() for s in sig['apis']}
            matches = api_set & sig_apis_lower
            if not matches:
                matches = str_set & sig_apis_lower

            if matches:
                confidence = len(matches) / max(1, len(sig_apis_lower))
                confidence = min(confidence * 1.5, 1.0)

                if confidence >= 0.15:
                    findings.append(MovementIndicator(
                        indicator_id=self._next_id(),
                        technique=technique,
                        severity=sig['severity'],
                        api_calls=list(matches),
                        description=sig['description'],
                        confidence=round(confidence, 2),
                        mitre_technique=sig['mitre']
                    ))

        return sorted(findings, key=lambda f: f.confidence, reverse=True)

def detect_credential_dump(self, api_calls: List[str],
                               strings_in_binary: Optional[List[str]] = None
                               ) -> List[MovementIndicator]:
        findings = []
        api_set = set(c.lower() for c in api_calls)
        str_set = set(s.lower() for s in (strings_in_binary or []))

        for tool, indicators in self.CREDENTIAL_DUMP_APIS.items():
            ind_lower = {i.lower() for i in indicators}
            matches = (api_set | str_set) & ind_lower
            if matches:
                confidence = len(matches) / max(1, len(ind_lower))
                findings.append(MovementIndicator(
                    indicator_id=self._next_id(),
                    technique=MovementTechnique.PASS_THE_HASH,
                    severity='critical',
                    api_calls=list(matches),
                    description=f'检测到 {tool} 凭证转储特征',
                    confidence=round(min(confidence * 2.0, 1.0), 2),
                    mitre_technique='T1003.001'
                ))

        return findings

def analyze(self, api_calls: Optional[List[str]] = None,
                strings_in_binary: Optional[List[str]] = None,
                network_targets: Optional[List[str]] = None,
                **kwargs) -> Dict[str, Any]:
        api_calls = api_calls or []
        strings_in_binary = strings_in_binary or []

        move_findings = self.detect_api_patterns(api_calls, strings_in_binary)
        cred_findings = self.detect_credential_dump(api_calls, strings_in_binary)
        all_findings = move_findings + cred_findings
        self._findings = all_findings

        network_analysis = {}
        if network_targets:
            network_analysis = {
                'internal_ips': [t for t in network_targets
                               if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)',
                                          t)],
                'port_445': sum(1 for t in network_targets if ':445' in t or 'SMB' in t.upper()),
                'port_135': sum(1 for t in network_targets if ':135' in t or 'RPC' in t.upper()),
            }

        return {
            'success': True,
            'total_indicators': len(all_findings),
            'techniques_detected': list(set(
                f.technique.value for f in move_findings)),
            'indicators': [f.to_dict() for f in all_findings],
            'confidence_scores': {
                f.technique.value: f.confidence for f in all_findings
            },
            'network_analysis': network_analysis,
            'risk_assessment': {
                'critical': sum(1 for f in all_findings if f.severity == 'critical'),
                'high': sum(1 for f in all_findings if f.severity == 'high'),
                'medium': sum(1 for f in all_findings if f.severity == 'medium'),
            }
        }

def detect_lateral_movement(api_calls: Optional[List[str]] = None,
                            strings: Optional[List[str]] = None,
                            **kwargs) -> Dict[str, Any]:
    """便捷入口：实例化检测器并执行横向移动全量分析。"""
    detector = LateralMovementDetector()
    return detector.analyze(api_calls=api_calls, strings_in_binary=strings)

__all__ = ["LateralMovementDetector", "MovementIndicator", "MovementTechnique",
           "detect_lateral_movement"]
