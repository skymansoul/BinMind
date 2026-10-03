#!/usr/bin/env python3
import logging, os, re, subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class TicketType:
    TGT = "tgt"; TGS = "tgs"; AS_REP = "as_rep"; AS_REQ = "as_req"

class EncryptionType:
    RC4_HMAC = 23; AES128_CTS = 17; AES256_CTS = 18
    DES_CBC_CRC = 1; DES_CBC_MD5 = 3

@dataclass
class KerberosTicket:
    ticket_type: str = ""; realm: str = ""; service_name: str = ""
    client_name: str = ""; encryption_type: int = 0
    validity_start: int = 0; validity_end: int = 0; renewal_end: int = 0
    flags: int = 0; pac_present: bool = False; pac_signed: bool = False
    is_weak: bool = False
    @property
    def lifetime_hours(self) -> float:
        if self.validity_end > 0 and self.validity_start > 0:
            return (self.validity_end - self.validity_start) / 3600.0
        return 0.0
    def to_dict(self) -> Dict[str, Any]:
        return {'ticket_type': self.ticket_type, 'realm': self.realm,
                'service_name': self.service_name, 'encryption_type': self.encryption_type,
                'is_weak': self.is_weak}

class KerberosFinding:
    __slots__ = ('finding_id','attack_type','severity','description','affected_account',
                 'spn','encryption_type','remediation','mitre_technique',)
    def __init__(self, finding_id, attack_type, severity, description,
                 affected_account="", spn="", encryption_type="",
                 remediation="", mitre_technique=""):
        self.finding_id = finding_id; self.attack_type = attack_type
        self.severity = severity; self.description = description
        self.affected_account = affected_account; self.spn = spn
        self.encryption_type = encryption_type; self.remediation = remediation
        self.mitre_technique = mitre_technique
    def to_dict(self) -> Dict[str, Any]:
        return {'finding_id': self.finding_id, 'attack_type': self.attack_type,
                'severity': self.severity, 'description': self.description,
                'affected_account': self.affected_account, 'spn': self.spn,
                'encryption_type': self.encryption_type, 'remediation': self.remediation,
                'mitre_technique': self.mitre_technique}

class KerberosAnalyzer:
    WEAK_ETYPES = {EncryptionType.RC4_HMAC, EncryptionType.DES_CBC_CRC, EncryptionType.DES_CBC_MD5}
    DANGEROUS_SPN_PATTERNS = ['MSSQLSvc','HTTP','TERMSRV','WSMAN','host','cifs',
                               'exchange','ldap','gc','DNS']

    def __init__(self):
        self._findings: List[KerberosFinding] = []; self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1; return f"KRB-{self._counter:04d}"

    def detect_kerberoasting(self, tickets: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        for ticket in tickets:
            etype = int(ticket.get('encryption_type', 23))
            spn = ticket.get('service_name', '')
            if etype in self.WEAK_ETYPES:
                findings.append(KerberosFinding(
                    finding_id=self._next_id(), attack_type='kerberoasting',
                    severity='high',
                    description=f'Service {spn} uses weak encryption type ({etype})',
                    spn=spn, encryption_type=str(etype),
                    remediation='Rotate service account password to 25+ characters',
                    mitre_technique='T1558.003'))
        for ticket in tickets:
            if any(p.lower() in ticket.get('service_name','').lower()
                   for p in self.DANGEROUS_SPN_PATTERNS):
                findings.append(KerberosFinding(
                    finding_id=self._next_id(), attack_type='kerberoasting',
                    severity='critical' if 'MSSQLSvc' in ticket.get('service_name','') else 'high',
                    description=f'High-value SPN: {ticket.get("service_name","")}',
                    spn=ticket.get('service_name',''),
                    remediation='Audit service account privileges; consider gMSA',
                    mitre_technique='T1558.003'))
        self._findings.extend(findings)
        return {'total_tickets': len(tickets), 'findings': [f.to_dict() for f in findings]}

    def detect_asrep_roasting(self, accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        for account in accounts:
            if not account.get('requires_preauth', True):
                findings.append(KerberosFinding(
                    finding_id=self._next_id(), attack_type='asrep_roasting',
                    severity='high',
                    description=f"Account {account.get('name','?')} lacks pre-authentication",
                    affected_account=account.get('name',''),
                    remediation='Enable Kerberos pre-authentication',
                    mitre_technique='T1558.004'))
        self._findings.extend(findings)
        return {'total_accounts': len(accounts), 'findings': [f.to_dict() for f in findings]}

    def detect_golden_silver_ticket(self, domain_info: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        if domain_info.get('krbtgt_password_age_days', 0) > 365:
            findings.append(KerberosFinding(
                finding_id=self._next_id(), attack_type='golden_ticket',
                severity='critical',
                description=f"krbtgt password unchanged for "
                           f"{domain_info.get('krbtgt_password_age_days',0)} days",
                affected_account='krbtgt',
                remediation='Reset krbtgt account password twice immediately',
                mitre_technique='T1558.001'))
        self._findings.extend(findings)
        return {'findings': [f.to_dict() for f in findings]}

    def detect_s4u_abuse(self, delegation_info: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        if delegation_info.get('unconstrained_delegation', False):
            findings.append(KerberosFinding(
                finding_id=self._next_id(), attack_type='s4u_abuse',
                severity='critical',
                description=f"Unconstrained delegation on "
                           f"{delegation_info.get('account','unknown')}",
                affected_account=delegation_info.get('account',''),
                remediation='Use constrained or resource-based delegation instead',
                mitre_technique='T1558.001'))
        # 新增: 基于资源的约束委派 (RBCD) 滥用检测
        if delegation_info.get('rbcd_configured', False):
            findings.append(KerberosFinding(
                finding_id=self._next_id(), attack_type='rbcd_abuse',
                severity='high',
                description="RBCD configured — service may add itself to msDS-AllowedToActOnBehalfOfOtherIdentity",
                affected_account=delegation_info.get('account', ''),
                remediation='Audit msDS-AllowedToActOnBehalfOfOtherIdentity on all service accounts',
                mitre_technique='T1558.003'))
        self._findings.extend(findings)
        return {'findings': [f.to_dict() for f in findings]}

    def detect_diamond_ticket(self, domain_info: Dict[str, Any]) -> Dict[str, Any]:
        """检测 Diamond Ticket 攻击条件, AES key 已被泄露或可被解密
        Diamond Ticket 比 Golden Ticket 更难检测，因为它使用正确的 AES key
        而不是 RC4，绕过了基于加密类型异常（事件 4769）的检测
        """
        findings = []
        aes_key_exposed = domain_info.get('aes_key_exposed', False)
        if aes_key_exposed:
            findings.append(KerberosFinding(
                finding_id=self._next_id(), attack_type='diamond_ticket',
                severity='critical',
                description="AES key exposure suspected — Diamond Ticket forgery possible",
                affected_account='krbtgt',
                remediation='Reset krbtgt password twice; verify AES key not in LSASS dump',
                mitre_technique='T1558.001'))
        self._findings.extend(findings)
        return {'findings': [f.to_dict() for f in findings]}

    def analyze(self, tickets=None, accounts=None, domain_info=None,
                delegation_info=None, **kwargs) -> Dict[str, Any]:
        results: Dict[str, Any] = {'success': True, 'findings': []}
        if tickets: results['kerberoasting'] = self.detect_kerberoasting(tickets)
        if accounts: results['asrep_roasting'] = self.detect_asrep_roasting(accounts)
        if domain_info:
            results['golden_ticket'] = self.detect_golden_silver_ticket(domain_info)
            results['diamond_ticket'] = self.detect_diamond_ticket(domain_info)
        if delegation_info: results['s4u_abuse'] = self.detect_s4u_abuse(delegation_info)
        return results

def analyze_kerberos(tickets=None, accounts=None, domain_info=None) -> Dict[str, Any]:
    return KerberosAnalyzer().analyze(tickets=tickets, accounts=accounts,
                                       domain_info=domain_info)

__all__ = ["KerberosAnalyzer","KerberosTicket","KerberosFinding",
           "TicketType","EncryptionType","analyze_kerberos"]
