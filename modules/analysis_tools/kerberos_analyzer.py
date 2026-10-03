from enum import StrEnum
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class TicketType(StrEnum):
    TGT = "tgt"
    TGS = "tgs"
    AS_REP = "as_rep"
    AS_REQ = "as_req"

class EncryptionType:
    RC4_HMAC = 23
    AES128_CTS = 17
    AES256_CTS = 18
    DES_CBC_CRC = 1
    DES_CBC_MD5 = 3

@dataclass
class KerberosTicket:
    ticket_type: Any = None
    realm: Any = None
    service_name: Any = None
    client_name: Any = None
    encryption_type: Any = None
    validity_start: Any = None
    validity_end: Any = None
    renewal_end: Any = None
    flags: Any = None
    pac_present: Any = None
    pac_signed: Any = None
    is_weak: Any = None

    @property
    def lifetime_hours(self) -> float:
        # 简单启发式：AS-REP/TGT 默认 10 小时，TGS 按票据生命周期推断
        if self.validity_start and self.validity_end:
            delta = (self.validity_end - self.validity_start).total_seconds()
            if delta > 0:
                return round(delta / 3600.0, 2)
        return 10.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ticket_type': self.ticket_type.value if self.ticket_type else None,
            'realm': self.realm,
            'service_name': self.service_name,
            'encryption_type': self.encryption_type.name if self.encryption_type else None,
            'is_weak': self.is_weak
        }


class KerberosFinding:
    __slots__ = ('finding_id', 'attack_type', 'severity', 'description', 'affected_account', 'spn', 'encryption_type', 'remediation', 'mitre_technique',)

    def __init__(self, finding_id, attack_type, severity, description, affected_account="", spn="", encryption_type="", remediation="", mitre_technique=""):
        self.finding_id = finding_id
        self.attack_type = attack_type
        self.severity = severity
        self.description = description
        self.affected_account = affected_account
        self.spn = spn
        self.encryption_type = encryption_type
        self.remediation = remediation
        self.mitre_technique = mitre_technique

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


class KerberosAnalyzer:

    WEAK_ETYPES = {EncryptionType.RC4_HMAC, EncryptionType.DES_CBC_CRC,
                   EncryptionType.DES_CBC_MD5}

    DANGEROUS_SPN_PATTERNS = [
        'MSSQLSvc', 'HTTP', 'TERMSRV', 'WSMAN', 'host', 'cifs',
        'exchange', 'ldap', 'gc', 'DNS',
    ]

    def __init__(self):
        self._findings: List[KerberosFinding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"KRB-{self._counter:04d}"

    def detect_kerberoasting(self, tickets: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        for ticket in tickets:
            etype = ticket.get('encryption_type', 23)
            spn = ticket.get('service_name', '')
            if int(etype) in {e.value for e in self.WEAK_ETYPES}:
                findings.append(KerberosFinding(
                    finding_id=self._next_id(), attack_type='kerberoasting',
                    severity='high',
                    description=f'Service {spn} uses weak encryption type ({etype}) -- offline crack feasible',
                    spn=spn, encryption_type=str(etype),
                    remediation='Rotate service account password to 25+ character random string',
                    mitre_technique='T1558.003'))

        high_value = [t for t in tickets
                     if any(p.lower() in t.get('service_name', '').lower()
                           for p in self.DANGEROUS_SPN_PATTERNS)]
        for ticket in high_value:
            findings.append(KerberosFinding(
                finding_id=self._next_id(), attack_type='kerberoasting',
                severity='critical' if 'MSSQLSvc' in ticket.get('service_name', '')
                else 'high',
                description=f'High-value SPN: {ticket.get("service_name", "")}',
                spn=ticket.get('service_name', ''),
                remediation='Audit service account privileges; consider gMSA',
                mitre_technique='T1558.003'))

        self._findings.extend(findings)
        return {'total_tickets': len(tickets), 'findings': [f.to_dict() for f in findings]}

    def detect_asrep_roasting(self, accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect AS-REP Roasting: accounts lacking Kerberos pre-authentication."""
        findings = []
        for account in accounts:
            if not account.get('requires_preauth', True):
                findings.append(KerberosFinding(
                    finding_id=self._next_id(), attack_type='asrep_roasting',
                    severity='high',
                    description=f"Account {account.get('name', '?')} does not require Kerberos pre-authentication -- "
                               f"AS-REP can be requested and cracked offline",
                    affected_account=account.get('name', ''),
                    remediation='Enable Kerberos pre-authentication (clear UF_DONT_REQUIRE_PREAUTH)',
                    mitre_technique='T1558.004'))
        self._findings.extend(findings)
        return {'total_accounts': len(accounts), 'findings': [f.to_dict() for f in findings]}

    def detect_golden_silver_ticket(self, domain_info: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        if domain_info.get('krbtgt_password_age_days', 0) > 365:
            findings.append(KerberosFinding(
                finding_id=self._next_id(), attack_type='golden_ticket',
                severity='critical',
                description=f"krbtgt account password unchanged for {domain_info.get('krbtgt_password_age_days', 0)} days",
                affected_account='krbtgt',
                remediation='Reset krbtgt account password twice immediately',
                mitre_technique='T1558.001'))
        self._findings.extend(findings)
        return {'findings': [f.to_dict() for f in findings]}

    def analyze(self, tickets: Optional[List[Dict[str, Any]]] = None,
                accounts: Optional[List[Dict[str, Any]]] = None,
                domain_info: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        results = {'success': True, 'findings': []}
        if tickets:
            results['kerberoasting'] = self.detect_kerberoasting(tickets)
        if accounts:
            results['asrep_roasting'] = self.detect_asrep_roasting(accounts)
        if domain_info:
            results['golden_ticket'] = self.detect_golden_silver_ticket(domain_info)
        return results


def analyze_kerberos(tickets: Optional[List[Dict[str, Any]]] = None,
                     accounts: Optional[List[Dict[str, Any]]] = None,
                     domain_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    analyzer = KerberosAnalyzer()
    return analyzer.analyze(tickets=tickets, accounts=accounts, domain_info=domain_info)


__all__ = ["KerberosAnalyzer", "KerberosTicket", "KerberosFinding",
           "TicketType", "EncryptionType", "analyze_kerberos"]