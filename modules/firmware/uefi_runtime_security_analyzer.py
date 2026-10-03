import logging

log = logging.getLogger(__name__)

class UEFIService:

    GET_VARIABLE = "GetVariable"
    SET_VARIABLE = "SetVariable"
    GET_TIME = "GetTime"
    SET_TIME = "SetTime"
    RESET_SYSTEM = "ResetSystem"
    UPDATE_CAPSULE = "UpdateCapsule"
    QUERY_CAPSULE_CAPABILITIES = "QueryCapsuleCapabilities"
    QUERY_VARIABLE_INFO = "QueryVariableInfo"

    _instances = []

    def __init__(self, value):
        self._val = value
        UEFIService._instances.append(self)

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

    @classmethod
    def __iter__(cls):
        return iter(cls._instances)

UEFIService.GET_VARIABLE = UEFIService("GetVariable")
UEFIService.SET_VARIABLE = UEFIService("SetVariable")
UEFIService.GET_TIME = UEFIService("GetTime")
UEFIService.SET_TIME = UEFIService("SetTime")
UEFIService.RESET_SYSTEM = UEFIService("ResetSystem")
UEFIService.UPDATE_CAPSULE = UEFIService("UpdateCapsule")
UEFIService.QUERY_CAPSULE_CAPABILITIES = UEFIService("QueryCapsuleCapabilities")
UEFIService.QUERY_VARIABLE_INFO = UEFIService("QueryVariableInfo")

class UEFIVulnerability:
    __slots__ = ('vuln_id', 'service', 'severity', 'description', 'cve_id', 'smm_related',)

    def __init__(self, vuln_id, service, severity, description, cve_id="", smm_related=False):
        self.vuln_id = vuln_id
        self.service = service
        self.severity = severity
        self.description = description
        self.cve_id = cve_id
        self.smm_related = smm_related

    def to_dict(self):
        return {
            'vuln_id': self.vuln_id,
            'service': self.service,
            'severity': self.severity,
            'description': self.description,
            'smm_related': self.smm_related
        }

class UEFIRuntimeSecurityAnalyzer:
    """UEFI runtime services security analyzer: maps API calls to known vulnerability patterns."""

    KNOWN_VULNS = [
        UEFIVulnerability("UEFI-001", "SetVariable", "high",
                         "Unauthenticated SetVariable can modify boot configuration",
                         smm_related=False),
        UEFIVulnerability("UEFI-002", "GetVariable", "medium",
                         "GetVariable may disclose sensitive UEFI variables",
                         smm_related=False),
        UEFIVulnerability("UEFI-003", "SMM_CommBuffer", "critical",
                         "SMM communication buffer overflow (CVE-2021-0157)",
                         "CVE-2021-0157", smm_related=True),
        UEFIVulnerability("UEFI-004", "UpdateCapsule", "high",
                         "Unsigned capsule update enables firmware implantation",
                         smm_related=False),
        UEFIVulnerability("UEFI-005", "SMM_Callout", "critical",
                         "SMM arbitrary code execution via callout (SMM Callout vulnerability)",
                         smm_related=True),
        UEFIVulnerability("UEFI-006", "BootService_AfterExit", "high",
                         "Boot Services called after ExitBootServices — UEFI spec violation",
                         smm_related=False),
    ]

    def __init__(self):
        self._findings = []
        self._counter = 0

    def _next_id(self):
        self._counter += 1
        return "UEFI-{:04d}".format(self._counter)

    def check_runtime_service_usage(self, api_calls):
        findings = []

        n_calls = len(api_calls)
        i = 0
        while i < n_calls:
            call = api_calls[i]
            svc_list = UEFIService._instances
            j = 0
            n_svc = len(svc_list)
            while j < n_svc:
                svc = svc_list[j]
                if svc.value.lower() in call.lower():
                    k = 0
                    n_known = len(self.KNOWN_VULNS)
                    while k < n_known:
                        known = self.KNOWN_VULNS[k]
                        if known.service.lower() == svc.value.lower():
                            findings.append({
                                'api_call': call,
                                'service': svc.value,
                                'known_risk': known.to_dict()
                            })
                        k += 1
                j += 1
            i += 1
        return findings

    def check_smm_security(self, strings_data, smm_modules=None):
        findings = []
        s_lower_parts = [s.lower() for s in strings_data]
        strings_lower = ' '.join(s_lower_parts)

        b_has_smm = False
        for kw in ('smm', 'swsmi', 'efiswsmislot'):
            if kw in strings_lower:
                b_has_smm = True
                break

        if b_has_smm:
            findings.append({
                'type': 'smm', 'severity': 'critical',
                'description': 'SMM-related code detected — CommBuffer handling requires review'
            })

        if smm_modules is not None:
            n_mods = len(smm_modules)
            i = 0
            while i < n_mods:
                mod = smm_modules[i]
                if mod.get('has_comm_buffer_overflow', False):
                    findings.append({
                        'type': 'smm_comm_buffer', 'severity': 'critical',
                        'module': mod.get('name', 'unknown'),
                        'description': 'SMM communication buffer overflow risk identified'
                    })
                i += 1

        return findings

    def analyze(self, api_calls=None, strings_data=None, smm_modules=None, **kwargs):
        if api_calls is None:
            api_calls = []
        if strings_data is None:
            strings_data = []

        svc_findings = self.check_runtime_service_usage(api_calls)
        smm_findings = self.check_smm_security(strings_data, smm_modules)

        all_findings = svc_findings + smm_findings

        self._findings = []
        for f in all_findings:
            if isinstance(f, dict):
                self._findings.append(UEFIVulnerability(**f))
            else:
                self._findings.append(f)

        critical_count = 0
        for f in svc_findings:
            if f.get('known_risk', {}).get('severity') == 'critical':
                critical_count += 1

        for f in smm_findings:
            if f.get('severity') == 'critical':
                critical_count += 1

        # Derive aggregate risk level from finding severity counts
        if critical_count > 0:
            s_risk = 'critical'
        elif len(svc_findings) > 0:
            s_risk = 'high'
        else:
            s_risk = 'medium'

        return {
            'success': True,
            'total_findings': len(all_findings),
            'critical_findings': critical_count,
            'known_uefi_vulns': [v.to_dict() for v in self.KNOWN_VULNS],
            'findings': all_findings[:50],
            'risk_level': s_risk
        }

def analyze_uefi_runtime_security(
    api_calls,
    strings_data=None,
    smm_modules=None,
    **kwargs):
    analyzer = UEFIRuntimeSecurityAnalyzer()
    return analyzer.analyze(api_calls=api_calls, strings_data=strings_data,
                           smm_modules=smm_modules)

__all__ = ["UEFIRuntimeSecurityAnalyzer", "UEFIVulnerability", "UEFIService",
           "analyze_uefi_runtime_security"]
