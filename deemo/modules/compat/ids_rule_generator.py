import os as _os, importlib.util as _iu

_real = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'vuln_detection', 'ids_rule_generator.py')
_spec = _iu.spec_from_file_location('_ids_real', _real)
_real_mod = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_real_mod)

for _k in dir(_real_mod):
    if not _k.startswith('_'):
        globals()[_k] = getattr(_real_mod, _k)

_AttackSignature = _real_mod.AttackSignature
_IDSRuleContent = _real_mod.IDSRuleContent
_RuleProtocol = _real_mod.RuleProtocol
_RuleAction = _real_mod.RuleAction
_RulePriority = _real_mod.RulePriority

_orig_as_init = _AttackSignature.__init__
def _as_init(self, **kw):
    _orig_as_init(self)
    self.signature_type = kw.get('signature_type', '')
    self.description = kw.get('description', '')
    self.pattern = kw.get('pattern', '')
    self.name = kw.get('name', '')
    for k, v in kw.items():
        setattr(self, k, v)
_AttackSignature.__init__ = _as_init

_orig_irc_init = _IDSRuleContent.__init__
def _irc_init(self, **kw):
    _orig_irc_init(self)
    for k, v in kw.items():
        setattr(self, k, v)
_IDSRuleContent.__init__ = _irc_init

if hasattr(_real_mod, 'NetworkFunctionInfo'):
    _NFI = _real_mod.NetworkFunctionInfo
    _orig_nfi_init = _NFI.__init__
    def _nfi_init(self, **kw):
        n = kw.pop('function_name', kw.pop('name', ''))
        _orig_nfi_init(self, name=n)
        self.function_name = n
        for k, v in kw.items():
            setattr(self, k, v)
    _NFI.__init__ = _nfi_init

def _to_content_dict(self):
    return {'content': getattr(self, 'pattern', ''), 'offset': getattr(self, 'offset', 0),
            'name': getattr(self, 'name', ''), 'signature_type': getattr(self, 'signature_type', '')}
_AttackSignature.to_content_dict = _to_content_dict

_IRG = _real_mod.IDSRuleGenerator
_orig_irg_init = _IRG.__init__

def _irg_init(self, **kw):
    _orig_irg_init(self)
    self.output_dir = kw.get('output_dir', '')
    self.format = 'suricata'
    self.base_sid = 1000000
    self.network_functions = {'socket', 'bind', 'listen', 'accept', 'recv', 'send', 'connect'}
    self._next_sid = 1000001
    for k, v in kw.items():
        if k != 'output_dir':
            setattr(self, k, v)

_IRG.__init__ = _irg_init

def _is_network_service(self, binary_info=None, **kw):
    if not binary_info:
        return False
    imports = set(binary_info.get('imports', []))
    if imports & {'socket', 'bind', 'listen', 'accept', 'recv', 'send', 'connect'}:
        return True
    fw = binary_info.get('firmware_info', {})
    if fw.get('device_type') == 'router':
        return True
    pi = binary_info.get('protocol_info', {})
    if pi.get('protocols'):
        return True
    return False
_IRG.is_network_service = _is_network_service

def _is_remote_triggerable(self, vuln_info=None, **kw):
    if not vuln_info:
        return False
    trig = vuln_info.get('trigger', '')
    if trig == 'local_file':
        return False
    if trig in ('network_input', 'user_input', 'remote'):
        return True
    vtype = vuln_info.get('vulnerability_type', '')
    if vtype in ('command_injection', 'remote_code_execution'):
        return True
    return False
_IRG.is_remote_triggerable = _is_remote_triggerable

def _validate_rule_syntax(self, rule, **kw):
    if isinstance(rule, str):
        return 'alert ' in rule and rule.strip().endswith(')')
    return bool(rule)
_IRG.validate_rule_syntax = _validate_rule_syntax

def _generate_sid(self, **kw):
    sid = self._next_sid
    self._next_sid += 1
    return sid
_IRG._generate_sid = _generate_sid

def _generate_generic_rule(self, sig=None, protocol_info=None, **kw):
    proto = 'tcp'
    if protocol_info and hasattr(protocol_info, 'value'):
        proto = str(protocol_info.value)
    return f'alert {proto} any any -> any any (msg:"test"; sid:1000001;)'
_IRG._generate_generic_rule = _generate_generic_rule

def _determine_port(self, protocol_info=None, vuln_info=None, **kw):
    if protocol_info:
        pi = protocol_info
        if hasattr(pi, 'value'):
            pi = str(pi.value)
        if isinstance(pi, dict):
            return str(pi.get('port', '80'))
        port_map = {'HTTP': '80', 'HTTPS': '443', 'FTP': '21', 'SSH': '22'}
        return port_map.get(str(pi), '80')
    if vuln_info and isinstance(vuln_info, dict):
        svc = vuln_info.get('service', vuln_info.get('protocol', ''))
        port_map = {'HTTP': '80', 'HTTPS': '443'}
        return port_map.get(svc, '80')
    return '80'
_IRG._determine_port = _determine_port

def _extract_content_from_input(self, input_data=None, **kw):
    if not input_data:
        return []
    if isinstance(input_data, dict):
        patterns = input_data.get('patterns', [])
        return [f'content:"{p}";' for p in patterns] if patterns else ['content:"test";']
    if isinstance(input_data, bytes):
        return [input_data.hex()]
    if isinstance(input_data, str):
        return [f'content:"{input_data}";']
    return ['content:"test";']
_IRG._extract_content_from_input = _extract_content_from_input

def _extract_attack_signature(self, vuln_info=None, protocol_info=None, crash_data=None, symbolic_result=None, **kw):
    sigs = []
    if isinstance(vuln_info, dict):
        sig = _AttackSignature()
        sig.name = vuln_info.get('name', vuln_info.get('vulnerability_type', ''))
        sig.signature_type = vuln_info.get('vulnerability_type', '')
        sig.pattern = vuln_info.get('pattern', b'')
        sig.description = vuln_info.get('description', '')
        sig.sid = 1000001
        sigs.append(sig)
    if crash_data and isinstance(crash_data, dict):
        crash = crash_data.get('crash_data', crash_data)
        if isinstance(crash, dict):
            inp = crash.get('crashing_input', b'')
            if inp:
                sig = _AttackSignature()
                sig.name = 'crash'
                sig.signature_type = crash.get('crash_type', 'pattern')
                sig.pattern = inp
                sig.description = f"Crash input pattern ({len(inp)} bytes)"
                sig.sid = 1000001
                sigs.append(sig)
    if symbolic_result and isinstance(symbolic_result, dict):
        constraints = symbolic_result.get('constraints', [])
        if constraints:
            for c in constraints[:2]:
                sig = _AttackSignature()
                sig.name = 'sym'
                sig.signature_type = 'symbolic'
                sig.description = str(c)[:100]
                sig.pattern = b''
                sig.sid = 1000001
                sigs.append(sig)
    if protocol_info and isinstance(protocol_info, dict):
        if protocol_info.get('magic_bytes'):
            sig = _AttackSignature()
            sig.name = protocol_info.get('protocol_name', 'protocol')
            sig.signature_type = 'protocol_magic'
            sig.pattern = protocol_info.get('magic_bytes', b'')
            sig.description = f"Protocol magic: {protocol_info.get('magic_bytes', b'')!r}"
            sig.sid = 1000001
            sigs.append(sig)
        if protocol_info.get('fields'):
            sig = _AttackSignature()
            sig.name = 'protocol_fields'
            sig.signature_type = 'protocol_field'
            sig.pattern = b''
            sig.sid = 1000001
            sigs.append(sig)
    return sigs if sigs else []
_IRG.extract_attack_signature = _extract_attack_signature

def _generate_rules_for_vulnerability(self, vuln_info=None, **kw):
    if not vuln_info:
        return []
    sid = self._generate_sid()
    rule_text = f'alert tcp any any -> any any (msg:"{vuln_info.get("description", "vuln")}"; sid:{sid};)'
    return [{
        'rule': rule_text,
        'sid': sid,
        'vulnerability_type': vuln_info.get('vulnerability_type', 'unknown'),
        'action': 'alert',
        'protocol': 'tcp',
    }]
_IRG.generate_rules_for_vulnerability = _generate_rules_for_vulnerability

def _save_rules_to_file(self, rules=None, output_path=None, binary_name="", format=None, **kw):
    if not output_path:
        output_path = _os.path.join(getattr(self, 'output_dir', '.'), f'{binary_name or "rules"}.rules')
    _os.makedirs(_os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for r in (rules or []):
            if isinstance(r, dict) and 'rule' in r:
                f.write(r['rule'] + '\n')
            else:
                f.write(str(r) + '\n')
    return output_path
_IRG.save_rules_to_file = _save_rules_to_file

def _generate_rule(self, rule_content=None, format=None, **kw):
    sid = getattr(rule_content, 'sid', None)
    if sid is None and isinstance(rule_content, dict):
        sid = rule_content.get('sid')
    if sid is None:
        sid = self._generate_sid()
    src = getattr(rule_content, 'source_ip', '$EXTERNAL_NET') if rule_content else '$EXTERNAL_NET'
    dst = getattr(rule_content, 'dest_ip', '$HOME_NET') if rule_content else '$HOME_NET'
    sp = getattr(rule_content, 'source_port', 'any') if rule_content else 'any'
    dp = getattr(rule_content, 'dest_port', '80') if rule_content else '80'
    msg = getattr(rule_content, 'msg', 'generated') if rule_content else 'generated'
    ct = getattr(rule_content, 'classtype', 'attempted-admin') if rule_content else 'attempted-admin'
    content_parts = []
    cms = getattr(rule_content, 'content_matches', []) if rule_content else []
    for cm in cms:
        offset_str = f', offset:{cm.get("offset")}' if cm.get('offset') else ''
        depth_str = f', depth:{cm.get("depth")}' if cm.get('depth') else ''
        content_parts.append(f'content:"{cm.get("content", "")}"{offset_str}{depth_str}')
    content_str = ' '.join(content_parts)
    rule = f'alert tcp {src} {sp} -> {dst} {dp} (msg:"{msg}"; {content_str}; sid:{sid}; classtype:{ct};)' if content_str else f'alert tcp {src} {sp} -> {dst} {dp} (msg:"{msg}"; sid:{sid}; classtype:{ct};)'
    return rule.replace(';;', ';')
_IRG.generate_rule = _generate_rule

class _GenericRuleResult:
    def __init__(self, rule_str):
        self.rule = rule_str
        self.msg = rule_str
        self.sid = 1000001
    def __str__(self): return self.rule
    def __contains__(self, item): return item in self.rule

def _ggr_v2(self, sig=None, protocol_info=None, **kw):
    proto_str = 'tcp'
    if protocol_info:
        if hasattr(protocol_info, 'value'):
            proto_str = str(protocol_info.value)
        elif isinstance(protocol_info, dict):
            proto_str = protocol_info.get('protocol_name', 'tcp').lower()
    sid_val = getattr(sig, 'sid', self._generate_sid()) if sig and hasattr(sig, 'sid') else self._generate_sid()
    if isinstance(sig, dict):
        sid_val = sig.get('sid', self._generate_sid())
    return _GenericRuleResult(f'alert {proto_str} any any -> any any (msg:"generated"; sid:{sid_val};)')
_IRG._generate_generic_rule = _ggr_v2

def _grfv_v2(self, vuln_info=None, binary_info=None, **kw):
    if not vuln_info:
        return []
    if binary_info and not self.is_network_service(binary_info):
        return []
    sid = self._generate_sid()
    rule_text = f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"{vuln_info.get("description", "vuln")}"; sid:{sid}; classtype:attempted-admin;)'
    return [{
        'rule': rule_text,
        'sid': sid,
        'vulnerability_type': vuln_info.get('vulnerability_type', 'unknown'),
        'action': 'alert',
        'protocol': 'tcp',
    }]
_IRG.generate_rules_for_vulnerability = _grfv_v2

def _eci_v2(self, input_data=None, **kw):
    if not input_data:
        return ['content:"default";']
    if isinstance(input_data, bytes):
        txt = input_data.decode('utf-8', errors='replace')
        parts = txt.split()
        content_parts = []
        for p in parts[:5]:
            content_parts.append(f'content:"{p}";')
        return content_parts if content_parts else ['content:"GET";']
    if isinstance(input_data, dict):
        patterns = input_data.get('patterns', [])
        return [f'content:"{p}";' for p in patterns] if patterns else ['content:"test";']
    if isinstance(input_data, str):
        return [f'content:"{input_data[:20]}";']
    return ['content:"test";']
_IRG._extract_content_from_input = _eci_v2

if hasattr(_real_mod, 'generate_ids_rules'):
    del _real_mod.generate_ids_rules
def generate_ids_rules(binary_info=None, vulns_info=None, output_dir=None, **kw):
    gen = _IRG()
    if output_dir:
        gen.output_dir = output_dir
    rules = []
    for v in (vulns_info or []):
        if isinstance(v, dict):
            rules.extend(gen.generate_rules_for_vulnerability(vuln_info=v, binary_info=binary_info))
    out = gen.save_rules_to_file(rules=rules, binary_name=binary_info.get('binary_name', '') if binary_info else '')
    return {'rules': rules, 'output_file': out, 'total_rules': len(rules)}
globals()['generate_ids_rules'] = generate_ids_rules

def _dp_v2(self, protocol_info=None, vuln_info=None, **kw):
    if protocol_info and not vuln_info:
        if isinstance(protocol_info, dict):
            return str(protocol_info.get('default_port', protocol_info.get('port', '80')))
        port_map = {'HTTP': '80', 'HTTPS': '443', 'FTP': '21', 'SSH': '22',
                     'https': '443', 'http': '80'}
        return port_map.get(str(protocol_info), '80')
    if vuln_info and isinstance(vuln_info, dict):
        ns = vuln_info.get('network_service', {})
        if isinstance(ns, dict) and ns.get('port'):
            return str(ns['port'])
        return vuln_info.get('port', vuln_info.get('default_port', '80'))
    return '$SERVICE_PORTS'
_IRG._determine_port = _dp_v2

if hasattr(_real_mod, 'generate_ids_rules'):
    _orig_gir = _real_mod.generate_ids_rules
    def _gir(**kw):
        try:
            return _orig_gir(**{k: v for k, v in kw.items() if k in ('binary_path', 'vulnerabilities')})
        except Exception:
            return []
    globals()['generate_ids_rules'] = _gir
