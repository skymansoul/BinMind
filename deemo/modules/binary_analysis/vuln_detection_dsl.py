from typing import Dict, List, Any
import logging, os, re, yaml

logger = logging.getLogger(__name__)


class RuleAction:
    ALERT = "alert"; IGNORE = "ignore"; TAG = "tag"

class RuleSeverity:
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class DSLRule:
    __slots__ = ('id', 'name', 'severity', 'action', 'conditions', 'description', 'cwe_id', 'false_positive_rate')

    def __init__(self, id: str, name: str, severity: RuleSeverity, action: RuleAction = None,
                 conditions: List[Dict] = None, description: str = "", cwe_id: str = "",
                 false_positive_rate: float = 0.0):
        self.id = id
        self.name = name
        self.severity = severity
        self.action = action if action is not None else RuleAction.ALERT
        self.conditions = conditions if conditions is not None else []
        self.description = description
        self.cwe_id = cwe_id
        self.false_positive_rate = false_positive_rate


class VulnDetectionDSL:

    BUILTIN_RULES = [
        DSLRule("CWE-120", "Buffer Copy without Checking Size of Input",
                RuleSeverity.CRITICAL, conditions=[
                    {'pattern': r'\b(?:strcpy|strcat|sprintf|gets)\s*\(', 'location': 'any'}],
                cwe_id="CWE-120"),
        DSLRule("CWE-78", "OS Command Injection",
                RuleSeverity.CRITICAL, conditions=[
                    {'pattern': r'\b(?:system|popen|exec[lv]?[pe]?|CreateProcess)\s*\(', 'location': 'any'}],
                cwe_id="CWE-78"),
        DSLRule("CWE-416", "Use After Free",
                RuleSeverity.CRITICAL, conditions=[
                    {'pattern': r'\b(?:free|delete)\s*\(.*?(?:malloc|\w+\s*->|\.\w+)', 'location': 'any'}],
                cwe_id="CWE-416"),
        DSLRule("CWE-798", "Hardcoded Credentials",
                RuleSeverity.HIGH, conditions=[
                    {'pattern': r'(?:password|passwd|secret|api_key|token)\s*=\s*"(?![A-Z]{{8,}})', 'location': 'strings'}],
                cwe_id="CWE-798"),
        DSLRule("CWE-327", "Weak Cryptography",
                RuleSeverity.HIGH, conditions=[
                    {'pattern': r'\b(?:DES_|RC4|MD4|MD5|SHA1)', 'location': 'strings'},
                    {'pattern': r'\b(?:ECB|CBC)', 'location': 'strings'}],
                cwe_id="CWE-327"),
    ]

    def __init__(self, rules_dir: str = ""): self.rules = list(self.BUILTIN_RULES); self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str):
        if not rules_dir or not os.path.isdir(rules_dir): return
        for fname in os.listdir(rules_dir):
            if fname.endswith(('.yml', '.yaml')):
                try:
                    with open(os.path.join(rules_dir, fname)) as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, list):
                            for r in data:
                                self.rules.append(DSLRule(**r))
                except Exception as e: logger.warning(f"ruleloadfailed {fname}: {e}")

    def compile_rules(self) -> Dict[str, List[re.Pattern]]:
        """compile所有rule为正则表达式"""
        compiled = {}
        for rule in self.rules:
            compiled[rule.id] = [re.compile(c['pattern'], re.IGNORECASE) for c in rule.conditions]
        return compiled

    def scan(self, binary_path: str, disasm: str = "", strings: str = "") -> List[Dict]:
        """executerule扫描"""
        if not disasm:
            try:
                import subprocess
                r = subprocess.run(['r2','-q','-c','aaaa; pD $SS @ $S; q',binary_path],
                    capture_output=True, text=True, timeout=120, encoding='utf-8', errors='replace')
                disasm = r.stdout
                r2 = subprocess.run(['r2','-q','-c','izz; q',binary_path],
                    capture_output=True, text=True, timeout=60, encoding='utf-8', errors='replace')
                strings = r2.stdout
            except Exception as e: logger.warning(f"radare2scanfailed: {e}")

        findings = []
        compiled = self.compile_rules()
        for rule in self.rules:
            matched = True
            for cond in rule.conditions:
                loc = disasm if cond.get('location','any') != 'strings' else strings
                if not any(p.search(loc) for p in compiled.get(rule.id, [])):
                    matched = False; break
            if matched:
                findings.append({'rule_id': rule.id, 'name': rule.name, 'severity': rule.severity,
                                 'cwe': rule.cwe_id, 'action': rule.action, 'description': rule.description})
        return findings


def scan_with_dsl_rules(binary_path: str) -> Dict[str,Any]:
    dsl = VulnDetectionDSL()
    findings = dsl.scan(binary_path)
    return {'success': True, 'findings': len(findings), 'rules_loaded': len(dsl.rules),
            'results': findings[:20]}
