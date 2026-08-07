# IR 规则匹配引擎
from typing import List, Dict, Any, Optional
import re

IR_RULES = {}

def _init_rules():
    global IR_RULES
    IR_RULES = {
        "uaf": {
            "pattern": "free.*LDle",
            "description": "free() followed by load from freed pointer",
            "severity": "Critical",
            "cwe": "CWE-416",
        },
        "double_free": {
            "pattern": "free.*free",
            "description": "two consecutive free() on same path",
            "severity": "Critical",
            "cwe": "CWE-415",
        },
        "format_string": {
            "pattern": "printf.*[^x22].*r",
            "description": "printf with variable format argument",
            "severity": "High",
            "cwe": "CWE-134",
        },
    }

_init_rules()

def match_ir_rules(normalized_ir):
    findings = []
    if not normalized_ir: return findings
    for rule_id, rule in IR_RULES.items():
        pat = rule.get("pattern", "")
        if not pat: continue
        for m in re.finditer(pat, normalized_ir, re.MULTILINE):
            findings.append({
                "rule_id": rule_id,
                "matched_text": m.group(0)[:120],
                "severity": rule["severity"],
                "cwe": rule["cwe"],
                "description": rule["description"],
                "confidence": 0.75,
            })
    return findings

def load_ir_rules_from_yaml(yaml_path):
    try:
        import yaml
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        for rule in data.get("ir_rules", []):
            rid = rule.get("id", "")
            if rid:
                IR_RULES[rid] = {
                    "pattern": rule.get("ir_pattern", ""),
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", "Medium"),
                    "cwe": rule.get("cwe", ""),
                }
    except Exception:
        pass
