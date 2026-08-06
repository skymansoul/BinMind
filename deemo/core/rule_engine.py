"""
YAML-rule-based static vulnerability pattern matching engine.

Loads rule files from data/rules/ and runs regex matching on decompiled code.
Each rule outputs matched_func, severity, cwe, and evidence. Format is compatible
with static_analysis.py but supports externalized rule sets so new patterns
don't require code changes.

Complementary to static_analysis.DANGEROUS_FUNCTIONS:
  - DANGEROUS_FUNCTIONS: O(1) per import via import table matching (faster)
  - rule_engine: semantic-level pattern matching on decompiled code (O(n*m))

Falls back to JSON parsing when PyYAML is not available.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "rules")


def _load_yaml_safe(path: str) -> Optional[Dict[str, Any]]:
    """Load YAML file: prefer yaml library, fall back to manual parsing for simple structures."""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        pass

    # Manual parse for simple rule structures only (rules list + fixed fields per rule).
    # Full YAML parsing requires a proper parser; this is a fallback for no-PyYAML envs.
    try:
        import json as _json
        # YAML is a superset of JSON; simple structures parse as JSON.
        # Comment lines are stripped below.
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # Remove YAML comment lines (starting with #)
        lines = [l for l in content.splitlines()
                 if not l.strip().startswith("#")]
        clean = "\n".join(lines)
        # Try JSON parsing as fallback for simple cases
        return _json.loads(clean)
    except (json.JSONDecodeError, OSError):
        return None


def load_rules(rule_dir: str = _RULES_DIR) -> List[Dict[str, Any]]:
    """
    Load all YAML rule files from a directory.

    Returns a flat list of rules with source file provenance.
    Returns an empty list for nonexistent directories.

    Design: static file loading instead of dynamic module imports (unlike
    hooks.py) because rule files are pure data and should not have code
    execution privileges.
    """
    if not os.path.isdir(rule_dir):
        return []

    all_rules: List[Dict[str, Any]] = []
    for fname in sorted(os.listdir(rule_dir)):
        if not fname.endswith((".yaml", ".yml", ".json")):
            continue

        fpath = os.path.join(rule_dir, fname)
        doc = _load_yaml_safe(fpath)
        if doc is None:
            _log.debug("Failed to load rule file: %s", fname)
            continue

        for rule in doc.get("rules", []):
            rule["_source_file"] = fname
            all_rules.append(rule)

    _log.info("Loaded %d rules from %s", len(all_rules), rule_dir)
    return all_rules


def apply_rules(
    pseudocode: str,
    func_name: str,
    rules: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Execute all rules against a single function's decompiled code.

    Each match contains rule_id, description, severity, cwe, function name,
    and evidence (code snippet truncated to 120 chars).

    Time complexity: O(|rules| * |pseudocode|). For large rule sets (>100 rules),
    pre-filter by func_pattern before running the full regex.

    Args:
        pseudocode: decompiled pseudocode text
        func_name: function name
        rules: rule list from load_rules()

    Returns:
        List of matches sorted by severity
    """
    findings = []
    seen_ids = set()

    for rule in rules:
        rule_id = rule.get("id", "")
        # Pre-filter: skip regex if func_pattern is specified and absent from pseudocode
        func_pat = rule.get("func_pattern", "")
        if func_pat and func_pat not in pseudocode:
            continue

        pattern = rule.get("pattern", "")
        if not pattern:
            continue

        try:
            compiled = re.compile(pattern, re.MULTILINE | re.DOTALL)
            matches = compiled.finditer(pseudocode)
            for m in matches:
                if rule_id in seen_ids:
                    break  # Report each rule once per function
                seen_ids.add(rule_id)

                evidence = m.group(0).strip()[:120]
                findings.append({
                    "rule_id": rule_id,
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", "Medium"),
                    "cwe": rule.get("cwe", ""),
                    "function": func_name,
                    "evidence": evidence,
                    "source_file": rule.get("_source_file", ""),
                })
        except re.error as e:
            _log.debug("Regex error in rule %s: %s", rule_id, e)
            continue

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

    return findings


def scan_with_rules(
    binary_path: str,
    func_names: Optional[List[str]] = None,
    rule_dir: str = _RULES_DIR,
) -> List[Dict[str, Any]]:
    """
    Perform a complete rule scan on a binary file.

    Iterates specified functions (or all) and applies all rules to each decompiled function.

    Args:
        binary_path: ELF file path
        func_names:  function name list, None = auto-select (user funcs first)
        rule_dir:    rule file directory

    Returns:
        All matching entries
    """
    rules = load_rules(rule_dir)
    if not rules:
        _log.debug("No rules loaded, skipping rule-based scan")
        return []

    from core.decompiler import list_functions, decompile_function

    # Function selection logic, consistent with pipeline.py
    if func_names is None:
        all_funcs = list_functions(binary_path)
        priority = ("main", "vuln", "win", "get_flag", "read_input",
                    "process", "parse", "handle", "init")
        func_names = [f for f in priority if f in all_funcs]
        if not func_names:
            func_names = all_funcs[:20]

    all_findings = []
    for fname in func_names:
        try:
            decomp = decompile_function(binary_path, fname)
            pseudo = decomp.get("pseudocode", "")
            if not pseudo:
                continue
            findings = apply_rules(pseudo, fname, rules)
            all_findings.extend(findings)
        except Exception as e:
            _log.debug("Rule scan failed for %s: %s", fname, e)

    _log.info("Rule scan: %d findings across %d functions",
              len(all_findings), len(func_names))
    return all_findings
