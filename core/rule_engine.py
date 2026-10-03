"""
基于YAML规则文件的静态漏洞模式匹配引擎。
从 data/rules/ 加载规则并在反编译代码上做正则匹配, 输出 rule_id/severity/cwe/evidence;
与 static_analysis.DANGEROUS_FUNCTIONS 互补 (后者导入表O(1)匹配, 本引擎语义级O(n*m)), PyYAML 缺失时回退 JSON 解析。
"""


import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "rules")


def _load_yaml_safe(path: str) -> Optional[Dict[str, Any]]:
    """加载YAML文件: 优先yaml库, 简单结构回退手动解析。"""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        pass

    # 仅手动解析简单规则结构 (rules列表+固定字段); 完整YAML解析需正式解析器, 此为无PyYAML环境的回退。
    try:
        # YAML是JSON的超集; 简单结构可作JSON解析, 注释行在下文去除。
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # 去除YAML注释行 (以#开头)
        lines = [l for l in content.splitlines()
                 if not l.strip().startswith("#")]
        clean = "\n".join(lines)
        # 简单场景回退JSON解析
        return json.loads(clean)
    except (json.JSONDecodeError, OSError):
        return None


def load_rules(rule_dir: str = _RULES_DIR) -> List[Dict[str, Any]]:
    """
    加载目录下的全部YAML规则文件。

    返回带源文件溯源的扁平规则列表; 目录不存在时返回空列表。
    采用静态文件加载而非动态模块导入: 规则文件是纯数据, 不应具备代码执行权限。
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
    对单个函数的反编译代码执行全部规则。

    每个匹配包含 rule_id/description/severity/cwe/函数名/evidence;
    evidence 截断至 120 字符, 结果按严重度排序。
    """
    findings = []
    seen_ids = set()

    for rule in rules:
        rule_id = rule.get("id", "")
        # 预过滤: func_pattern 指定且伪代码中不存在时跳过正则
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
                    break  # 每个函数每条规则只报告一次
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

    # 按严重程度排序
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

    return findings


def scan_with_rules(
    binary_path: str,
    func_names: Optional[List[str]] = None,
    rule_dir: str = _RULES_DIR,
) -> List[Dict[str, Any]]:
    """
    对二进制文件执行完整规则扫描。

    遍历指定函数 (缺省自动选择用户函数优先) 并对每个反编译
    函数应用全部规则, 返回全部匹配项。
    """
    rules = load_rules(rule_dir)
    if not rules:
        _log.debug("No rules loaded, skipping rule-based scan")
        return []

    from core.decompiler import list_functions, decompile_function

    # 函数选择逻辑, 与 pipeline.py 一致
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
