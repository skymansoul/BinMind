"""
基于 YAML 规则的静态漏洞模式匹配引擎。

从 data/rules/ 加载规则文件，在反编译代码上运行正则匹配。
每条规则输出 matched_func / severity / cwe / evidence，格式与
static_analysis.py 兼容但支持外部化规则集——新增漏洞模式无需改代码。

与 static_analysis.DANGEROUS_FUNCTIONS 的关系: 互补而非替代。
DANGEROUS_FUNCTIONS 基于导入表做快速匹配（O(1) per import），
rule_engine 对反编译代码做语义级模式匹配（O(n*m) per function）。
对于已知危险函数直接走 DANGEROUS_FUNCTIONS（更快），
对于跨语句的模式（如 free 后使用同一指针）走 rule_engine。

YAML 解析使用标准库（无外部依赖），缺失 YAML 模块时回退到 JSON。
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
    """加载 YAML 文件——优先 yaml 库，不可用时手动解析简单结构。"""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        pass

    # 手动解析——仅支持本项目中规则的简单结构（rules 列表 + 每个 rule 的固定字段）
    # 复杂 YAML 的正确解析需要完整 parser，此处只为无 PyYAML 环境提供降级
    try:
        import json as _json
        # YAML 是 JSON 的超集，简单结构可直接按 JSON 解析
        # 实际规则文件中的注释行会在以下处理中被跳过
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # 移除 YAML 注释行 (# 开头)
        lines = [l for l in content.splitlines()
                 if not l.strip().startswith("#")]
        clean = "\n".join(lines)
        # 尝试 JSON 解析（简单情况的回退）
        return _json.loads(clean)
    except (json.JSONDecodeError, OSError):
        return None


def load_rules(rule_dir: str = _RULES_DIR) -> List[Dict[str, Any]]:
    """
    从目录加载全部 YAML 规则文件。

    返回扁平化的规则列表，每条规则保留其来源文件信息。
    不存在的目录返回空列表。

    设计权衡:
      不使用动态模块导入（如 hooks.py 的做法），因为规则文件是纯数据，
      不应有任意代码执行权限。YAML 解析的风险可控。
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
    在单函数的反编译代码上执行全部规则。

    返回匹配项的列表，每个匹配项包含:
      - rule_id:    规则 ID
      - description: 规则描述
      - severity:   严重度
      - cwe:        CWE 编号
      - function:   匹配所在的函数名
      - evidence:   匹配到的代码片段（截断至 120 字符）

    时间复杂度: O(|rules| * |pseudocode|)，对大型规则集 (>100条) 建议
    按 func_pattern 预过滤——先检查伪代码是否含有关键函数名再运行全正则。

    Args:
        pseudocode: 反编译的伪代码文本
        func_name:  函数名
        rules:      load_rules() 返回的规则列表

    Returns:
        匹配项列表，按严重度排序
    """
    findings = []
    seen_ids = set()

    for rule in rules:
        rule_id = rule.get("id", "")
        # 预过滤: 若规则指定了 func_pattern 且伪代码中不包含该函数则跳过正则
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
                    break  # 同规则在同一个函数中只报告一次
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

    # 按严重度排序
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

    return findings


def scan_with_rules(
    binary_path: str,
    func_names: Optional[List[str]] = None,
    rule_dir: str = _RULES_DIR,
) -> List[Dict[str, Any]]:
    """
    对二进制文件执行完整的规则扫描。

    遍历指定函数（或全部函数），对每个函数的反编译代码应用所有规则。

    Args:
        binary_path: ELF 文件路径
        func_names:  要扫描的函数名列表，None 表示自动选择（优先用户函数）
        rule_dir:    规则文件目录

    Returns:
        全部匹配项的列表
    """
    rules = load_rules(rule_dir)
    if not rules:
        _log.debug("No rules loaded, skipping rule-based scan")
        return []

    from core.decompiler import list_functions, decompile_function

    # 函数选择逻辑——与 pipeline.py 保持一致
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
