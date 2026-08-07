"""
格式化字符串检测回归测试模块 — FSCS (Format Spec Constraint System) 集成.

FSCS 将格式串漏洞评估从简单的 "printf(user_str) → VULN" 提升到定量评分:
  1. 解析格式说明符 → SpecifierRisk (CRITICAL/HIGH/MEDIUM/LOW/INFO/NONE)
  2. 用户可控性判断 (argv, stdin, recv, getenv 等)
  3. 栈偏移估计 (参数位置影响利用难度)
  4. 输出目标评估 (stdout < file < buffer)

评分阈值:
  overall_score ≥ 5.0 → KEEP (高利用价值, 保留告警)
  overall_score ≥ 3.0 → LIKELY (中等利用价值, 保留但降级)
  overall_score <  3.0 → FILTER (低利用价值, 过滤)

  - FSCS 源自 scut/team teso 的格式串利用分类法
  - CVSS-style 0-10 评分映射自 CWE-134 利用难度
  - 与 FormatSpecAnalyzer + FormatImpactCalculator 协同
"""

from __future__ import annotations

import json, os, re, sys, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# 格式串漏洞检测

# 危险格式化函数
_FMT_FUNCTIONS = [
    'printf', 'fprintf', 'sprintf', 'snprintf', 'syslog',
    'dprintf', 'vfprintf', 'vsprintf', 'vsnprintf', 'vprintf',
]

# 用户输入源模式
_USER_SOURCE_PATS = [
    r'argv\[', r'getenv\s*\(', r'gets\s*\(', r'fgets\s*\(',
    r'recv\s*\(', r'read\s*\(', r'scanf\s*\(', r'fscanf\s*\(',
    r'getc\s*\(', r'fgetc\s*\(', r'getchar\s*\(', r'readline\s*\(',
    r'cin\s*>>', r'istream', r'RecvMsg', r'HTTP_', r'REQUEST',
]

# 安全格式串模式 (格式串是字面量 → SAFE)
_SAFE_FMT_PAT = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf|syslog)\s*\(\s*"')

# 危险格式串模式:
#   Type A: printf(var) — 单参数格式函数
#   Type B: fprintf(stream, var), dprintf(fd, var) — 双参数格式函数
#   Type C: syslog(priority, var) — syslog格式
_DANGER_FMT_PAT = re.compile(
    r'(fprintf|dprintf)\s*\(\s*\w+\s*,\s*(\w+(?:\[[^\]]+\])?(?:->\w+)?)\s*[),]'
    r'|(printf|syslog|vprintf)\s*\(\s*(\w+(?:\[[^\]]+\])?(?:->\w+)?)\s*[),]'
    r'|(sprintf|snprintf)\s*\(\s*\w+\s*,\s*(\w+(?:\[[^\]]+\])?(?:->\w+)?)\s*[),]',
    re.IGNORECASE)

@dataclass
class FormatStringCandidate:
    """格式串漏洞候选."""
    func_name: str
    fmt_arg: str
    line_no: int = 0
    is_user_controlled: bool = False
    fmt_content: str = ""
    risk_label: str = ""          # CRITICAL/HIGH/MEDIUM/LOW/INFO/NONE
    exploit_score: float = 0.0    # 0-10
    impact_score: float = 0.0     # 0-10
    overall_score: float = 0.0    # 0-10
    confidence: float = 0.5
    description: str = ""

def detect_format_string_vulns(source_code: str) -> List[FormatStringCandidate]:
    """检测格式串漏洞候选, 调用 FSCS 评分."""
    candidates = []

    for i, line in enumerate(source_code.splitlines()):
        # 跳过安全模式 (格式串是字面量)
        if _SAFE_FMT_PAT.search(line):
            continue

        # 匹配危险模式 (多形式正则)
        for m in _DANGER_FMT_PAT.finditer(line):
            # 正则有三组备选: (fprintf-type), (printf-type), (sprintf-type)
            if m.group(1):  # fprintf/dprintf: group(1)=func, group(2)=arg
                func = m.group(1)
                arg = m.group(2)
            elif m.group(3):  # printf/syslog/vprintf: group(3)=func, group(4)=arg
                func = m.group(3)
                arg = m.group(4)
            elif m.group(5):  # sprintf/snprintf: group(5)=func, group(6)=arg
                func = m.group(5)
                arg = m.group(6)
            else:
                continue

            # 排除误匹配 (变量名是已知安全的)
            if arg in ('stderr', 'stdout', 'stdin', 'fmt', 'format'):
                continue

            # 用户可控性判断
            is_ctrl = _check_user_controlled(source_code, arg)

            # 提取格式串字面量 (如果能)
            fmt_content = _extract_fmt_literal(source_code, func, i)

            candidate = FormatStringCandidate(
                func_name=func, fmt_arg=arg, line_no=i,
                is_user_controlled=is_ctrl, fmt_content=fmt_content,
            )
            candidates.append(candidate)

    # FSCS 评分
    try:
        from analysis.format_spec_scorer import FormatSpecAnalyzer
        for c in candidates:
            assessment = FormatSpecAnalyzer.assess_exploitability(
                format_func=c.func_name,
                format_arg=c.fmt_arg,
                format_string_content=c.fmt_content,
                is_user_controlled=c.is_user_controlled,
            )
            c.exploit_score = assessment.exploitability_score
            c.impact_score = assessment.impact_score
            c.overall_score = assessment.overall_score
            c.risk_label = assessment.max_risk.name
            c.confidence = assessment.confidence
            c.description = assessment.description
    except ImportError:
        # 回退: 基于规则的评分
        for c in candidates:
            c.risk_label = "MEDIUM" if c.is_user_controlled else "LOW"
            c.overall_score = 5.0 if c.is_user_controlled else 2.0
            c.confidence = 0.6 if c.is_user_controlled else 0.4

    return candidates

def filter_by_fscs_threshold(candidates: List[FormatStringCandidate],
                              threshold: float = 3.0) -> Tuple[List[FormatStringCandidate], List[FormatStringCandidate]]:
    """使用 FSCS 阈值过滤: score ≥ threshold → KEEP, < threshold → FILTER."""
    kept = [c for c in candidates if c.overall_score >= threshold]
    filtered = [c for c in candidates if c.overall_score < threshold]
    return kept, filtered

# Ground Truth

def extract_fmt_ground_truth(source_path: str) -> Dict[str, Any]:
    """提取格式串的 ground truth."""
    truth = {"is_vulnerable": False, "expected_count": 0, "description": "", "cve_ref": ""}
    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return truth

    # 行注释标记
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r'//\s*VULN:\s*format', line, re.IGNORECASE)
        if m:
            truth["is_vulnerable"] = True
            truth["description"] = m.group(1)
        m = re.match(r'//\s*SAFE:\s*(.+)', line, re.IGNORECASE)
        if m:
            truth["is_vulnerable"] = False
            truth["description"] = m.group(1)
        m = re.match(r'//\s*CVE:\s*(\S+)', line, re.IGNORECASE)
        if m:
            truth["cve_ref"] = m.group(1)

    # CVE块注释
    if "TRUE POSITIVE" in content.upper():
        truth["is_vulnerable"] = True
    if "FALSE POSITIVE" in content.upper():
        truth["is_vulnerable"] = False

    # 启发式: 存在 printf(user_input) → 漏洞
    dm = _DANGER_FMT_PAT.search(content)
    if dm:
        # 提取格式参数 (多形式正则group解析)
        arg = dm.group(2) or dm.group(4) or dm.group(6) or ""
        if arg and _check_user_controlled(content, arg):
            if not truth.get("is_vulnerable") and "SAFE" not in content.upper():
                truth["is_vulnerable"] = True

    # CVE编号
    cve_m = re.search(r'CVE-\d{4}-\d{4,}', content)
    if cve_m:
        truth["cve_ref"] = cve_m.group(0)

    return truth

# 辅助

def _check_user_controlled(source: str, var: str) -> bool:
    """判断变量是否来自用户输入.

    方法:
      1. 变量名直接匹配用户输入源 (argv, getenv, gets 等)
      2. 变量被赋值为用户输入 (var = argv[1], var = getenv(...))
      3. 变量作为函数参数, 从调用链追溯到用户输入
    """
    # 变量名本身引用用户输入源
    if var.startswith('argv') or re.search(r'argv\s*\[', var):
        return True
    if 'getenv' in var.lower() or 'gets(' in var.lower():
        return True

    # 变量被赋值为用户输入源
    for pat in _USER_SOURCE_PATS:
        if re.search(rf'{re.escape(var)}\s*=\s*[^;]*{pat}', source, re.IGNORECASE):
            return True

    # 变量名是函数参数, 检查调用者是否传入用户输入
    # 模式: func_call(argv[1]) 或 func_call(getenv(...))
    func_patterns = [
        rf'(\w+)\s*\(\s*{re.escape(var)}\s*\)',  # func(var)
        rf'(\w+)\s*\([^)]*{re.escape(var)}\s*[),]',  # func(..., var, ...)
    ]
    for fp in func_patterns:
        for cm in re.finditer(fp, source, re.IGNORECASE):
            caller = cm.group(1)
            # 检查 caller 是否从用户输入获得其参数
            # 简化: 在 main 中调用且参数来自 argc/argv
            if re.search(rf'main\s*\(.*{re.escape(var)}', source):
                return True

    return False

def _extract_fmt_literal(source: str, func: str, line_no: int) -> str:
    """提取格式串字面量."""
    lines = source.splitlines()
    if line_no < len(lines):
        line = lines[line_no]
        m = re.search(rf'{re.escape(func)}\s*\(\s*"([^"]*)"', line)
        if m:
            return m.group(1)
    return ""

# 回归测试入口

def run_fmt_regression(sample_dir: str, threshold: float = 3.0) -> Dict[str, Any]:
    """运行格式串回归测试.

    Returns:
        {"metrics": {...}, "per_sample": [...], "summary": {...}}
    """
    results = []
    root = Path(sample_dir)
    if not root.exists():
        return {"error": f"directory not found: {sample_dir}"}

    for c_file in sorted(root.rglob("*.c")):
        sample_path = str(c_file)
        sample_name = c_file.parent.name

        try:
            with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            continue

        t0 = time.time()
        candidates = detect_format_string_vulns(source)
        kept, filtered = filter_by_fscs_threshold(candidates, threshold)
        dt = (time.time() - t0) * 1000

        truth = extract_fmt_ground_truth(sample_path)
        is_vuln = truth.get("is_vulnerable", False)
        detected = len(kept) > 0

        if is_vuln:
            verdict = "TP" if detected else "FN"
        else:
            verdict = "FP" if detected else "TN"

        results.append({
            "sample_name": sample_name,
            "is_vulnerable": is_vuln,
            "cve_ref": truth.get("cve_ref", ""),
            "raw_findings": len(candidates),
            "kept_count": len(kept),
            "filtered_count": len(filtered),
            "verdict": verdict,
            "scan_time_ms": round(dt, 1),
            "details": [
                {"func": c.func_name, "arg": c.fmt_arg, "score": c.overall_score,
                 "risk": c.risk_label, "user_ctrl": c.is_user_controlled}
                for c in kept
            ],
        })

    # 计算指标
    tp = sum(1 for r in results if r["verdict"] == "TP")
    fp = sum(1 for r in results if r["verdict"] == "FP")
    tn = sum(1 for r in results if r["verdict"] == "TN")
    fn = sum(1 for r in results if r["verdict"] == "FN")
    total = tp + fp + tn + fn

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "metrics": {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "per_sample": results,
        "summary": {
            "total": total,
            "threshold": threshold,
        },
        "report_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

if __name__ == "__main__":
    base = Path(__file__).parent.parent.parent
    sample_dir = str(base / "samples" / "format_string")
    report = run_fmt_regression(sample_dir)
    print(f"Format String Regression: {report['metrics']}")
    print(f"  Samples: {report['summary']['total']}")
    for r in report["per_sample"]:
        print(f"  {r['sample_name']}: {r['verdict']} "
              f"(raw={r['raw_findings']}, kept={r['kept_count']})")
