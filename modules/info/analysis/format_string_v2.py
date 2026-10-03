# analysis/format_string_v2 — 格式串漏洞检测 (v2): 污点来源推断
# 超越 v1 的 printf(var) 简单匹配,
# 增加了两个分析维度来区分真实漏洞和误报:
#
# 维度1: 格式串来源推断 — 格式串来自:
#   DATA_SEGMENT:  数据段常量 → 安全 (开发者定义的格式串)
#   STACK_LOCAL:   栈上局部变量 → 可疑 (用户可控)
#   ARGV:          命令行参数 → 高置信漏洞
#   NETWORK_READ:  网络数据 → 极高置信漏洞
#   UNKNOWN:       无法确定 → 中等置信
# 维度2: 格式控制符密度分析 — 统计 %s %x %n 的密度,
#   高密度 → 攻击面大; 仅有 %% → 并非真正的格式串问题
# 维度3: 安全变体升级检测 — 若 printf(user) 与 snprintf(buf, N, user)
#   共存, 说明开发者有格式安全意识但部分调用点遗漏 → 提高置信度

from __future__ import annotations
import re
from typing import Dict, List, Set, Tuple, Optional

# 格式控制符 (排除 %% 转义)
_FMT_SPEC = re.compile(r'%(?!%)[-\+0 #]*\d*\.?\d*[hlLjzt]*[diouxXeEfFgGaAcspn]')

# 危险格式控制符
_DANGEROUS_SPECS = {"%n", "%s", "%x", "%p", "%d"}

# 可变参数 printf 函数族
_PRINTF_FNS = {"printf", "fprintf", "sprintf", "snprintf", "dprintf",
               "syslog", "vsprintf", "vsnprintf", "vfprintf"}

# 安全变体映射
_SAFE_VARIANTS = {"sprintf": "snprintf", "vsprintf": "vsnprintf",
                  "printf": "fprintf", "gets": "fgets"}

def _classify_format_source(code: str, fmt_arg: str) -> Tuple[str, float]:
    """推断格式串参数的来源和攻击者可控程度。

    返回 (来源类型, 可控性评分 0-1, 1=攻击者完全可控)。
    """
    # 1. argv 来源 → 攻击者可控
    if re.search(rf"{re.escape(fmt_arg)}\s*=\s*argv\[", code):
        return ("ARGV", 0.95)

    # 2. 网络输入 → 攻击者可控
    if re.search(rf"(?:recv|read|fread|fgets)\s*\([^)]*{re.escape(fmt_arg)}", code):
        return ("NETWORK_READ", 0.90)

    # 3. 栈上局部变量 → 可疑 (未初始化或部分初始化)
    if re.search(rf"char\s+{re.escape(fmt_arg)}\s*\[", code):
        # 检查是否紧接赋值了常量字符串
        if re.search(rf"{re.escape(fmt_arg)}\s*=\s*\"", code):
            return ("DATA_SEGMENT", 0.05)
        # 检查 getenv
        if re.search(rf"{re.escape(fmt_arg)}\s*=\s*getenv", code):
            return ("ENV_VAR", 0.80)
        return ("STACK_LOCAL", 0.55)

    # 4. 全局/静态变量
    if re.search(rf"(?:static|extern)\s+char\s*\*\s*{re.escape(fmt_arg)}", code):
        return ("DATA_SEGMENT", 0.10)

    # 5. 直接是字符串字面量
    if fmt_arg.startswith('"') or fmt_arg.startswith("'"):
        return ("LITERAL", 0.01)

    return ("UNKNOWN", 0.40)

def _analyze_format_specifiers(fmt_string: str) -> Dict:
    """分析格式串中的控制符种类和密度。

    返回 {total, dangerous, has_n_writer, density}。
    """
    specs = _FMT_SPEC.findall(fmt_string)
    dangerous = [s for s in specs if any(d in s for d in _DANGEROUS_SPECS)]
    has_n = any("%n" in s for s in specs)

    return {
        "total_specs": len(specs),
        "dangerous_specs": len(dangerous),
        "has_n_writer": has_n,
        "density": round(len(specs) / max(len(fmt_string), 1), 3),
        "unique_specs": list(set(specs))[:10],
    }

def _check_safe_variant_usage(code: str, func_name: str) -> float:
    """检查代码中是否使用了安全变体 → 压制置信度。"""
    safe = _SAFE_VARIANTS.get(func_name)
    if safe and safe in code:
        return 0.35  # 安全变体存在 → 此处可能是遗留调用, 但仍需标记
    return 0.0

def detect_format_string_v2(code: str, func_name: str = "") -> List[Dict]:
    """格式串漏洞检测主入口 (v2)。"""
    findings = []
    fn_list = list(_PRINTF_FNS)

    for fn in fn_list:
        # 查找所有该函数的调用
        pat = re.compile(rf"{re.escape(fn)}\s*\(([^)]*)\)")
        for m in pat.finditer(code):
            args_str = m.group(1)
            # 提取第一个参数 (格式串)
            first_arg = args_str.split(",")[0].strip() if args_str else ""

            # 跳过明显的常量格式串
            if first_arg.startswith('"') or first_arg.startswith("'"):
                continue
            if first_arg in ("NULL", "nullptr", "stderr", "stdout",
                            "format", "fmt", "__fmt", "__format"):
                continue

            # 分类来源
            source_type, controllability = _classify_format_source(code, first_arg)

            # 分析格式控制符 (如果有格式串内容)
            fmt_content_match = re.search(rf'{re.escape(first_arg)}\s*=\s*"([^"]*)"', code)
            fmt_content = fmt_content_match.group(1) if fmt_content_match else ""
            spec_analysis = _analyze_format_specifiers(fmt_content)

            # 安全变体压制
            safe_penalty = _check_safe_variant_usage(code, fn)

            # 置信度计算
            base_conf = controllability  # 基础: 可控性越高 → 越可能是漏洞

            if spec_analysis["has_n_writer"]:
                base_conf = min(0.98, base_conf + 0.20)  # %n 可写 → 极高危
            if spec_analysis["dangerous_specs"] >= 3:
                base_conf = min(0.98, base_conf + 0.10)
            if safe_penalty > 0:
                base_conf = max(0.10, base_conf - safe_penalty)

            findings.append({
                "type": "format-string",
                "function": func_name,
                "format_func": fn,
                "format_arg": first_arg,
                "format_source": source_type,
                "controllability": round(controllability, 2),
                "spec_analysis": spec_analysis,
                "severity": "Critical" if base_conf > 0.70 else "High",
                "cwe": "CWE-134",
                "confidence": round(base_conf, 2),
                "description": (f"{fn}({first_arg}): 来源={source_type}, "
                               f"可控性={controllability:.2f}, "
                               f"安全压制={safe_penalty:.2f}"),
            })

    return findings
