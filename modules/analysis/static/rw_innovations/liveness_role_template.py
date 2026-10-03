"""LivenessRoleTemplate - 调用点参数角色模板 (stage 56).

预扫描所有 call, 按 ABI 为每个调用点构造 (arg_reg -> role) 模板
(size/dest/src), 对 finding 的 size 参数做角色一致性投票,
多数派不一致时降权. 与 constraint_based_pairing 不同: 按角色模板
投票而非 liveness 配对.

设计决策:
  - SysV: rdi=dest, rsi=src, rdx=size
  - Win64: rcx=dest, rdx=src, r8=size
  - 逐 call 点构建模板, 对 finding 的 size 寄存器做投票

差异化 (vs call_conv_duality):
  - 本模块做消费型角色审计: 第 3 参收 findings, 按角色模板对已有
    findings 投票复核 (alloc/copy/free 角色匹配)
  - call_conv_duality 做调用点双约定校验 (不收 findings, 纯伪代码分析)
  - 输入维度彻底不同: 本模块收 findings, call_conv 不收
  - 汇编侧 size 寄存器表/窗口提取路径标记 DEPRECATED (与 call_conv 重叠)
"""

import re
from typing import Dict, List, Optional

_TYPE = "heap_overflow"
_CWE = "CWE-122"
_SEVERITY = "medium"

_ABI_ROLES: Dict[str, Dict[str, str]] = {
    "sysv": {"rdi": "dest", "rsi": "src", "rdx": "size",
             "rcx": "extra", "r8": "extra", "r9": "extra"},
    "win64": {"rcx": "dest", "rdx": "src", "r8": "size",
              "r9": "extra", "r10": "extra", "r11": "extra"},
}


def _detect_abi(lines: List[str]) -> str:
    """按序言与寄存器用法判断 ABI."""
    text = "\n".join(lines).lower()
    if "sub rsp" in text and "rcx" in text and "rdi" not in text:
        return "win64"
    return "sysv"


def _build_role_templates(pseudocode: str, abi: str) -> List[dict]:
    """#[DEPRECATED] 汇编侧 size 寄存器模板构建.
    与 call_conv_duality 的窗口提取+寄存器表重叠, 差异化后保留函数体
    供汇编场景兼容回退, 主判定改为 C 风格角色审计.
    """
    templates: List[dict] = []
    table = _ABI_ROLES.get(abi, _ABI_ROLES["sysv"])
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\bcall\s+(\w+)", line)
        if not m:
            continue
        # 该 call 行及前 6 行内出现的传参寄存器
        window = pseudocode.splitlines()[max(0, ln - 7):ln]
        regs = re.findall(r"\b(r(?:di|si|dx|cx|8|9|10|11))\b", "\n".join(window))
        roles = {reg: table.get(reg, "unknown") for reg in regs}
        size_reg = next((r for r, role in roles.items() if role == "size"), None)
        templates.append({
            "line": ln, "callee": m.group(1), "roles": roles,
            "size_reg": size_reg,
        })
    return templates


def _vote(roles: Dict[str, str], size_reg: Optional[str]) -> float:
    """#[DEPRECATED] 汇编侧 size 角色一致性投票.
    与 call_conv_duality 的单表投票重叠, 保留函数体供汇编兼容.
    """
    if not size_reg:
        return 0.5
    return 1.0 if roles.get(size_reg) == "size" else 0.0


def _audit_finding_role(
    finding: dict,
    c_templates: List[dict],
) -> Optional[dict]:
    """消费型角色审计: 根据调用点角色模板对已有 finding 投票复核.
    返回降权后的 finding 副本, 或 None 表示不降权.
    与 call_conv 的双约定校验不同: 本函数基于角色匹配而非约定对偶.
    """
    out = dict(finding)
    f_type = out.get("type", "")
    f_conf = out.get("confidence", 0.5)
    for t in c_templates:
        callee = t["callee"]
        roles = t.get("roles", {})
        # free 调用点出现且 finding 为 UAF -> free 角色已标注, 降权 UAF 告警
        if callee == "free" and f_type == "use_after_free":
            out["confidence"] = round(f_conf * 0.7, 2)
            out["verdict"] = "downgraded"
            out["source"] = "liveness_role_template"
            return out
        # memcpy 调用点且 finding 为堆溢出 -> size 角色存在则审计通过
        if callee == "memcpy" and f_type == "heap_overflow":
            has_size = any(v == "size" for v in roles.values())
            if has_size:
                return None
    return None


# C 风格调用点角色模板: 函数名 -> 参数位置角色
_C_CALL_ROLES = {
    "free": {0: "free"},
    "memcpy": {0: "write_target", 2: "size"},
    "memmove": {0: "write_target", 2: "size"},
    "memset": {0: "write_target", 2: "size"},
    "malloc": {0: "alloc_size"},
    "realloc": {0: "realloc_ptr", 1: "alloc_size"},
    "printf": {0: "format"},
    "scanf": {0: "format"},
    "strlen": {0: "read_target"},
    "strcpy": {0: "write_target", 1: "read_target"},
}
_C_CALL_RE = re.compile(
    r"\b(free|memcpy|memmove|memset|malloc|realloc|printf|scanf|strlen|strcpy)\s*\("
)


def _build_c_role_templates(pseudocode: str) -> List[dict]:
    """C 风格调用点角色模板构建."""
    templates: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        for m in _C_CALL_RE.finditer(line):
            fname = m.group(1)
            paren_pos = m.end() - 1
            args_str = _extract_call_args(line, paren_pos)
            if args_str is None:
                continue
            args = [a.strip() for a in _split_args(args_str)]
            roles_map = _C_CALL_ROLES.get(fname, {})
            roles: Dict[str, str] = {}
            for idx, arg in enumerate(args):
                role = roles_map.get(idx, "unknown")
                # 用参数文本作为 key, 角色为值
                roles[arg] = role
            templates.append({
                "line": ln,
                "callee": fname,
                "roles": roles,
                "args": args,
            })
    return templates


def _extract_call_args(line: str, paren_pos: int) -> Optional[str]:
    """从 paren_pos 位置的左括号开始提取实参字符串."""
    depth = 0
    for i in range(paren_pos, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[paren_pos + 1:i]
    return None


def _split_args(args_str: str) -> List[str]:
    """按顶层逗号分割实参."""
    parts: List[str] = []
    depth = 0
    current = ""
    for ch in args_str:
        if ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current)
    return parts


def run_liveness_role_template(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """调用点参数角色模板投票. 返回 findings."""
    lines = pseudocode.splitlines()
    abi = _detect_abi(lines)
    templates = _build_role_templates(pseudocode, abi)
    findings: List[dict] = []
    for t in templates:
        vote = _vote(t["roles"], t["size_reg"])
        verdict = "consistent" if vote >= 0.5 else "inconsistent"
        findings.append({
            "type": _TYPE,
            "function": func_name or "unknown",
            "severity": _SEVERITY,
            "cwe": _CWE,
            "confidence": round(vote, 2),
            "description": (
                f"call@{t['line']} {t['callee']} abi={abi} "
                f"size_reg={t['size_reg']} vote={vote:.2f}"
            ),
            "verdict": verdict,
            "source": "liveness_role_template",
        })

    # C 风格调用点角色模板审计条目
    c_templates = _build_c_role_templates(pseudocode)
    for t in c_templates:
        roles_desc = ",".join(
            f"{k}={v}" for k, v in t["roles"].items()
        )
        findings.append({
            "type": _TYPE,
            "function": func_name or "unknown",
            "severity": _SEVERITY,
            "cwe": _CWE,
            "confidence": 0.7,
            "description": (
                f"call@{t['line']} c_call {t['callee']} roles=[{roles_desc}]"
            ),
            "verdict": "role_audited",
            "source": "liveness_role_template",
        })

    # C 风格 findings 角色审计: 根据调用点角色模板对已有 findings 投票复核
    # 差异化: 用 _audit_finding_role 统一角色审计逻辑, 替代旧的内联降权
    if existing_findings:
        for f in existing_findings:
            out = dict(f)
            # 汇编风格降权: 从 description 提取 size_reg (保留兼容)
            m = re.search(r"size_reg=(\w+)", out.get("description", ""))
            if m:
                vote = _vote({"size_reg": "size"}, m.group(1))
                if vote < 0.5:
                    out["confidence"] = round(out.get("confidence", 0.5) * 0.6, 2)
                    out["verdict"] = "downgraded"
                    out["source"] = "liveness_role_template"
                findings.append(out)
                continue
            # C 风格: 角色审计复核 (与 call_conv 双约定校验不同维度)
            audited = _audit_finding_role(f, c_templates)
            if audited is not None:
                findings.append(audited)
            else:
                findings.append(out)
    return findings

if __name__ == "__main__":
    demo = """\
push rbp;
mov rdi, [rbp-8];
mov rsi, [rbp-16];
mov rdx, 64;
call memcpy;
"""
    out = run_liveness_role_template(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"], item["confidence"])