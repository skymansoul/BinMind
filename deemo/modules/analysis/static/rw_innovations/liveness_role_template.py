"""LivenessRoleTemplate - 调用点参数角色模板 (stage 56).

预扫描所有 call, 按 ABI 为每个调用点构造 (arg_reg -> role) 模板
(size/dest/src), 对 finding 的 size 参数做角色一致性投票,
多数派不一致时降权. 与 constraint_based_pairing 不同: 按角色模板
投票而非 liveness 配对.

设计决策:
  - SysV: rdi=dest, rsi=src, rdx=size
  - Win64: rcx=dest, rdx=src, r8=size
  - 逐 call 点构建模板, 对 finding 的 size 寄存器做投票
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
    """为每个 call 行构造角色模板."""
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
    """size 参数角色一致性投票: size 角色存在且被标记则 1.0."""
    if not size_reg:
        return 0.5
    return 1.0 if roles.get(size_reg) == "size" else 0.0


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
    if existing_findings:
        for f in existing_findings:
            out = dict(f)
            m = re.search(r"size_reg=(\w+)", out.get("description", ""))
            vote = _vote({"size_reg": "size"} if m else {}, m.group(1) if m else None)
            if vote < 0.5:
                out["confidence"] = round(out.get("confidence", 0.5) * 0.6, 2)
                out["verdict"] = "downgraded"
                out["source"] = "liveness_role_template"
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