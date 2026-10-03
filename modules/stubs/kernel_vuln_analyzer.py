# kernel_vuln_analyzer.py — 内核漏洞模式分析
# 检测 UAF、竞态条件、权限提升等内核级漏洞模式。
# FUZE — 内核 UAF 利用编排
# SLAKE — Slab 内存操纵
# RetSpill — 用户态数据注入内核
# K-LEAK — 多步信息泄露利用
# DDRace — 并发 UAF 定向模糊测试
import re as _re
from dataclasses import dataclass as _dc

@_dc
class KernelVulnCandidate:
    func_name: str
    vuln_type: str       # 'uaf' | 'race' | 'overflow' | 'info_leak' | 'privilege_escalation'
    location: str
    confidence: float
    evidence: list[str]

# FUZE 识别的内核高风险模式
_KERNEL_RISK_PATTERNS = {
    'uaf': [
        _re.compile(r'(?:kfree|free)\s*\(([^)]*)\).*\n.*\1', _re.DOTALL),
        _re.compile(r'(?:kmem_cache_free|vfree)\s*\(.*\)'),
    ],
    'race': [
        _re.compile(r'(?:copy_to_user|copy_from_user)\s*\(.*\).*\n.*(?:mutex_unlock|spin_unlock)',
                    _re.DOTALL),
        _re.compile(r'rcu_read_unlock.*\n.*(?!rcu_dereference)', _re.DOTALL),
    ],
    'info_leak': [
        _re.compile(r'(?:copy_to_user|put_user)\s*\([^,]*,\s*([^,]*)\)'),
        _re.compile(r'__copy_to_user\s*\([^,]*,\s*([^)]*)\)'),
    ],
    'privilege_escalation': [
        _re.compile(r'commit_creds\s*\(\s*prepare_kernel_cred\s*\(\s*0\s*\)\s*\)'),
        _re.compile(r'(?:capable|ns_capable)\s*\(.*\).*\n.*(?!return)'),
    ],
}

def scan_kernel_code(source_text: str) -> list[KernelVulnCandidate]:
    """扫描内核源码/伪代码中的已知漏洞模式。
    先静态匹配风险点，后续符号执行验证可利用性（FUZE范式）。"""
    candidates = []
    # 按函数边界分割
    functions = source_text.split('\n\n')
    for func_block in functions:
        func_name = 'unknown'
        name_match = _re.search(r'(\w+)\s*\(', func_block)
        if name_match:
            func_name = name_match.group(1)

        for vtype, patterns in _KERNEL_RISK_PATTERNS.items():
            evidence = []
            for pat in patterns:
                m = pat.search(func_block)
                if m:
                    evidence.append(m.group()[:80])
            if evidence:
                # 启发式置信度 — FUZE用符号执行精化
                conf = 0.45 + len(evidence) * 0.1
                candidates.append(KernelVulnCandidate(
                    func_name=func_name, vuln_type=vtype,
                    location=func_name,
                    confidence=min(0.9, conf),
                    evidence=evidence[:3],
                ))
    return candidates


def assess_exploitability(vuln: KernelVulnCandidate, protections: set[str]) -> float:
    """评估内核漏洞可利用性。
    protections 示例: {'KASLR', 'SMEP', 'SMAP', 'KPTI', 'CFI', 'SELinux'}"""
    base = vuln.confidence
    # 每种保护的折扣因子（RetSpill启发式）
    mitigation_penalty = {
        'KASLR': 0.85, 'SMEP': 0.80, 'SMAP': 0.75,
        'KPTI': 0.90, 'CFI': 0.60, 'SELinux': 0.85,
    }
    for prot in protections:
        base *= mitigation_penalty.get(prot, 0.95)
    return round(base, 4)
