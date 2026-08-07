"""
三层风险面映射器 — 攻击面入口 → 漏洞 → 可利用性的有向加权图。

架构:
  第1层 (入口面): 二进制对外暴露的接口 — 导入函数、文件解析器、网络侦听
  第2层 (漏洞面): 从入口面可达的代码区域中已发现或潜在的漏洞
  第3层 (可利用性): 漏洞在当前加固上下文下的实际可利用性

  三层之间的边权重:
    入口→漏洞: 基于 CFG 距离 + 调用深度 (近 → 热路径, 权重高)
    漏洞→可利用性: 基于加固差分 (无 Canary → 栈溢出的利用权重显著升高)

与现有工作的区别:
  - MIRAGE: 跨二进制攻击图，本模块是单二进制的三层模型
  - Binarly US 12,287,885: 纯可达性 (ICFG)，无风险加权
  - Microsoft Attack Surface Analyzer: Windows 特化，无漏洞/加固整合

每函数风险评分:
  R(f) = S_attack(f) × S_vuln(f) × S_exploit(f)
  三者均为 [0, 1]。
  乘积形式确保: 任一维度的零分将整个风险置零 (未暴露 or 无漏洞 or 不可利用)。

修改记录:
  2026-08-03 13:27 - 初始版本，三层有向图 + 每函数风险评分
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 导入函数 → 攻击面类别映射
_IMPORT_ATTACK_SURFACE: Dict[str, float] = {}
for _kw in ('socket', 'bind', 'listen', 'accept', 'connect', 'recv', 'send'):
    _IMPORT_ATTACK_SURFACE[_kw] = 0.90  # 网络暴露 — 最高风险
for _kw in ('fopen', 'open', 'read', 'fread', 'fgets', 'mmap', 'stat', 'access'):
    _IMPORT_ATTACK_SURFACE[_kw] = 0.70  # 文件解析 — 中高风险
for _kw in ('recvfrom', 'recvmsg', 'getaddrinfo', 'gethostbyname'):
    _IMPORT_ATTACK_SURFACE[_kw] = 0.85
for _kw in ('dlsym', 'dlopen', 'LoadLibrary', 'GetProcAddress'):
    _IMPORT_ATTACK_SURFACE[_kw] = 0.60  # 动态加载 — 中等风险
for _kw in ('system', 'popen', 'execve', 'execvp', 'CreateProcess', 'WinExec'):
    _IMPORT_ATTACK_SURFACE[_kw] = 0.55  # 命令执行 — 中等风险但常被利用


@dataclass
class FunctionRisk:
    """单函数三层风险评分。"""
    function_name: str
    attack_surface_score: float     # 距最近攻击面入口的归一化距离
    vulnerability_score: float      # CFG 指纹漏洞倾向分 (委托 cfg_entropy_fingerprint)
    exploitability_score: float     # 加固差分下的可利用性
    composite_risk: float           # R = S_attack × S_vuln × S_exploit
    risk_level: str = 'low'

    def __post_init__(self):
        if self.composite_risk >= 0.7:
            self.risk_level = 'critical'
        elif self.composite_risk >= 0.4:
            self.risk_level = 'high'
        elif self.composite_risk >= 0.15:
            self.risk_level = 'medium'


def _normalize_import(name: str) -> str:
    return name.lower().lstrip('_').replace('__imp_', '')


def _attack_surface_score(
    function_name: str,
    imports: List[str],
    call_graph_distances: Optional[Dict[str, int]] = None,
) -> float:
    """
    计算函数距攻击面入口的归一化距离。

    距离 = 从最接近的危险导入调用点到该函数的最短调用链长度。
    使用指数衰减: score = base_surface × exp(-distance / tau)。

    tau = 3 — 超过 3 跳的间接调用面风险急剧衰减。
    无调用图时，仅基于函数名是否匹配导入表 (导出函数直接暴露)。
    """
    norm_name = _normalize_import(function_name)

    if call_graph_distances is not None:
        dist = call_graph_distances.get(function_name, 99)
        # 如果该函数本身不在图中但名称匹配导入表 → 视为直接暴露
        if dist == 99 and any(norm_name == _normalize_import(imp) for imp in imports):
            dist = 0
        base_risk = max(
            _IMPORT_ATTACK_SURFACE.get(_normalize_import(imp), 0.30)
            for imp in imports
        ) if imports else 0.20
        return round(base_risk * math.exp(-dist / 3.0), 4)

    # 无调用图: 名称直接匹配 → 高暴露
    for imp in imports:
        if norm_name == _normalize_import(imp):
            return round(_IMPORT_ATTACK_SURFACE.get(_normalize_import(imp), 0.50), 2)
    # 回退: 部分匹配 (函数名含导入关键词)
    for imp in imports:
        ni = _normalize_import(imp)
        if ni in norm_name or norm_name in ni:
            return round(_IMPORT_ATTACK_SURFACE.get(ni, 0.40) * 0.6, 2)
    return 0.10  # 内部函数 — 低暴露


def _exploitability_from_hardening(
    vuln_type: str,
    checksec: Dict[str, Any],
) -> float:
    """
    根据加固状态计算特定漏洞类型的可利用性。

    利用矩阵: hardening_advisor 的逆映射 — 加固越弱, 可利用性越高。
    """
    base = 0.5  # 默认中位可利用性
    nx = checksec.get('NX', False)
    pie = checksec.get('PIE', False)
    canary = checksec.get('Canary', False)
    relro_full = 'full' in checksec.get('RELRO', '').lower()
    fortify = checksec.get('FORTIFY', False)

    vtype_lower = vuln_type.lower()

    if 'stack' in vtype_lower or 'overflow' in vtype_lower:
        if not canary: base += 0.25
        if not nx: base += 0.15
        if not pie: base += 0.10
    elif 'heap' in vtype_lower:
        if not nx: base += 0.30
        if not fortify: base += 0.15
    elif 'format' in vtype_lower:
        if not fortify: base += 0.25
        if not relro_full: base += 0.20
    elif 'got' in vtype_lower or 'overwrite' in vtype_lower:
        if not relro_full: base += 0.35
        if not pie: base += 0.15
    elif 'exec' in vtype_lower or 'code' in vtype_lower:
        if not nx: base += 0.35
        if not pie: base += 0.10

    return round(min(base, 1.0), 4)


def compute_risk_surface(
    functions: List[Dict[str, Any]],
    imports: List[str],
    checksec: Dict[str, Any],
    call_graph_distances: Optional[Dict[str, int]] = None,
) -> List[FunctionRisk]:
    """
    计算所有函数的三层风险面评分。

    Args:
      functions: [{'name': str, 'cfg_fingerprint': {'vuln_likelihood': ...},
                   'vulnerabilities': [{'type': str}, ...]}, ...]
      imports: 导入函数名列表
      checksec: checksec 字典
      call_graph_distances: {func_name: min_distance_to_import_call}, None=使用启发式

    Returns:
      按 composite_risk 降序排列的 FunctionRisk 列表。
    """
    results: List[FunctionRisk] = []

    for func in functions:
        fname = func.get('name', 'unknown')
        fp = func.get('cfg_fingerprint', {})
        vuln_likelihood = fp.get('vuln_likelihood', 0.1)

        # 显式发现的漏洞 → vuln_score 取 max(likelihood, 1/0)
        vulns = func.get('vulnerabilities', [])
        if vulns:
            vuln_score = max(vuln_likelihood, 0.6)
            # 取最危险的漏洞类型计算可利用性
            worst_vuln = max(vulns, key=lambda v: v.get('severity', ''))
            exploit_score = _exploitability_from_hardening(
                worst_vuln.get('type', ''), checksec
            )
        else:
            vuln_score = vuln_likelihood
            exploit_score = _exploitability_from_hardening('unknown', checksec)

        attack_score = _attack_surface_score(fname, imports, call_graph_distances)
        composite = round(attack_score * vuln_score * exploit_score, 4)

        results.append(FunctionRisk(
            function_name=fname,
            attack_surface_score=attack_score,
            vulnerability_score=round(vuln_score, 4),
            exploitability_score=exploit_score,
            composite_risk=composite,
        ))

    results.sort(key=lambda r: r.composite_risk, reverse=True)
    return results


def risk_summary(risks: List[FunctionRisk]) -> Dict[str, Any]:
    """三层风险面的统计摘要。"""
    if not risks:
        return {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for r in risks:
        levels[r.risk_level] += 1

    top_n = 5
    return {
        'total': len(risks),
        **levels,
        'mean_risk': round(sum(r.composite_risk for r in risks) / len(risks), 4),
        'max_risk': risks[0].composite_risk if risks else 0.0,
        'top_risks': [
            {'function': r.function_name, 'composite': r.composite_risk,
             'attack_surface': r.attack_surface_score,
             'vulnerability': r.vulnerability_score,
             'exploitability': r.exploitability_score}
            for r in risks[:top_n]
        ],
    }
