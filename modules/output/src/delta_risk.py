"""
增量更新风险评估 — 补丁引入新风险的量化模型。

问题定义:
  patch_impact.py 回答 "漏洞被修复了吗?"。本模块回答逆向问题:
  "修复过程中引入了新的攻击面吗?"
  每次二进制更新都是一把双刃剑 — 新代码路径可能引入新漏洞。


  三类引入风险:
    1. 导入表增长 — 新依赖引入新攻击面
    2. 新代码路径 — 新增的基本块/函数未经安全审计
    3. 加固退化 — 新构建意外关闭了某些加固选项

  评分 = max(import_risk, codepath_risk, hardening_regression_risk)
  取 max 而非 product — 单类风险即可构成新的攻击面。

  PLocator: 跨优化补丁定位，但只检测存在性非风险.
  patch_impact.py: 评估修复完整性, 本模块评估引入风险.

修改记录:
  2024-11-05 11:09 - 初始版本，三类引入风险模型
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

@dataclass
class DeltaRisk:
    """增量更新风险评估。"""
    binary_name: str
    import_risk: float           # 0-10
    codepath_risk: float         # 0-10
    hardening_regression: float  # 0-10
    overall_risk: float          # 0-10, max of the three
    new_imports: List[str] = field(default_factory=list)
    new_string_endpoints: List[str] = field(default_factory=list)
    risk_level: str = 'low'

    def __post_init__(self):
        if self.overall_risk >= 7.0:
            self.risk_level = 'critical'
        elif self.overall_risk >= 5.0:
            self.risk_level = 'high'
        elif self.overall_risk >= 3.0:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'

# 高风险导入关键词 — 新增这些导入提升引入风险
_HIGH_RISK_IMPORTS: Dict[str, float] = {
    'system': 0.9, 'popen': 0.85, 'exec': 0.9, 'CreateProcess': 0.85,
    'WinExec': 0.8, 'ShellExecute': 0.8,
    'socket': 0.6, 'bind': 0.6, 'listen': 0.5, 'accept': 0.6,
    'connect': 0.5, 'send': 0.4, 'recv': 0.4,
    'memcpy': 0.2, 'strcpy': 0.5, 'sprintf': 0.5, 'gets': 0.7,
    'scanf': 0.3, 'strcat': 0.3,
    'dlopen': 0.6, 'dlsym': 0.55, 'LoadLibrary': 0.6,
    'GetProcAddress': 0.5,
    'mmap': 0.3, 'mprotect': 0.5, 'VirtualAlloc': 0.4,
    'VirtualProtect': 0.5,
}

def _normalize(name: str) -> str:
    return name.lower().lstrip('_').replace('__imp_', '')

def _import_risk(old_imports: List[str], new_imports: List[str]) -> Tuple[float, List[str]]:
    """
    导入表增长风险 — 新增高风险导入加权累加。

    指数衰减叠加: risk = 1 - Π(1 - w_i), 防止大量低风险导入堆积成高分。
    """
    old_set = {_normalize(i) for i in old_imports}
    new_set = {_normalize(i) for i in new_imports}
    added = new_set - old_set

    if not added:
        return 0.0, []

    risk_product = 1.0
    risky_added = []
    for imp in added:
        for keyword, weight in _HIGH_RISK_IMPORTS.items():
            if keyword.lower() in imp:
                risk_product *= (1.0 - weight)
                risky_added.append(imp)
                break

    risk = (1.0 - risk_product) * 10.0
    return round(min(risk, 10.0), 1), risky_added

def _codepath_risk(
    old_bb_count: int, new_bb_count: int,
    old_func_count: int, new_func_count: int,
) -> float:
    """
    新代码路径风险 — 新增基本块/函数占比映射到风险分。

    新增超过 30% 的全新代码 → 高风险 (未经审计的代码面显著扩大)。
    """
    bb_growth = (new_bb_count - old_bb_count) / max(old_bb_count, 1)
    func_growth = (new_func_count - old_func_count) / max(old_func_count, 1)

    # 加权: 新函数 (×0.6) + 新基本块 (×0.4)
    growth_score = 0.6 * func_growth + 0.4 * bb_growth

    # sigmoid 映射到 [0, 10]
    risk = 10.0 / (1.0 + math.exp(-4.0 * (growth_score - 0.15)))
    return round(risk, 1)

def _hardening_regression_risk(
    old_checksec: Dict[str, Any], new_checksec: Dict[str, Any]
) -> float:
    """
    加固退化风险 — 新构建意外关闭了加固。

    每项退化 +2 分, 全退化 = 10 分。
    """
    regressions = 0
    for key in ('NX', 'PIE', 'Canary', 'FORTIFY'):
        if old_checksec.get(key, False) and not new_checksec.get(key, False):
            regressions += 1
    old_relro = 'full' in old_checksec.get('RELRO', '').lower()
    new_relro = 'full' in new_checksec.get('RELRO', '').lower()
    if old_relro and not new_relro:
        regressions += 1

    # 严重性: 同时丢失多个加固 → 非线性惩罚
    return round(min(regressions * 2.5, 10.0), 1)

def _new_endpoint_strings(old_strings: List[str], new_strings: List[str]) -> List[str]:
    """
    新增字符串中的潜在端点 — URL/路径/域名模式的简单匹配。
    """
    added = set(new_strings) - set(old_strings)
    endpoints = []
    for s in added:
        sl = s.lower()
        if any(sl.startswith(p) for p in ('http://', 'https://', 'ws://', 'tcp://')):
            endpoints.append(s)
        elif any(kw in sl for kw in ('/api/', '/v1/', '/v2/', 'endpoint', 'callback')):
            endpoints.append(s)
    return endpoints

def assess_delta_risk(
    binary_name: str = '',
    old_imports: Optional[List[str]] = None,
    new_imports: Optional[List[str]] = None,
    old_bb_count: int = 0,
    new_bb_count: int = 0,
    old_func_count: int = 0,
    new_func_count: int = 0,
    old_checksec: Optional[Dict[str, Any]] = None,
    new_checksec: Optional[Dict[str, Any]] = None,
    old_strings: Optional[List[str]] = None,
    new_strings: Optional[List[str]] = None,
) -> DeltaRisk:
    """
    评估增量更新的引入风险。

    返回 DeltaRisk, overall_risk = max(三类风险)。
    """
    old_imports = old_imports or []
    new_imports = new_imports or []
    old_checksec = old_checksec or {}
    new_checksec = new_checksec or {}
    old_strings = old_strings or []
    new_strings = new_strings or []

    imp_risk, risky_imports = _import_risk(old_imports, new_imports)
    cp_risk = _codepath_risk(old_bb_count, new_bb_count, old_func_count, new_func_count)
    hw_risk = _hardening_regression_risk(old_checksec, new_checksec)
    endpoints = _new_endpoint_strings(old_strings, new_strings)

    overall = round(max(imp_risk, cp_risk, hw_risk), 1)

    return DeltaRisk(
        binary_name=binary_name or 'unknown',
        import_risk=imp_risk,
        codepath_risk=cp_risk,
        hardening_regression=hw_risk,
        overall_risk=overall,
        new_imports=risky_imports,
        new_string_endpoints=endpoints,
    )

def delta_risk_summary(risk: DeltaRisk) -> Dict[str, Any]:
    """增量风险评估摘要。"""
    warnings = []
    if risk.import_risk >= 5.0:
        warnings.append(f'新增 {len(risk.new_imports)} 个高风险导入: {", ".join(risk.new_imports[:5])}')
    if risk.codepath_risk >= 5.0:
        warnings.append('新代码路径占比显著 — 建议审计新增函数')
    if risk.hardening_regression >= 2.5:
        warnings.append('检测到加固退化 — 确认编译标志未改变')
    if risk.new_string_endpoints:
        warnings.append(f'新增 {len(risk.new_string_endpoints)} 个潜在外部端点')

    return {
        'overall_risk': risk.overall_risk,
        'risk_level': risk.risk_level,
        'import_risk': risk.import_risk,
        'codepath_risk': risk.codepath_risk,
        'hardening_regression': risk.hardening_regression,
        'warnings': warnings,
    }
