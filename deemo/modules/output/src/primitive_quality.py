"""
利用原语质量评分 — 可控性×可达范围×可靠性×副作用的四维评估。

问题定义:
  Colorstreams 用符号执行 + SMT 求解量化"攻击者控制域"，
  但这是重量级方法，不适于报告阶段的快速评估。
  安全审计报告需要回答: "这个漏洞的利用原语有多强?"

  四维评估:
    1. 可控性 (controllability): 攻击者能控制什么值? (0=崩溃不可控, 1=完全受控)
    2. 可达范围 (reach): 能读/写多大范围? (0=受限, 1=任意地址)
    3. 可靠性 (reliability): 利用成功是确定性还是概率性? (0=概率<10%, 1=>90%)
    4. 副作用 (side_effects): 利用后程序状态? (0=立即崩溃, 1=干净返回)

  四者乘积 → 原语质量分 (PQF = Primitive Quality Factor) [0, 1]。
  乘积形式而非和: 任一维度为零 → 整体原语质量为零。

  Colorstreams: wQC (weighted Quantitative Control) 度量
  ARCANIST: gadget chain synthesis with primitive abstraction
  BridgeRouter: OOB→arbitrary write 原语升级

  本模块与上述工具的位置不同:
    Colorstreams/ARCANIST/BridgeRouter: 利用生成阶段，需要符号执行
    本模块: 报告阶段，基于已有分析结果的启发式评分

修改记录:
  2026-08-02 15:28 - 初始版本，四维乘积原语质量模型
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

class PrimitiveType(Enum):
    CRASH = "crash"                  # 仅崩溃，无控制
    READ_OOB = "read_oob"            # 越界读 — 可能的信息泄露
    WRITE_OOB = "write_oob"          # 越界写 — 可能的控制流劫持
    WRITE_CONTROLLED = "write_controlled"  # 受控写 (值+地址可控)
    WRITE_ARBITRARY = "write_arbitrary"    # 任意写
    READ_ARBITRARY = "read_arbitrary"      # 任意读
    EXEC_CONTROL = "exec_control"    # 直接执行控制 (EIP/RIP 劫持)
    CODE_EXEC = "code_exec"          # 已达成代码执行

# 原语能力矩阵 — 每种原语在各维度上的默认能力分
_PRIMITIVE_CAPABILITY: Dict[PrimitiveType, Tuple[float, float, float, float]] = {
    # (controllability, reach, reliability, side_effects)
    PrimitiveType.CRASH:             (0.05, 0.0,  0.3,  0.0),
    PrimitiveType.READ_OOB:          (0.20, 0.1,  0.5,  0.4),
    PrimitiveType.WRITE_OOB:         (0.30, 0.2,  0.4,  0.3),
    PrimitiveType.WRITE_CONTROLLED:  (0.70, 0.5,  0.6,  0.5),
    PrimitiveType.WRITE_ARBITRARY:   (0.90, 1.0,  0.7,  0.6),
    PrimitiveType.READ_ARBITRARY:    (0.85, 1.0,  0.8,  0.7),
    PrimitiveType.EXEC_CONTROL:      (0.95, 0.9,  0.6,  0.4),
    PrimitiveType.CODE_EXEC:         (1.0,  1.0,  0.9,  0.9),
}

@dataclass
class PrimitiveQuality:
    """单个利用原语的四维质量评估。"""
    primitive_type: PrimitiveType
    controllability: float     # [0, 1]
    reach: float               # [0, 1]
    reliability: float         # [0, 1]
    side_effects: float        # [0, 1] — 1=无副作用 (干净返回)
    pqf: float                 # 乘积: c × r × rel × s
    tier: str = ''             # trivial / limited / moderate / powerful / weaponized

    def __post_init__(self):
        if self.pqf >= 0.5:
            self.tier = 'weaponized'
        elif self.pqf >= 0.2:
            self.tier = 'powerful'
        elif self.pqf >= 0.08:
            self.tier = 'moderate'
        elif self.pqf >= 0.02:
            self.tier = 'limited'
        else:
            self.tier = 'trivial'

def _parse_primitive_type(vuln_info: Dict[str, Any]) -> PrimitiveType:
    """从漏洞描述推断原语类型。"""
    vtype = vuln_info.get('type', '').lower()
    desc = vuln_info.get('description', '').lower()
    combined = vtype + ' ' + desc

    if 'code execution' in combined or 'shell' in combined:
        return PrimitiveType.CODE_EXEC
    if 'eip' in combined or 'rip' in combined or 'pc control' in combined:
        return PrimitiveType.EXEC_CONTROL
    if 'arbitrary write' in combined or 'write-what-where' in combined:
        return PrimitiveType.WRITE_ARBITRARY
    if 'arbitrary read' in combined:
        return PrimitiveType.READ_ARBITRARY
    if 'controlled write' in combined:
        return PrimitiveType.WRITE_CONTROLLED
    if 'write' in vtype or 'overflow' in vtype or 'overwrite' in vtype:
        return PrimitiveType.WRITE_OOB
    if 'read' in vtype or 'leak' in vtype or 'disclosure' in vtype:
        return PrimitiveType.READ_OOB

    return PrimitiveType.CRASH

def score_primitive(
    vuln_info: Dict[str, Any],
    crash_analysis: Optional[Dict[str, Any]] = None,
    exploit_result: Optional[Dict[str, Any]] = None,
) -> PrimitiveQuality:
    """
    评估单个漏洞的利用原语质量。

    vuln_info 中可覆盖默认能力分:
      - controllable_value: bool
      - address_reach: 'limited' | 'page' | 'arbitrary'
      - exploit_reliability: 0-1
      - clean_return: bool
    """
    ptype = _parse_primitive_type(vuln_info)
    c0, r0, rel0, s0 = _PRIMITIVE_CAPABILITY[ptype]

    # 从 vuln_info 和 crash_analysis 微调
    c = c0 + (0.15 if vuln_info.get('controllable_value') else 0.0)

    reach_hint = vuln_info.get('address_reach', '')
    if reach_hint == 'arbitrary':
        r = min(r0 + 0.3, 1.0)
    elif reach_hint == 'page':
        r = min(r0 + 0.15, 1.0)
    else:
        r = r0

    rel = vuln_info.get('exploit_reliability', rel0)
    if crash_analysis:
        reproducibility = crash_analysis.get('reproducibility', crash_analysis.get('combined', {}).get('reproducibility', ''))
        if 'always' in str(reproducibility).lower():
            rel = min(rel + 0.15, 1.0)
        elif 'sometimes' in str(reproducibility).lower():
            rel = max(rel - 0.1, 0.05)

    s = s0 + (0.2 if vuln_info.get('clean_return') else 0.0)

    c = round(max(0.0, min(1.0, c)), 4)
    r = round(max(0.0, min(1.0, r)), 4)
    rel = round(max(0.0, min(1.0, rel)), 4)
    s = round(max(0.0, min(1.0, s)), 4)
    pqf = round(c * r * rel * s, 4)

    return PrimitiveQuality(
        primitive_type=ptype,
        controllability=c, reach=r,
        reliability=rel, side_effects=s,
        pqf=pqf,
    )

def chain_potential(primitives: List[PrimitiveQuality]) -> Dict[str, Any]:
    """
    多原语组合潜力评估 — 如果存在信息泄露+任意写 → 完整利用链可行。

    抽取最小原语集构成完整攻击链:
      信息泄露 (read_*) + 控制流劫持 (write_*/exec_*) → 代码执行。
    返回链可行性和缺失环节。
    """
    if not primitives:
        return {'chain_possible': False, 'missing_link': 'no_primitives',
                'best_pqf': 0.0}

    has_read = any(p.primitive_type in (PrimitiveType.READ_OOB, PrimitiveType.READ_ARBITRARY)
                   for p in primitives)
    has_write = any(p.primitive_type in (PrimitiveType.WRITE_OOB, PrimitiveType.WRITE_CONTROLLED,
                                          PrimitiveType.WRITE_ARBITRARY)
                    for p in primitives)
    has_exec = any(p.primitive_type in (PrimitiveType.EXEC_CONTROL, PrimitiveType.CODE_EXEC)
                   for p in primitives)

    best_pqf = max(p.pqf for p in primitives)

    if has_exec:
        return {'chain_possible': True, 'chain_type': 'direct_exec',
                'best_pqf': best_pqf}
    if has_read and has_write:
        chain_pqf = round(
            max(p.pqf for p in primitives if p.primitive_type in
                (PrimitiveType.READ_OOB, PrimitiveType.READ_ARBITRARY)) *
            max(p.pqf for p in primitives if p.primitive_type in
                (PrimitiveType.WRITE_OOB, PrimitiveType.WRITE_CONTROLLED, PrimitiveType.WRITE_ARBITRARY)),
            4)
        return {'chain_possible': True, 'chain_type': 'leak+write',
                'chain_pqf': chain_pqf, 'best_pqf': best_pqf}
    if has_write:
        return {'chain_possible': False, 'missing_link': 'information_leak',
                'best_pqf': best_pqf}
    if has_read:
        return {'chain_possible': False, 'missing_link': 'control_flow_hijack',
                'best_pqf': best_pqf}

    return {'chain_possible': False, 'missing_link': 'all',
            'best_pqf': best_pqf}

def batch_score_primitives(
    vulnerabilities: List[Dict[str, Any]],
    crash_analysis: Optional[Dict[str, Any]] = None,
) -> List[PrimitiveQuality]:
    """批量原语质量评分。"""
    results = []
    for v in vulnerabilities:
        pq = score_primitive(v, crash_analysis)
        results.append(pq)
    results.sort(key=lambda p: p.pqf, reverse=True)
    return results
