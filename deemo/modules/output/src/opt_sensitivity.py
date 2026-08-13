"""
编译器优化敏感性评分 — 漏洞发现对优化级别的鲁棒性量化。

问题定义:
  FSE 2025 证实 "no existing basic-block-centric binary diffing tools properly
  handle all peephole-induced changes"。在 -O0 构建上发现的漏洞可能在 -O2/-O3
  中被消除 (死代码消除/内联展开/常量折叠) 或变形 (指令重排/循环展开)。

  安全审计需要知道: "这个漏洞在 release build 中还存在吗?"

  本模块不模拟编译器行为，而是通过代码模式分析估算敏感性:
    1. 死存储模式 (memset后被覆盖 → -O2+ 可能消除)
    2. 可内联调用点 (static函数 → -O2+ 内联 → CFG 变化)
    3. 循环展开潜力 (小循环 → -O3 展开 → 基本块复制)
    4. 常量传播倾向 (函数参数为常量 → -O1+ 折叠)
    5. 尾部调用优化 (递归 → -O2+ TCO → 栈溢出消除)

  输出: 敏感性评分 + 每因子的受影响程度。

  FSE 2025: "Revisiting Optimization-Resilience Claims in Binary Diffing Tools"
  PLocator: CFG 常量锚点对抗优化变化的 44-75% 提升
  arXiv 2025.12: 函数内联可武器化以规避 ML 二进制分析模型

修改记录:
  2025-02-06 09:52 - 初始版本，五因子优化敏感性模型
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

@dataclass
class OptSensitivity:
    """单个漏洞的优化敏感性评估。"""
    function_name: str
    vuln_type: str
    sensitivity_score: float       # 0-10, 越高越敏感 (越可能被优化消除/变形)
    dead_store_risk: float         # 死存储消除风险
    inline_risk: float             # 函数内联风险
    loop_unroll_risk: float        # 循环展开风险
    const_prop_risk: float         # 常量传播风险
    tco_risk: float                # 尾部调用优化风险
    likely_persists: bool = True   # 预计在 -O2 中仍然存在?
    recommendation: str = ""

# 五因子的归一化权重
_DEFAULT_WEIGHTS = (0.25, 0.30, 0.20, 0.15, 0.10)
# 死存储, 内联, 循环展开, 常量传播, TCO

def _dead_store_risk(pseudocode: str, block_instructions: List[List[str]]) -> float:
    """
    死存储消除风险 — memset/bzero 后无读取即被覆盖的模式。

    检测: memset(buf, 0, ...) 后面紧跟 memcpy(buf, src, ...) 或赋值。
    编译器将第一个 memset 视为死存储并消除。
    CWE-14 的直接体现。
    """
    joined_pseudo = pseudocode.lower()
    joined_ins = ' '.join(' '.join(ins).lower() for ins in block_instructions)

    risk = 0.0
    # 模式 1: memset + 立即覆盖
    if 'memset' in joined_pseudo and ('memcpy' in joined_pseudo or 'strcpy' in joined_pseudo):
        risk += 0.5
    if 'memset' in joined_ins:
        risk += 0.3
    if 'bzero' in joined_pseudo or 'bzero' in joined_ins:
        risk += 0.2
    # 模式 2: 敏感缓冲区零化 (CWE-14)
    if any(kw in joined_pseudo for kw in ('password', 'key', 'secret', 'token', 'credential')):
        if 'memset' in joined_pseudo or 'bzero' in joined_pseudo:
            risk += 0.3

    return min(risk, 1.0)

def _inline_risk(is_static: bool, caller_count: int, func_size_ins: int) -> float:
    """
    函数内联风险 — static + 小型 + 单调用者 = 高内联概率。

    GCC -O2: 自动内联小函数 (< 约 30 条指令)。
    LLVM -O2: 类似启发式。
    内联后 CFG 完全吸收到调用者中 → 基本块签名失效。
    """
    if not is_static:
        return 0.05  # 非 static → 不太可能内联
    risk = 0.3
    if func_size_ins <= 30:
        risk += 0.35
    if caller_count <= 2:
        risk += 0.25
    return min(risk, 1.0)

def _loop_unroll_risk(loop_count_estimate: int, has_small_loop: bool) -> float:
    """
    循环展开风险 — 小循环 (< 8 次迭代) 在 -O3 可能完全展开。

    展开 → 基本块复制 → 块签名匹配失败 → 漏洞"消失"的假象。
    """
    if not has_small_loop:
        return 0.0
    risk = 0.3
    if 0 < loop_count_estimate <= 4:
        risk += 0.5  # 微型循环 → 几乎必展开
    elif loop_count_estimate <= 8:
        risk += 0.3
    elif loop_count_estimate <= 16:
        risk += 0.1
    return min(risk, 1.0)

def _const_prop_risk(has_const_args: bool, has_const_branches: bool) -> float:
    """
    常量传播风险 — 函数参数或分支条件为编译时常量。

    -O1 即启用基本常量折叠；-O2 启用条件常量传播 (CCP)。
    常量分支被消除 → 整个基本块消失。
    """
    if not has_const_args and not has_const_branches:
        return 0.05
    risk = 0.15
    if has_const_args:
        risk += 0.35
    if has_const_branches:
        risk += 0.40  # 常量分支消除是整个块消失的主因
    return min(risk, 1.0)

def _tco_risk(is_recursive: bool, is_tail_recursive: bool) -> float:
    """
    尾部调用优化风险 — 递归函数在 -O2+ 可能被转为迭代。

    TCO 消除栈帧 → 栈溢出漏洞的可能性消失。
    注意: 此处的"风险"指漏洞因优化而消失的风险，不是安全风险。
    """
    if not is_recursive:
        return 0.0
    if is_tail_recursive:
        return 0.9  # 几乎确定尾递归会被优化
    return 0.3      # 普通递归 — 可能被部分优化

def score_optimization_sensitivity(
    function_name: str = '',
    vuln_type: str = '',
    pseudocode: str = '',
    block_instructions: Optional[List[List[str]]] = None,
    is_static: bool = False,
    caller_count: int = 1,
    func_size_ins: int = 20,
    loop_count_estimate: int = 0,
    has_small_loop: bool = False,
    has_const_args: bool = False,
    has_const_branches: bool = False,
    is_recursive: bool = False,
    is_tail_recursive: bool = False,
    weights: Optional[Tuple[float, ...]] = None,
) -> OptSensitivity:
    """
    计算漏洞的优化敏感性。

    返回 OptSensitivity — 含五因子分解和持久性判定。
    阈值 5.0: sensitivity ≥ 5.0 → likely_persists = False (可能在 -O2 中消失)
    """
    w = weights or _DEFAULT_WEIGHTS
    bb_ins = block_instructions or []

    ds = _dead_store_risk(pseudocode, bb_ins)
    il = _inline_risk(is_static, caller_count, func_size_ins)
    lu = _loop_unroll_risk(loop_count_estimate, has_small_loop)
    cp = _const_prop_risk(has_const_args, has_const_branches)
    tc = _tco_risk(is_recursive, is_tail_recursive)

    raw = w[0]*ds + w[1]*il + w[2]*lu + w[3]*cp + w[4]*tc
    score = round(raw * 10.0, 1)

    persists = score < 5.0  # 阈值 5.0

    # 推荐操作
    if not persists:
        if ds >= 0.5:
            rec = "在 -O0 重新验证。使用 volatile 或 compiler barrier 保护敏感缓冲区"
        elif il >= 0.5:
            rec = "在 -O0 或 -O1 重新验证。考虑 __attribute__((noinline))"
        elif tc >= 0.5:
            rec = "非优化构建中验证。尾递归可加 #pragma GCC optimize(\"O0\")"
        else:
            rec = "在多个优化级别 (-O0/-O2/-O3) 下交叉验证此发现"
    else:
        rec = "漏洞在 release build 中预计保留"

    return OptSensitivity(
        function_name=function_name or 'unknown',
        vuln_type=vuln_type or 'unknown',
        sensitivity_score=score,
        dead_store_risk=round(ds * 10, 1),
        inline_risk=round(il * 10, 1),
        loop_unroll_risk=round(lu * 10, 1),
        const_prop_risk=round(cp * 10, 1),
        tco_risk=round(tc * 10, 1),
        likely_persists=persists,
        recommendation=rec,
    )

def batch_sensitivity(
    vulnerabilities: List[Dict[str, Any]],
) -> List[OptSensitivity]:
    """批量评分 — 按敏感性降序 (最可能被优化消除的排前面)。"""
    results = []
    for v in vulnerabilities:
        s = score_optimization_sensitivity(
            function_name=v.get('function_name', v.get('name', '')),
            vuln_type=v.get('type', ''),
            pseudocode=v.get('pseudocode', ''),
            block_instructions=v.get('block_instructions'),
            is_static=v.get('is_static', False),
            caller_count=v.get('caller_count', v.get('fan_in', 1)),
            func_size_ins=v.get('func_size_ins', v.get('instruction_count', 20)),
            loop_count_estimate=v.get('loop_count_estimate', 0),
            has_small_loop=v.get('has_small_loop', False),
            has_const_args=v.get('has_const_args', False),
            has_const_branches=v.get('has_const_branches', False),
            is_recursive=v.get('is_recursive', False),
            is_tail_recursive=v.get('is_tail_recursive', False),
        )
        results.append(s)
    results.sort(key=lambda s: s.sensitivity_score, reverse=True)
    return results

def sensitivity_summary(results: List[OptSensitivity]) -> Dict[str, Any]:
    """优化敏感性统计摘要。"""
    if not results:
        return {'total': 0, 'persists': 0, 'may_disappear': 0,
                'mean_sensitivity': 0.0, 'high_sensitivity': []}

    persists = sum(1 for r in results if r.likely_persists)
    may_drop = len(results) - persists
    high = [{'function': r.function_name, 'score': r.sensitivity_score,
             'recommendation': r.recommendation}
            for r in results if r.sensitivity_score >= 7.0][:5]

    return {
        'total': len(results),
        'persists_in_release': persists,
        'may_disappear_in_release': may_drop,
        'mean_sensitivity': round(sum(r.sensitivity_score for r in results) / len(results), 1),
        'high_sensitivity': high,
    }
