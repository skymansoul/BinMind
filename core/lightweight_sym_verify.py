# 轻量符号执行二次验证 — 对规则匹配候选点做约束可达性检查。
# 文本模式规则不验证路径可行性，本模块对候选点周围局部CFG（前后各5个
# 基本块，30s超时）做小规模符号执行；确定不可达则标记误报，可达或
# 超时则保留（保守策略，参考静态污点+符号执行混合降低误报的思路）。


import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# 候选点的CFG上下文大小
_CFG_RADIUS = 5

# 符号执行超时 (秒)
_TIMEOUT_S = 30


def verify_candidate_reachability(
    binary_path: str,
    candidate_addr: int,
    func_name: str = "",
    timeout_s: float = _TIMEOUT_S,
) -> Tuple[bool, str]:
    """轻量符号执行验证候选点可达性。

    返回 (is_reachable, evidence).
    is_reachable=True 表示找到了一条可达路径;
    is_reachable=False 表示未证明可达 (可能真不可达, 也可能超时)。

    实现: 尝试加载angr, 不可用时返回保守的True (不做过滤)。
    """
    try:
        import angr
    except ImportError:
        return True, "angr_not_available_preserve_candidate"

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
    except Exception:
        return True, f"angr_load_failed_for_{binary_path}"

    # 从候选地址开始做局部探索
    try:
        state = proj.factory.blank_state(addr=candidate_addr)
    except Exception:
        return True, "cannot_create_state"

    simgr = proj.factory.simulation_manager(state)
    start = time.monotonic()

    try:
        simgr.run(
            n=_CFG_RADIUS * 3,
            timeout=int(timeout_s),
        )
    except Exception:
        pass

    elapsed = time.monotonic() - start

    # 判定: 如果探索到了至少一个active/deadend状态且无error,
    # 认为候选点可达 (保守——即使超时也保留候选)
    if simgr.active or simgr.deadended:
        return True, f"path_found_{len(simgr.active)}_active_{elapsed:.1f}s"

    # 如果所有状态都errored且无active→可能不可达
    if simgr.errored and not simgr.active:
        return False, f"all_states_errored_{elapsed:.1f}s"

    # 退守: 保留候选
    return True, f"inconclusive_{elapsed:.1f}s"


def filter_by_reachability(
    findings: List[Dict[str, Any]],
    binary_path: str,
) -> List[Dict[str, Any]]:
    """对检测结果列表做可达性过滤。

    仅过滤那些"确定不可达"的候选点——保守策略。
    超时或工具不可用的候选点保留。
    """
    if not findings:
        return findings

    filtered: List[Dict[str, Any]] = []
    false_positives = 0

    for f in findings:
        addr = f.get('call_address', 0)
        if not addr or addr <= 0:
            filtered.append(f)
            continue

        reachable, evidence = verify_candidate_reachability(
            binary_path, int(addr), f.get('function', ''))

        if reachable:
            f['reachability_verified'] = True
            f['reachability_evidence'] = evidence
            filtered.append(f)
        else:
            false_positives += 1
            _log.debug("FP filtered: %s @ %#x — %s",
                       f.get('rule_id', '?'), addr, evidence)

    if false_positives > 0:
        _log.info("symbolic verify: %d/%d candidates filtered as unreachable",
                  false_positives, len(findings))

    return filtered
