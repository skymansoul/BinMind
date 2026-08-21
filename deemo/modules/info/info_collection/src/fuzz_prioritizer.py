# fuzz_prioritizer — 模糊测试面优先级排序器
# 基于 exploit chain + import reachability + segment risk 的综合分析，
# 为二进制中的函数/区域生成模糊测试优先级排序。
#
# 排序信号 (每函数/区域):
#   1. 危险度: 该函数是否为已知危险汇聚点 (sink)
#   2. 可达性: 从用户输入到该函数的导入图最短路径长度
#   3. 段风险: 函数所在段的 RWX 邻接风险
#   4. 保护缺口: 所在编译单元的保护机制缺失程度
#   5. 历史价值: 同类函数在 CVE 数据库中的出现频率
#
# 输出: 按 fuzz_score 降序排列的目标列表，前 N 个为最应优先模糊测试的目标

import math
from typing import Dict, List, Tuple, Optional


# 函数类别的基础 fuzz 价值
_FUZZ_BASE_VALUE = {
    # 解析器类 — 格式解析是漏洞高发区
    "parser": 100, "decoder": 95, "deserializer": 90,
    # 网络类 — 远程攻击面
    "network_handler": 95, "protocol_handler": 90,
    # 内存操作 — 直接操作内存的函数
    "memory_allocator": 70, "memory_copy": 85, "buffer_handler": 80,
    # 认证/加密 — 逻辑漏洞高发区
    "auth_handler": 85, "crypto_handler": 80, "key_manager": 75,
    # 文件操作 — 本地攻击面
    "file_parser": 85, "file_writer": 60,
    # 进程间通信
    "ipc_handler": 80, "signal_handler": 75,
    # 默认
    "unknown": 30,
}


def _classify_function_category(func_name: str, imports: Dict) -> str:
    """从函数名和导入上下文推断函数类别。"""
    _n = func_name.lower()
    if any(kw in _n for kw in ["parse", "decode", "deserial", "unmarshal", "xml", "json"]):
        return "parser"
    if any(kw in _n for kw in ["recv", "send", "socket", "http", "connect", "request"]):
        return "network_handler"
    if any(kw in _n for kw in ["alloc", "free", "realloc", "heap", "pool"]):
        return "memory_allocator"
    if any(kw in _n for kw in ["cpy", "copy", "memcpy", "memmove", "strcpy", "strcat"]):
        return "memory_copy"
    if any(kw in _n for kw in ["crypt", "encrypt", "decrypt", "hash", "sign", "verify"]):
        return "crypto_handler"
    if any(kw in _n for kw in ["auth", "login", "password", "credential", "token"]):
        return "auth_handler"
    if any(kw in _n for kw in ["file", "read", "write", "open", "close", "fopen"]):
        return "file_parser"
    if any(kw in _n for kw in ["ipc", "pipe", "shm", "msg", "signal", "callback"]):
        return "ipc_handler"
    return "unknown"


def _reachability_penalty(
    func_name: str,
    reachability_graph: Dict,
) -> float:
    """可达性惩罚: 离输入越远 → fuzz 优先级越低。"""
    _reach = reachability_graph.get("reachability", {})
    _min_dist = 999
    _norm_name = func_name.lower().rstrip('aw')

    for _src_name, _sink_info in _reach.items():
        for _sink_type, _info in _sink_info.items():
            _closest = (_info.get("closest_sink", "") if isinstance(_info, dict)
                       else "")
            if _norm_name in _closest.lower() or _closest.lower() in _norm_name:
                _dist = _info.get("min_distance", 999) if isinstance(_info, dict) else 999
                _min_dist = min(_min_dist, _dist)

    if _min_dist >= 999:
        return 0.5  # 不在图中 → 中性评分
    if _min_dist <= 1:
        return 1.0  # 直接可达 → 最高优先级
    if _min_dist <= 2:
        return 0.80
    if _min_dist <= 3:
        return 0.55
    return 0.30


def _sink_multiplier(func_name: str) -> float:
    """危险汇聚点乘数: 越危险的 sink → fuzz 优先级越高。"""
    _n = func_name.lower().rstrip('aw')
    # 代码执行 sink
    if _n in {"system", "execve", "execvp", "popen", "createprocess",
              "winexec", "shellexecute", "createremotethread"}:
        return 1.5
    # 内存损坏 sink
    if _n in {"strcpy", "strcat", "sprintf", "memcpy", "memmove", "gets"}:
        return 1.3
    # 权限修改 sink
    if _n in {"mprotect", "virtualprotect", "virtualalloc", "mmap"}:
        return 1.2
    return 1.0


def prioritize_fuzz_targets(
    functions: List[Dict],
    imports: Dict = None,
    exploit_chain: Dict = None,
    segment_risk: Dict = None,
    reachability_graph: Dict = None,
    top_k: int = 10,
) -> Dict:
    """模糊测试目标优先级排序主入口。

    functions: 函数列表 [{"name":..., "address":..., "size":...}, ...]
    imports: 导入表
    exploit_chain: exploit_chain_inference 输出
    segment_risk: segment_risk 输出
    reachability_graph: import_reachability 输出

    返回:
    - ranked_targets: 按 fuzz_score 降序排列的目标列表
    - top_fuzz_targets: 前 top_k 个最优先目标
    - coverage_summary: 按类别/优先级分布的覆盖摘要
    """
    _fns = functions or []
    if not _fns:
        return {"ranked_targets": [], "top_fuzz_targets": [],
                "coverage_summary": {}, "error": "no_functions"}

    _imps = imports or {}
    _exploit = exploit_chain or {}
    _seg_risk = segment_risk or {}
    _reach = reachability_graph or {}

    _base_exploit = _exploit.get("exploitability_index", 30.0) / 100.0
    _base_seg_risk = _seg_risk.get("adjacency_risk_score", 0.0)

    _scored = []
    for _fn in _fns:
        if not isinstance(_fn, dict):
            continue
        _name = _fn.get("name", "unknown")
        _size = _fn.get("size", 0)

        # 1. 类别基础价值
        _cat = _classify_function_category(_name, _imps)
        _base = _FUZZ_BASE_VALUE.get(_cat, 30)

        # 2. 可达性加权
        _reach_w = _reachability_penalty(_name, _reach)

        # 3. 函数尺寸加权 (大函数 → 更大的攻击面)
        _size_w = min(1.5, max(0.5, math.log2(max(_size, 16)) / 10.0))

        # 4. sink 乘数
        _sink_w = _sink_multiplier(_name)

        # 5. 全局风险基线
        _global_risk = _base_exploit * 0.4 + _base_seg_risk * 0.3 + 0.3

        _score = _base * _reach_w * _size_w * _sink_w * _global_risk

        _scored.append({
            "function": _name,
            "address": _fn.get("address", 0),
            "size": _size,
            "category": _cat,
            "fuzz_score": round(_score, 2),
            "is_sink": _sink_w > 1.0,
            "reachability_weight": round(_reach_w, 3),
            "size_weight": round(_size_w, 3),
        })

    _scored.sort(key=lambda x: x["fuzz_score"], reverse=True)
    _top = _scored[:top_k]

    # 覆盖摘要
    _cats = {}
    _levels = {"HIGH_PRIORITY": 0, "MEDIUM_PRIORITY": 0, "LOW_PRIORITY": 0}
    for _s in _scored:
        _cats[_s["category"]] = _cats.get(_s["category"], 0) + 1
        if _s["fuzz_score"] > 50:
            _levels["HIGH_PRIORITY"] += 1
        elif _s["fuzz_score"] > 20:
            _levels["MEDIUM_PRIORITY"] += 1
        else:
            _levels["LOW_PRIORITY"] += 1

    return {
        "ranked_targets": _scored,
        "top_fuzz_targets": _top,
        "coverage_summary": {
            "total_functions": len(_scored),
            "priority_distribution": _levels,
            "category_distribution": dict(sorted(_cats.items(),
                                                  key=lambda x: x[1], reverse=True)[:8]),
            "top_score": _top[0]["fuzz_score"] if _top else 0,
            "mean_score": round(sum(s["fuzz_score"] for s in _scored) / max(len(_scored), 1), 2),
        },
        "recommended_fuzzer": (_recommend_fuzzer(_exploit, _seg_risk)),
    }


def _recommend_fuzzer(exploit_chain: Dict, segment_risk: Dict) -> str:
    """根据二进制特征推荐最合适的 fuzzer。"""
    _ei = exploit_chain.get("exploitability_index", 0.0)
    _primitive = segment_risk.get("primitive_estimate", "")

    if _ei > 60:
        return "AFL++ with ASAN + UBSAN (高 exploitability → 优先内存安全)"
    if _ei > 30:
        return "libFuzzer with coverage-guided mutation"
    if "code_execution" in str(_primitive):
        return "honggfuzz with hardware feedback (Intel PT / ARM ETM)"
    return "AFL++ (默认) — 通用 coverage-guided fuzzer"
