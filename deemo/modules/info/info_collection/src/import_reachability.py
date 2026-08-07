# Created: 2026-06-26 17:22:10
#
# import_reachability — 导入可达性图 (Import Reachability Graph)
# 仅使用导入表构建从用户输入函数到危险汇聚点的有向图，
# 无需反汇编/CFG 恢复。近似轻量级污点追踪，估算危险函数的实际可达性。
#
# 核心假设: 同一 DLL 内的函数间存在隐式调用边 (该 DLL 的其他导入函数
# 可能作为回调或间接调用被触发)。这是对完整调用图的粗略下近似。
#
# 输入函数 (sources): 任何接收外部数据的 API
#   - 网络: recv, recvfrom, recvmsg, read, fread, WSARecv, InternetReadFile
#   - 文件: fopen, open, CreateFile, ReadFile, fgets
#   - 进程间: recv, getenv, readlink, RegQueryValueEx
#
# 危险汇聚点 (sinks): 可能执行任意代码或写入任意内存的 API
#   - 代码执行: system, execve, popen, CreateProcess, WinExec, ShellExecute
#   - 内存损坏: strcpy, strcat, sprintf, memcpy, gets
# 权限修改: mprotect, VirtualProtect, chmod
#
# 图构建规则:
#   1. 同一 DLL 内的函数两两相连 (DLL 内聚假设)
#   2. 通过 DLL 依赖传递: kernel32!CreateProcess 与 kernel32!ReadFile 互连
#   3. 短路径 < 3 跳 → 高度可疑 (输入直接可达危险汇聚点)
#   4. 长路径或无路径 → 危险函数可能位于死代码或需特殊触发条件

import math
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict, deque


# DLL 所属类别 (决定隐式连通性)
_DLL_CATEGORIES = {
    "kernel32.dll": "win32_core", "ntdll.dll": "win32_core",
    "advapi32.dll": "win32_sec", "user32.dll": "win32_ui",
    "ws2_32.dll": "win32_net", "wininet.dll": "win32_net",
    "msvcrt.dll": "c_runtime", "ucrtbase.dll": "c_runtime",
    "libc.so.6": "c_runtime", "libpthread.so.0": "posix_thread",
    "libdl.so.2": "posix_dl", "libm.so.6": "posix_math",
    "libSystem.B.dylib": "darwin_core",
}

# 输入源函数 (source nodes)
_SOURCES: Set[str] = {
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets",
    "fopen", "open", "CreateFile", "ReadFile", "WSARecv",
    "InternetReadFile", "getenv", "readlink", "RegQueryValueEx",
    "scanf", "fscanf", "sscanf", "gets", "getchar",
}

# 危险汇聚点 (sink nodes)
_SINKS_CODE_EXEC: Set[str] = {
    "system", "execve", "execvp", "execl", "execle", "execlp",
    "popen", "CreateProcess", "CreateProcessA", "CreateProcessW",
    "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "CreateRemoteThread", "fork", "dlopen", "LoadLibrary",
}
_SINKS_MEMORY: Set[str] = {
    "strcpy", "strcat", "sprintf", "vsprintf", "memcpy",
    "memmove", "gets", "memset", "bcopy",
}
_SINKS_PRIVILEGE: Set[str] = {
    "mprotect", "VirtualProtect", "VirtualAlloc", "mmap",
    "chmod", "chown", "setuid", "setgid",
}
_ALL_SINKS = _SINKS_CODE_EXEC | _SINKS_MEMORY | _SINKS_PRIVILEGE


def _normalize_api(name: str) -> str:
    """去 A/W 后缀 + 小写归一化。"""
    _n = name.strip().lower()
    if (_n.endswith('a') or _n.endswith('w')) and len(_n) > 1:
        _n = _n[:-1]
    return _n


def _dll_category(dll_name: str) -> str:
    _key = dll_name.lower().strip()
    return _DLL_CATEGORIES.get(_key, _key.split('.')[0])


def build_reachability_graph(imports: Dict[str, List[str]]) -> Dict:
    """从导入表构建可达性图。

    imports: {dll_name: [func_name, ...]} — 来自 binary_info 的导入表

    返回:
    - nodes: {func_id: {name, dll, category, is_source, is_sink}}
    - edges: [[from_id, to_id], ...]
    - source_nodes: [node_id, ...]
    - sink_nodes: {sink_type: [node_id, ...]}
    - reachability_matrix: 每个 source 到每个 sink 的最短路径长度
    """
    _nodes: Dict[int, Dict] = {}
    _node_ids: Dict[str, int] = {}
    _node_list: List[Tuple[str, str]] = []  # (func_name, dll_name)
    _next_id = 0

    # 构建节点
    for _dll, _funcs in imports.items():
        for _fn in _funcs:
            _norm = _normalize_api(_fn)
            _key = f"{_dll}:{_norm}"
            if _key not in _node_ids:
                _node_ids[_key] = _next_id
                _node_list.append((_norm, _dll))
                _next_id += 1

    if _next_id == 0:
        return {"nodes": {}, "edges": [], "source_nodes": [],
                "sink_nodes": {}, "reachability": {}, "dead_sinks": [],
                "reachability_matrix": {}, "risk_score": 0.0, "risk_level": "LOW"}

    # 节点属性
    _source_ids = []
    _sink_ids: Dict[str, List[int]] = {
        "code_exec": [], "memory_corruption": [], "privilege": [],
    }

    for _nid, (_fn, _dll) in enumerate(_node_list):
        _cat = _dll_category(_dll)
        _is_source = _fn in _SOURCES
        _is_sink = _fn in _ALL_SINKS
        _sink_type = None

        if _fn in _SINKS_CODE_EXEC:
            _sink_type = "code_exec"
            _sink_ids["code_exec"].append(_nid)
        elif _fn in _SINKS_MEMORY:
            _sink_type = "memory_corruption"
            _sink_ids["memory_corruption"].append(_nid)
        elif _fn in _SINKS_PRIVILEGE:
            _sink_type = "privilege"
            _sink_ids["privilege"].append(_nid)

        if _is_source:
            _source_ids.append(_nid)

        _nodes[_nid] = {
            "name": _fn, "dll": _dll, "category": _cat,
            "is_source": _is_source, "is_sink": _is_sink,
            "sink_type": _sink_type,
        }

    # 构建边: 同 DLL 或同 category → 隐式连通
    _edges = []
    _by_dll: Dict[str, List[int]] = defaultdict(list)
    _by_cat: Dict[str, List[int]] = defaultdict(list)

    for _nid, _node in _nodes.items():
        _by_dll[_node["dll"]].append(_nid)
        _by_cat[_node["category"]].append(_nid)

    # 同 DLL 内全连接 (若 ≤ 30 个函数；大型 DLL 采样连接)
    for _dll, _member_ids in _by_dll.items():
        if len(_member_ids) <= 30:
            for _i, _a in enumerate(_member_ids):
                for _b in _member_ids[_i + 1:]:
                    _edges.append([_a, _b])
                    _edges.append([_b, _a])
        else:
            # 大型 DLL: 仅连接同 category 内的函数对
            for _i, _a in enumerate(_member_ids):
                for _b in _member_ids[_i + 1:]:
                    if _nodes[_a]["category"] == _nodes[_b]["category"]:
                        _edges.append([_a, _b])
                        _edges.append([_b, _a])

    # 跨 DLL 同类连接
    _cats = set(n["category"] for n in _nodes.values())
    for _cat in _cats:
        _members = _by_cat[_cat]
        if len(_members) <= 20:
            for _i, _a in enumerate(_members):
                for _b in _members[_i + 1:]:
                    _edges.append([_a, _b])

    # BFS 计算最短路径
    _adj: Dict[int, List[int]] = defaultdict(list)
    for _a, _b in _edges:
        _adj[_a].append(_b)

    _reachability: Dict[str, Dict[str, int]] = {}

    for _src_id in _source_ids:
        _src_name = _nodes[_src_id]["name"]
        _dist = {_src_id: 0}
        _q = deque([_src_id])
        while _q:
            _u = _q.popleft()
            for _v in _adj.get(_u, []):
                if _v not in _dist:
                    _dist[_v] = _dist[_u] + 1
                    _q.append(_v)

        _reach_sinks = {}
        for _sink_type, _sink_id_list in _sink_ids.items():
            _min_dist = 999
            _closest = None
            for _sid in _sink_id_list:
                _d = _dist.get(_sid, 999)
                if _d < _min_dist:
                    _min_dist = _d
                    _closest = _nodes[_sid]["name"]
            if _min_dist < 999:
                _reach_sinks[_sink_type] = {
                    "min_distance": _min_dist,
                    "closest_sink": _closest,
                }

        if _reach_sinks:
            _reachability[_src_name] = _reach_sinks

    # 死代码危险函数: 所有 sink 中无 source 可达的
    _dead_sinks = []
    # 最短路径索引: {sink_function_name: min_distance} — 供 Tier 2 可达性增强使用
    _shortest_paths: Dict[str, int] = {}
    for _sink_type, _sink_id_list in _sink_ids.items():
        for _sid in _sink_id_list:
            _reachable = False
            _min_d = 999
            for _src_id in _source_ids:
                _dist = _bfs_distance(_adj, _src_id, _sid)
                if _dist < 999:
                    _reachable = True
                    _min_d = min(_min_d, _dist)
            if not _reachable:
                _dead_sinks.append({
                    "function": _nodes[_sid]["name"],
                    "dll": _nodes[_sid]["dll"],
                    "sink_type": _sink_type,
                })
            _shortest_paths[_nodes[_sid]["name"]] = _min_d

    # 风险评分
    _risk_score = _compute_risk_score(
        _source_ids, _sink_ids, _adj, _nodes)

    return {
        "nodes": _nodes,
        "edges": _edges,
        "source_nodes": _source_ids,
        "sink_nodes": _sink_ids,
        "reachability": _reachability,
        "shortest_paths": _shortest_paths,
        "dead_sinks": _dead_sinks,
        "risk_score": round(_risk_score, 4),
        "risk_level": ("CRITICAL" if _risk_score > 0.7 else
                       "HIGH" if _risk_score > 0.4 else
                       "MEDIUM" if _risk_score > 0.15 else "LOW"),
    }


def _bfs_distance(adj: Dict[int, List[int]], start: int, target: int) -> int:
    _dist = {start: 0}
    _q = deque([start])
    while _q:
        _u = _q.popleft()
        if _u == target: return _dist[_u]
        for _v in adj.get(_u, []):
            if _v not in _dist:
                _dist[_v] = _dist[_u] + 1
                _q.append(_v)
    return 999


def _compute_risk_score(
    source_ids: List[int],
    sink_ids: Dict[str, List[int]],
    adj: Dict[int, List[int]],
    nodes: Dict[int, Dict],
) -> float:
    """综合可达性风险评分: 短路径 (≤2跳) sink 数 / 总 sink 数，logistic 平滑。"""
    _total_sinks = sum(len(v) for v in sink_ids.values())
    if _total_sinks == 0 or not source_ids:
        return 0.0

    _reachable_short = 0
    for _sink_type, _sink_id_list in sink_ids.items():
        for _sid in _sink_id_list:
            for _src_id in source_ids:
                _d = _bfs_distance(adj, _src_id, _sid)
                if _d <= 2:
                    _reachable_short += 1
                    break

    _ratio = _reachable_short / _total_sinks
    # logistic 平滑: 快速上升区在 0.05-0.30
    _score = 1.0 / (1.0 + math.exp(-12 * (_ratio - 0.15)))
    return _score
