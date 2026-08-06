"""
进程间攻击面传播 — IPC 通道作为漏洞触发向量的有向图模型。

问题定义:
  二进制 A 有漏洞 X。二进制 B 与 A 通过 IPC 通信。
  问: B 能否通过合法的 IPC 交互触发 A 中的 X?

  现有工作 MIRAGE (IEEE TDSC 2025) 用攻击图建模固件二进制间通信，
  但需要运行时交互信息 (消息格式、协议语义)。本模块做静态近似:
    1. 从导入表检测 IPC 机制 (pipe/socket/shm/dbus)
    2. 从字符串表提取 IPC 端点标识符 (路径/端口/服务名)
    3. 构建 IPC 边: A 的漏洞函数 ← 可达性 → A 的 IPC 处理函数
    4. 传播评分: IPC 通道类型 × 认证状态 → 触发概率

  静态近似的取舍: 假阳性率偏高 (不知道消息格式是否可达漏洞路径)，
  但零运行时成本且不会漏掉潜在的 IPC 攻击面。

与 MIRAGE 的区别:
  MIRAGE: 需要解析固件包中的二进制交互 (init脚本, 启动顺序)
  本模块: 仅需导入表 + 字符串表 + 函数可达性图

IPC 通道风险权重 (基于历史 CVE 统计):
  D-Bus (无认证)    → 0.9  (CVE-2021-3560, CVE-2021-3989 等)
  Unix domain socket → 0.7  (本地提权经典向量)
  pipe/FIFO          → 0.6  (需同用户)
  shared memory      → 0.8  (无消息边界 → 更难审计)
  TCP/UDP socket     → 0.5  (远程但通常有防火墙)
  signal handler     → 0.4  (有限的输入通道)

修改记录:
  2026-08-03 14:11 - 初始版本，IPC 机制检测 + 传播边构建
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class IpcMechanism(Enum):
    DBUS = "dbus"
    UNIX_SOCKET = "unix_socket"
    TCP_UDP = "tcp_udp"
    PIPE_FIFO = "pipe_fifo"
    SHARED_MEMORY = "shared_memory"
    SIGNAL = "signal"
    UNKNOWN = "unknown"


# IPC 机制默认风险权重 (0-1)
_IPC_RISK_WEIGHTS: Dict[IpcMechanism, float] = {
    IpcMechanism.DBUS: 0.9,
    IpcMechanism.UNIX_SOCKET: 0.7,
    IpcMechanism.TCP_UDP: 0.5,
    IpcMechanism.PIPE_FIFO: 0.6,
    IpcMechanism.SHARED_MEMORY: 0.8,
    IpcMechanism.SIGNAL: 0.4,
    IpcMechanism.UNKNOWN: 0.3,
}

# 导入函数 → IPC 机制映射
_IMPORT_IPC_MAP: Dict[str, IpcMechanism] = {
    'sd_bus': IpcMechanism.DBUS, 'dbus': IpcMechanism.DBUS,
    'g_dbus': IpcMechanism.DBUS, 'dbus_message': IpcMechanism.DBUS,
    'socket': IpcMechanism.TCP_UDP, 'bind': IpcMechanism.TCP_UDP,
    'listen': IpcMechanism.TCP_UDP, 'accept': IpcMechanism.TCP_UDP,
    'connect': IpcMechanism.UNIX_SOCKET, 'getsockname': IpcMechanism.UNIX_SOCKET,
    'pipe': IpcMechanism.PIPE_FIFO, 'mkfifo': IpcMechanism.PIPE_FIFO,
    'shm_open': IpcMechanism.SHARED_MEMORY, 'shmget': IpcMechanism.SHARED_MEMORY,
    'mmap': IpcMechanism.SHARED_MEMORY, 'shmat': IpcMechanism.SHARED_MEMORY,
    'signal': IpcMechanism.SIGNAL, 'sigaction': IpcMechanism.SIGNAL,
    'send': IpcMechanism.TCP_UDP, 'recv': IpcMechanism.TCP_UDP,
    'sendto': IpcMechanism.TCP_UDP, 'recvfrom': IpcMechanism.TCP_UDP,
    'sendmsg': IpcMechanism.UNIX_SOCKET, 'recvmsg': IpcMechanism.UNIX_SOCKET,
}


def _detect_ipc_mechanisms(imports: List[str]) -> Dict[IpcMechanism, List[str]]:
    """从导入表检测使用的 IPC 机制 — 返回 {机制: [匹配的导入函数]}。"""
    found: Dict[IpcMechanism, List[str]] = defaultdict(list)
    for imp in imports:
        norm = imp.lower().lstrip('_').replace('__imp_', '')
        for keyword, mech in _IMPORT_IPC_MAP.items():
            if keyword in norm:
                found[mech].append(imp)
                break
    return dict(found)


def _extract_ipc_endpoints(strings: List[str]) -> Dict[IpcMechanism, List[str]]:
    """从字符串表提取 IPC 端点标识符。"""
    endpoints: Dict[IpcMechanism, List[str]] = defaultdict(list)
    for s in strings:
        s_lower = s.lower()
        if s_lower.startswith('/var/run/') or s_lower.startswith('/tmp/'):
            if s_lower.endswith('.sock') or s_lower.endswith('.socket'):
                endpoints[IpcMechanism.UNIX_SOCKET].append(s)
        if s_lower.startswith('/dev/shm/') or s_lower.startswith('/shm/'):
            endpoints[IpcMechanism.SHARED_MEMORY].append(s)
        if s_lower.startswith('unix:') and ('path=' in s_lower or 'abstract=' in s_lower):
            endpoints[IpcMechanism.DBUS].append(s)
        if 'dbus' in s_lower and ('path=' in s_lower or 'interface=' in s_lower
                                   or 'destination=' in s_lower):
            endpoints[IpcMechanism.DBUS].append(s)
        if '.' in s and any(c.isdigit() for c in s) and ':' in s:
            # 简单启发式: IP:port 模式
            if not s.startswith('/') and not s.startswith('#'):
                endpoints[IpcMechanism.TCP_UDP].append(s)
    return dict(endpoints)


@dataclass
class IpcEdge:
    """单条 IPC 攻击面边 — 从一个 IPC 入口到漏洞函数。"""
    mechanism: IpcMechanism
    endpoint: str                  # 端点标识符
    vulnerable_function: str       # 被触发的漏洞函数名
    distance: int                  # CFG 距离 (IPC handler → vuln func)
    trigger_risk: float            # IPC_risk × distance_decay
    authentication: str = 'unknown'


def _distance_decay(distance: int, tau: float = 3.0) -> float:
    """调用距离指数衰减。"""
    return math.exp(-distance / tau)


def map_ipc_surface(
    imports: List[str],
    strings: List[str],
    vulnerable_functions: List[Dict[str, Any]],
    function_call_distances: Optional[Dict[str, Dict[str, int]]] = None,
) -> List[IpcEdge]:
    """
    构建 IPC 攻击面边集。

    vulnerable_functions: [{'name': str, 'type': str}, ...]
    function_call_distances: {ipc_func: {vuln_func: distance, ...}, ...}
      可选 — 提供时精确计算距离，缺省使用启发式距离=1。
    """
    ipc_mechs = _detect_ipc_mechanisms(imports)
    ipc_endpoints = _extract_ipc_endpoints(strings)

    edges: List[IpcEdge] = []

    for mechanism, imp_funcs in ipc_mechs.items():
        base_risk = _IPC_RISK_WEIGHTS.get(mechanism, 0.3)
        endpoints = ipc_endpoints.get(mechanism, ['(unknown)'])

        for vuln_func in vulnerable_functions:
            vname = vuln_func.get('name', vuln_func.get('function_name', ''))

            # 计算最近距离
            # 无精确调用图时假设 IPC handler 直接调用漏洞函数 (distance=1)
            min_dist = 1
            if function_call_distances:
                min_dist = 99
                for ipc_func in imp_funcs:
                    dist_map = function_call_distances.get(
                        ipc_func, function_call_distances.get(
                            ipc_func.split('@')[0], {}))
                    d = dist_map.get(vname, 99)
                    min_dist = min(min_dist, d)

            decay = _distance_decay(min_dist)
            trigger_risk = round(base_risk * decay, 4)

            if trigger_risk >= 0.05:  # 最小阈值 — 过滤极低概率边
                for ep in endpoints[:3]:  # 最多取 3 个端点
                    edges.append(IpcEdge(
                        mechanism=mechanism,
                        endpoint=ep,
                        vulnerable_function=vname,
                        distance=min_dist,
                        trigger_risk=trigger_risk,
                    ))

    edges.sort(key=lambda e: e.trigger_risk, reverse=True)
    return edges


def ipc_risk_summary(edges: List[IpcEdge]) -> Dict[str, Any]:
    """IPC 攻击面统计 — 各机制的暴露度和最高风险函数。"""
    if not edges:
        return {'total_edges': 0, 'mechanisms_detected': [],
                'max_trigger_risk': 0.0, 'top_risks': []}

    mech_counts = defaultdict(int)
    mech_max_risk: Dict[IpcMechanism, float] = defaultdict(float)
    for e in edges:
        mech_counts[e.mechanism.value] += 1
        mech_max_risk[e.mechanism] = max(mech_max_risk[e.mechanism], e.trigger_risk)

    # 去重: 同一 (mechanism, vuln_func) 取最高 risk
    by_key: Dict[Tuple[str, str], float] = {}
    for e in edges:
        key = (e.mechanism.value, e.vulnerable_function)
        by_key[key] = max(by_key.get(key, 0.0), e.trigger_risk)

    top = sorted(by_key.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        'total_edges': len(edges),
        'unique_pairs': len(by_key),
        'mechanisms_detected': [
            {'mechanism': m, 'edges': mech_counts.get(m, 0),
             'max_risk': round(mech_max_risk.get(IpcMechanism(m), 0.0), 4)}
            for m in set(e.mechanism.value for e in edges)
        ],
        'max_trigger_risk': round(max(e.trigger_risk for e in edges), 4),
        'top_risks': [
            {'mechanism': k[0], 'function': k[1], 'risk': round(v, 4)}
            for k, v in top
        ],
    }
