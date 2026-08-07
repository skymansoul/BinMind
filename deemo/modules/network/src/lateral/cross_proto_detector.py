# 修改记录:
# 2025-08-06 14:41 - 初始实现：跨协议行为序列对齐——检测横向移动模式

"""多协议横向移动检测 — 跨SMB/RDP/SSH/WinRM的行为序列关联。

APT攻击的核心阶段：在初始入侵后，攻击者在网络中横向移动寻找高价值目标。
单协议检测（如只看SMB）漏检率>50%——攻击者切换协议以规避。

本模块的核心——跨协议行为序列对齐（CP-BSA）：
1. 从多个协议日志中提取"主机间交互事件"——
   (src_host, dst_host, protocol, action, timestamp)。
2. 构建多协议交互时间线并按(src→dst)对有序列对齐。
3. 检测横向移动特征模式：
   - 扫描→登录→执行：短时间内N个目标的同协议序列
   - 协议跳跃：同一(src,dst)对在时间窗口内使用≥3种协议
   - 凭证复用：同一认证token/源IP出现在多个目标的成功登录中
4. 输出横向移动路径图和受感染主机列表。

与既有模块的关系：
- cross_protocol_correlation.py: 协议格式级对比。本模块是行为序列级对齐。
- forensic_causal_graph.py: 因果关系图。本模块提供横向移动这一特定因果模式。
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9


class ActionType(Enum):
    SCAN = "scan"           # 端口扫描/服务发现
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    EXECUTE = "execute"      # 远程命令执行
    FILE_TRANSFER = "file_transfer"
    TUNNEL_SETUP = "tunnel_setup"
    PRIVILEGE_ESCALATE = "privilege_escalate"
    DATA_EXFIL = "data_exfil"


@dataclass
class HostInteraction:
    """一次主机间交互事件。"""
    src_host: str
    dst_host: str
    protocol: str         # SMB / RDP / SSH / WinRM / WMI / PSRemoting
    action: ActionType
    timestamp: float
    auth_user: str = ""
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_key(self) -> str:
        return f"{self.src_host}→{self.dst_host}"


@dataclass
class LateralMovementPath:
    """一条检测到的横向移动路径。"""
    path_hosts: List[str]
    protocols_used: List[str]
    start_time: float
    end_time: float
    interaction_count: int
    credential_reuse_count: int
    risk_score: float
    is_automated: bool  # 自动扫描特征


class CrossProtocolLateralDetector:
    """多协议横向移动检测器。

    使用范式：
      detector = CrossProtocolLateralDetector()
      for event in network_events:
          detector.ingest_interaction(event)
      paths = detector.detect_lateral_movement()
    """

    def __init__(
        self,
        scan_window: float = 60.0,       # 扫描检测时间窗口(秒)
        protocol_jump_window: float = 300.0,  # 协议跳跃检测窗口
        min_targets_for_scan: int = 3,
        min_protocols_for_jump: int = 3,
    ):
        self.scan_window = scan_window
        self.protocol_jump_window = protocol_jump_window
        self.min_targets_for_scan = min_targets_for_scan
        self.min_protocols_for_jump = min_protocols_for_jump

        self._interactions: List[HostInteraction] = []
        # 索引: src_host → [interactions]
        self._by_src: Dict[str, List[HostInteraction]] = defaultdict(list)
        # 索引: (src, dst) → [interactions]
        self._by_pair: Dict[Tuple[str, str], List[HostInteraction]] = defaultdict(list)

    def ingest_interaction(self, event: HostInteraction):
        """摄入一次主机间交互事件。"""
        self._interactions.append(event)
        self._by_src[event.src_host].append(event)
        self._by_pair[(event.src_host, event.dst_host)].append(event)

    def detect_lateral_movement(
        self,
    ) -> List[LateralMovementPath]:
        """检测所有横向移动路径。"""
        _paths: List[LateralMovementPath] = []

        # 模式1: 扇出扫描——一个源对N个目标在时间窗口内执行扫描
        _scan_paths = self._detect_fan_out_scan()
        _paths.extend(_scan_paths)

        # 模式2: 协议跳跃——同一(src,dst)对短时间内使用多协议
        _jump_paths = self._detect_protocol_jumping()
        _paths.extend(_jump_paths)

        # 模式3: 凭证复用——同一用户在短时间内登录多台主机
        _cred_paths = self._detect_credential_reuse()
        _paths.extend(_cred_paths)

        # 去重+排序
        _paths = self._dedup_paths(_paths)
        _paths.sort(key=lambda p: p.risk_score, reverse=True)

        return _paths

    def reconstruct_lateral_graph(self) -> Dict[str, Any]:
        """重建横向移动图——节点=主机，边=观察到的横向移动。"""
        _nodes: Set[str] = set()
        _edges: List[Dict] = []

        for _ix in self._interactions:
            _nodes.add(_ix.src_host)
            _nodes.add(_ix.dst_host)
            _edges.append({
                "source": _ix.src_host, "target": _ix.dst_host,
                "protocol": _ix.protocol, "action": _ix.action.value,
                "timestamp": _ix.timestamp,
            })

        return {"nodes": sorted(_nodes), "edges": _edges}

    # 模式检测

    def _detect_fan_out_scan(self) -> List[LateralMovementPath]:
        """检测扇出扫描——1→N的扫描/登录。"""
        _paths: List[LateralMovementPath] = []

        for _src, _events in self._by_src.items():
            _events_sorted = sorted(_events, key=lambda e: e.timestamp)
            _windows = self._sliding_windows(_events_sorted, self.scan_window)

            for _win in _windows:
                if len(_win) < self.min_targets_for_scan:
                    continue

                _targets = set(e.dst_host for e in _win)
                _scan_actions = [
                    e for e in _win
                    if e.action in (ActionType.SCAN, ActionType.LOGIN_FAILURE)
                ]

                if len(_scan_actions) >= self.min_targets_for_scan:
                    _paths.append(LateralMovementPath(
                        path_hosts=[_src] + sorted(_targets),
                        protocols_used=list(set(e.protocol for e in _win)),
                        start_time=_win[0].timestamp,
                        end_time=_win[-1].timestamp,
                        interaction_count=len(_win),
                        credential_reuse_count=0,
                        risk_score=min(1.0, len(_targets) / 10.0 * 0.7),
                        is_automated=len(_targets) >= 5,
                    ))

        return _paths

    def _detect_protocol_jumping(self) -> List[LateralMovementPath]:
        """检测协议跳跃——同一对主机短时间内使用多协议。"""
        _paths: List[LateralMovementPath] = []

        for (_src, _dst), _events in self._by_pair.items():
            _events_sorted = sorted(_events, key=lambda e: e.timestamp)
            _windows = self._sliding_windows(_events_sorted, self.protocol_jump_window)

            for _win in _windows:
                _protocols = set(e.protocol for e in _win)
                _has_exec = any(e.action == ActionType.EXECUTE for e in _win)

                if len(_protocols) >= self.min_protocols_for_jump and _has_exec:
                    _paths.append(LateralMovementPath(
                        path_hosts=[_src, _dst],
                        protocols_used=sorted(_protocols),
                        start_time=_win[0].timestamp,
                        end_time=_win[-1].timestamp,
                        interaction_count=len(_win),
                        credential_reuse_count=0,
                        risk_score=0.5 + 0.2 * len(_protocols),
                        is_automated=False,
                    ))

        return _paths

    def _detect_credential_reuse(self) -> List[LateralMovementPath]:
        """检测凭证复用——同一用户登录多台不同主机。"""
        _by_user: Dict[str, List[HostInteraction]] = defaultdict(list)
        for _ix in self._interactions:
            if _ix.auth_user and _ix.action == ActionType.LOGIN_SUCCESS:
                _by_user[_ix.auth_user].append(_ix)

        _paths: List[LateralMovementPath] = []
        for _user, _events in _by_user.items():
            if len(_events) < 2:
                continue

            _targets = sorted(set(e.dst_host for e in _events))
            if len(_targets) >= 2:
                _paths.append(LateralMovementPath(
                    path_hosts=_targets,
                    protocols_used=list(set(e.protocol for e in _events)),
                    start_time=min(e.timestamp for e in _events),
                    end_time=max(e.timestamp for e in _events),
                    interaction_count=len(_events),
                    credential_reuse_count=len(_targets),
                    risk_score=min(1.0, 0.4 + len(_targets) * 0.15),
                    is_automated=len(_targets) >= 10,
                ))

        return _paths

    # 工具

    @staticmethod
    def _sliding_windows(
        events: List[HostInteraction], window: float,
    ) -> List[List[HostInteraction]]:
        """生成时间滑动窗口。"""
        if not events:
            return []
        _windows: List[List[HostInteraction]] = []
        for _i in range(len(events)):
            _win = [events[_i]]
            for _j in range(_i + 1, len(events)):
                if events[_j].timestamp - events[_i].timestamp <= window:
                    _win.append(events[_j])
                else:
                    break
            if len(_win) >= 2:
                _windows.append(_win)
        return _windows

    @staticmethod
    def _dedup_paths(
        paths: List[LateralMovementPath],
    ) -> List[LateralMovementPath]:
        """去重——保留每条路径的最高分版本。"""
        _seen: Dict[str, LateralMovementPath] = {}
        for _p in paths:
            _key = "→".join(_p.path_hosts)
            if _key not in _seen or _p.risk_score > _seen[_key].risk_score:
                _seen[_key] = _p
        return list(_seen.values())


# 冒烟测试
def _smoke_test():
    _detector = CrossProtocolLateralDetector(
        scan_window=120.0, protocol_jump_window=600.0,
    )

    _events = [
        # 扫描阶段：A扫描B,C,D
        HostInteraction("host_A", "host_B", "icmp", ActionType.SCAN, 0.0),
        HostInteraction("host_A", "host_C", "icmp", ActionType.SCAN, 2.0),
        HostInteraction("host_A", "host_D", "icmp", ActionType.SCAN, 4.0),
        # 协议跳跃：A→B使用SMB+RDP+WinRM
        HostInteraction("host_A", "host_B", "smb", ActionType.LOGIN_SUCCESS, 30.0, "admin"),
        HostInteraction("host_A", "host_B", "rdp", ActionType.LOGIN_SUCCESS, 45.0, "admin"),
        HostInteraction("host_A", "host_B", "winrm", ActionType.EXECUTE, 60.0, "admin"),
        # 凭证复用：admin登录多台主机
        HostInteraction("host_A", "host_C", "smb", ActionType.LOGIN_SUCCESS, 90.0, "admin"),
        HostInteraction("host_A", "host_D", "ssh", ActionType.LOGIN_SUCCESS, 120.0, "admin"),
    ]

    for _e in _events:
        _detector.ingest_interaction(_e)

    _paths = _detector.detect_lateral_movement()
    print(f"[lateral] detected {len(_paths)} lateral movement paths:")
    for _p in _paths:
        print(f"  hosts={'→'.join(_p.path_hosts)} protocols={_p.protocols_used} "
              f"risk={_p.risk_score:.3f} automated={_p.is_automated}")

    _graph = _detector.reconstruct_lateral_graph()
    print(f"[lateral] graph: {len(_graph['nodes'])} nodes, {len(_graph['edges'])} edges")

    assert len(_paths) >= 2, f"should detect at least 2 paths, got {len(_paths)}"
    print("[OK] CrossProtocolLateralDetector smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
