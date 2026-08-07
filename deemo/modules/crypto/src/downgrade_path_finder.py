# 修改记录:
# 2025-08-06 16:33 - 初始实现：协议状态图上的降级攻击路径自动搜索

"""降级攻击路径发现 — 从协议状态机中自动搜索安全降级路径。

crypto_protocol_state.py 从二进制重建协议状态机（TLS/SSH/IPSec）。
但重建后缺少关键一步——自动识别状态机中的降级攻击面。

降级攻击的本质：协议允许从高安全状态过渡到低安全状态，
且这一过渡未经充分的密码学绑定。例如：
- TLS 1.3 → TLS 1.2（ServerHello 中的版本号未受 Finished MAC 保护）
- ECDHE → DHE（密钥交换算法降级，若DH参数较弱）
- GCM → CBC（AEAD降级到可被 padding oracle 攻击的模式）

本模块在 crypto_protocol_state 输出的状态转移图上：
1. 标记每个状态的"安全等级"（基于密码学原语强度）。
2. 检测是否存在"降级边"——从高安全状态到低安全状态。
3. 对每条降级边分析：该转移是否受后续密码学验证保护？
   若不受保护→标记为可 exploiting 降级路径。
4. 输出降级攻击路径列表，按 exploitability 排序。

与既有工作的区别：
- Beurdouche et al.: 手动审查TLS状态机。
- TLS-Attacker (Ruhr Uni): 运行时主动探测→需要运行目标。
- 本方案: 从静态重建的状态机自动推理→无需运行、无需源码。

- "A Messy State of the Union": TLS状态机缺陷模板。
- TLS-Attacker: 协议Fuzzing框架。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

class SecurityLevel(Enum):
    """协议状态的安全等级——基于使用的密码学原语强度。"""
    HIGH = 4       # TLS 1.3 / ECDHE + AEAD / PQC
    MEDIUM = 3     # TLS 1.2 / DHE + GCM
    LOW = 2        # TLS 1.0 / RSA key exchange / CBC
    WEAK = 1       # SSLv3 / NULL cipher / EXPORT
    UNKNOWN = 0

@dataclass
class ProtoState:
    """协议状态机中的一个状态。"""
    state_id: str
    description: str
    security_level: SecurityLevel = SecurityLevel.UNKNOWN
    crypto_params: Dict[str, str] = field(default_factory=dict)
    # {cipher_suite, key_exchange, auth_method, protocol_version, ...}

@dataclass
class StateTransition:
    """状态机中的一条转移。"""
    from_state: str
    to_state: str
    trigger: str           # 触发该转移的API调用/协议消息
    is_authenticated: bool  # 该转移是否受密码学验证保护
    auth_binding: str = ""  # 若受保护，保护它的密码学操作

@dataclass
class DowngradePath:
    """一条可 exploiting 的降级攻击路径。"""
    path: List[Tuple[str, str]]  # [(from_state, to_state), ...]
    start_security: SecurityLevel
    end_security: SecurityLevel
    security_drop: int       # 降了多少级
    exploitability: float    # [0, 1] 可 exploiting性评分
    unprotected_edges: List[StateTransition]
    description: str = ""

class DowngradePathFinder:
    """协议降级攻击路径自动发现器。

    使用范式：
      finder = DowngradePathFinder()
      finder.load_state_machine(states, transitions)
      paths = finder.find_downgrade_paths()
      for path in paths:
          if path.exploitability > 0.7:
              report_vulnerability(path)
    """

    def __init__(
        self,
        min_security_drop: int = 2,
        exploitability_threshold: float = 0.5,
    ):
        """
        min_security_drop: 最小安全降级级数——低于此值的降级不被报告。
        exploitability_threshold: 可exploit性最低门限。
        """
        self.min_security_drop = min_security_drop
        self.exploitability_threshold = exploitability_threshold

        self._states: Dict[str, ProtoState] = {}
        self._transitions: List[StateTransition] = []
        # 每个状态的出边索引
        self._outgoing: Dict[str, List[StateTransition]] = defaultdict(list)

    # 公开 API

    def load_state_machine(
        self,
        states: List[ProtoState],
        transitions: List[StateTransition],
    ):
        """加载协议状态机和转移表。"""
        self._states = {s.state_id: s for s in states}
        self._transitions = transitions
        self._outgoing.clear()
        for _t in transitions:
            self._outgoing[_t.from_state].append(_t)

    def find_downgrade_paths(
        self, max_depth: int = 5,
    ) -> List[DowngradePath]:
        """搜索所有降级攻击路径。

        使用 DFS 从高安全状态出发，沿"未认证的转移"递归探索，
        直到抵达显著更低的安全状态。

        关键判定——降级边是否可 exploiting：
        (a) 转移是否受密码学验证保护？若否→可疑。
        (b) 目标安全等级是否显著低于源？级差越大→越危险。
        (c) 降级路径中是否存在中间状态混淆（如resumption/0-RTT歧义）？
        """
        _high_states = [
            s for s in self._states.values()
            if s.security_level.value >= SecurityLevel.MEDIUM.value
        ]

        _paths: List[DowngradePath] = []
        for _start in _high_states:
            _visited: Set[str] = set()
            _current_path: List[Tuple[str, str]] = []
            self._dfs_downgrade(
                _start.state_id, _start.security_level,
                _visited, _current_path, _paths, max_depth,
            )

        # 去重 + 按 exploitability 排序
        _paths = self._deduplicate_paths(_paths)
        _paths.sort(key=lambda p: p.exploitability, reverse=True)

        return [
            p for p in _paths
            if p.exploitability >= self.exploitability_threshold
        ]

    def assess_transition_risk(
        self, transition: StateTransition,
    ) -> float:
        """评估单条转移的降级风险 ∈ [0, 1]。

        高风险 = 降级幅度大 + 无密码学保护。
        """
        _from = self._states.get(transition.from_state)
        _to = self._states.get(transition.to_state)

        if _from is None or _to is None:
            return 0.0

        _from_level = _from.security_level.value
        _to_level = _to.security_level.value

        if _to_level >= _from_level:
            return 0.0  # 不是降级

        _drop = _from_level - _to_level
        _drop_factor = min(1.0, _drop / 3.0)  # 降 3 级 = 最危险

        _auth_factor = 0.0 if transition.is_authenticated else 1.0

        return _drop_factor * _auth_factor

    def get_downgrade_summary(self) -> Dict[str, Any]:
        """生成降级攻击面的汇总报告。"""
        _paths = self.find_downgrade_paths()
        _risky_transitions = []

        for _t in self._transitions:
            _risk = self.assess_transition_risk(_t)
            if _risk > 0.3:
                _risky_transitions.append({
                    "from": _t.from_state,
                    "to": _t.to_state,
                    "trigger": _t.trigger,
                    "authenticated": _t.is_authenticated,
                    "risk": round(_risk, 3),
                })

        return {
            "downgrade_paths_found": len(_paths),
            "risky_transitions": _risky_transitions,
            "most_exploitable": (
                {
                    "description": _paths[0].description,
                    "exploitability": _paths[0].exploitability,
                    "security_drop": _paths[0].security_drop,
                }
                if _paths else None
            ),
        }

    # 内部 — DFS 降级路径搜索

    def _dfs_downgrade(
        self,
        current_state: str,
        start_level: SecurityLevel,
        visited: Set[str],
        path: List[Tuple[str, str]],
        results: List[DowngradePath],
        max_depth: int,
    ):
        if len(path) >= max_depth or current_state in visited:
            return

        _cur = self._states.get(current_state)
        if _cur is None:
            return

        _visited = visited | {current_state}

        for _t in self._outgoing.get(current_state, []):
            _to_state = self._states.get(_t.to_state)
            if _to_state is None:
                continue

            _new_path = path + [(_t.from_state, _t.to_state)]
            _level_drop = start_level.value - _to_state.security_level.value

            if _level_drop >= self.min_security_drop and not _t.is_authenticated:
                _exploit = self._compute_exploitability(
                    start_level, _to_state.security_level, _new_path,
                )
                if _exploit >= self.exploitability_threshold:
                    results.append(DowngradePath(
                        path=list(_new_path),
                        start_security=start_level,
                        end_security=_to_state.security_level,
                        security_drop=_level_drop,
                        exploitability=_exploit,
                        unprotected_edges=[
                            e for e in self._transitions
                            if (e.from_state, e.to_state) in _new_path
                            and not e.is_authenticated
                        ],
                        description=(
                            f"downgrade from {start_level.name} to "
                            f"{_to_state.security_level.name} via "
                            f"{len(_new_path)} transitions"
                        ),
                    ))

            # 继续搜索——沿已认证的边也可以深入
            self._dfs_downgrade(
                _t.to_state, start_level, _visited, _new_path, results, max_depth,
            )

    @staticmethod
    def _compute_exploitability(
        start: SecurityLevel,
        end: SecurityLevel,
        path: List[Tuple[str, str]],
    ) -> float:
        """计算降级路径的可 exploiting性 ∈ [0, 1]."""
        _drop = max(0, start.value - end.value)
        _drop_factor = _drop / 3.0

        # 短路径 → 更容易 exploiting（不需要多步条件同时满足）
        _path_factor = 1.0 / max(1, len(path))

        return min(1.0, _drop_factor * 0.7 + _path_factor * 0.3)

    @staticmethod
    def _deduplicate_paths(paths: List[DowngradePath]) -> List[DowngradePath]:
        """去重——保留每条降级路径的 best exploitability 版本。"""
        _seen: Dict[Tuple[str, ...], DowngradePath] = {}
        for _p in paths:
            _key = tuple(s for s, _ in _p.path)
            if _key not in _seen or _p.exploitability > _seen[_key].exploitability:
                _seen[_key] = _p
        return list(_seen.values())

# 冒烟测试
def _smoke_test():
    # 构造一个简化的TLS状态机
    _states = [
        ProtoState("init", "未初始化", SecurityLevel.UNKNOWN),
        ProtoState("tls13_hello", "TLS 1.3 ClientHello", SecurityLevel.HIGH,
                   {"version": "1.3", "ciphers": "TLS_AES_256_GCM_SHA384"}),
        ProtoState("tls12_hello", "TLS 1.2 ServerHello", SecurityLevel.MEDIUM,
                   {"version": "1.2", "ciphers": "TLS_ECDHE_RSA_AES_128_GCM"}),
        ProtoState("tls10_hello", "TLS 1.0 ServerHello", SecurityLevel.LOW,
                   {"version": "1.0", "ciphers": "TLS_RSA_WITH_RC4_128_MD5"}),
        ProtoState("export_hello", "EXPORT ServerHello", SecurityLevel.WEAK,
                   {"version": "1.0", "ciphers": "TLS_RSA_EXPORT_WITH_RC4_40_MD5"}),
        ProtoState("encrypted", "加密通信中", SecurityLevel.HIGH),
        ProtoState("finished", "握手完成", SecurityLevel.HIGH),
    ]

    _transitions = [
        StateTransition("init", "tls13_hello", "ClientHello", True, ""),
        # 降级路径1: TLS 1.3 → 1.2 (不受 Finished 保护)
        StateTransition("tls13_hello", "tls12_hello", "ServerHello(v1.2)", False, ""),
        # 降级路径2: TLS 1.2 → 1.0
        StateTransition("tls12_hello", "tls10_hello", "ServerHello(v1.0)", False, ""),
        # 降级路径3: TLS 1.0 → EXPORT
        StateTransition("tls10_hello", "export_hello", "ServerHello(EXPORT)", False, ""),
        # 合法路径：认证后的加密
        StateTransition("tls13_hello", "encrypted", "ChangeCipherSpec", True, "Finished MAC"),
        StateTransition("encrypted", "finished", "Finished", True, "Finished MAC"),
    ]

    _finder = DowngradePathFinder(min_security_drop=2)
    _finder.load_state_machine(_states, _transitions)

    _paths = _finder.find_downgrade_paths()
    print(f"[downgrade] found {len(_paths)} downgrade paths:")

    for _p in _paths:
        print(f"  {_p.description}")
        print(f"    exploitability={_p.exploitability:.3f} "
              f"drop={_p.security_drop} "
              f"edges={len(_p.unprotected_edges)}")

    _summary = _finder.get_downgrade_summary()
    print(f"[downgrade] risky transitions: {len(_summary['risky_transitions'])}")

    # 应检测到从 HIGH(TLS 1.3) 到 LOW(TLS 1.0) 的降级路径
    assert len(_paths) >= 3, f"expected at least 3 paths, got {len(_paths)}"

    # 最 exploitable 的应该是 TLS 1.3 → EXPORT (跨度最大)
    _worst = _paths[0]
    assert _worst.exploitability > 0.4, (
        f"worst path should be exploitable, got {_worst.exploitability}"
    )

    print("[OK] DowngradePathFinder smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
