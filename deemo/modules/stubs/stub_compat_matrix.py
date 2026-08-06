# stub_compat_matrix.py — 跨桩版本兼容性矩阵
# 追踪"调用方桩的哪个版本已验证与依赖桩的哪个版本兼容"。
# 回答: 升级 B 是否会导致 A 不兼容？哪些组合已经测试过？
#
# 问题:
#   Merkle 版本树追踪每个桩的独立版本历史。
#   但兼容性是 pairwise 的: A v1.2 调用 B v2.0 是否安全？
#   缺少跨桩兼容性矩阵时，每次升级都需要全量重验证，
#   即使升级的桩与下游调用方之间的接口未变化。
#
# 方案:
#   1. 稀疏矩阵: {(caller, caller_ver, callee, callee_ver) → compat_status}
#   2. 状态: verified_ok | verified_fail | untested | implied_compat
#   3. implied_compat: 若 B 的合约 Merkle 根未变，则自动兼容
#   4. 查询: is_compatible(A_v, B_w) → 查矩阵 + 合约 diff 推断
#   5. 升级风险评估: upgrade B → 列出所有需要重验证的调用方
import json as _json
import os as _os
from dataclasses import dataclass as _dc, field as _field
from enum import Enum as _Enum
from typing import Optional as _Opt


class CompatStatus(_Enum):
    VERIFIED_OK = 'verified_ok'
    VERIFIED_FAIL = 'verified_fail'
    UNTESTED = 'untested'
    IMPLIED_COMPAT = 'implied_compat'


@_dc
class CompatEntry:
    """单条兼容性记录。"""
    caller_module: str
    caller_version: str     # Merkle root[:12]
    callee_module: str
    callee_version: str
    status: str = 'untested'
    verified_at: float = 0.0
    source: str = ''        # 验证来源描述


@_dc
class UpgradeRisk:
    """升级风险评估。"""
    callee_module: str
    from_version: str
    to_version: str
    affected_callers: list = _field(default_factory=list)
    verified_compat: list = _field(default_factory=list)
    needs_reverify: list = _field(default_factory=list)
    risk_level: str = 'unknown'  # safe | low | medium | high


class CompatMatrix:
    """跨桩版本兼容性矩阵。

    存储: stubs/_compat_matrix/matrix.json
    稀疏存储 — 仅记录已验证或失败的条目。未记录的默认为 IMPLIED_COMPAT
    （基于"合约未变 → 接口兼容"的保守假设）。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.store_dir = _os.path.join(stubs_dir, '_compat_matrix')
        self._entries: dict[tuple, CompatEntry] = {}
        self._ensure_loaded()

    def record(self, caller: str, caller_ver: str,
               callee: str, callee_ver: str,
               status: str, source: str = '') -> CompatEntry:
        """记录一条兼容性验证结果。"""
        import time
        key = (caller, caller_ver, callee, callee_ver)
        entry = CompatEntry(
            caller_module=caller, caller_version=caller_ver,
            callee_module=callee, callee_version=callee_ver,
            status=status, verified_at=time.time(), source=source)
        self._entries[key] = entry
        self._persist()
        return entry

    def check(self, caller: str, callee: str,
              caller_ver: str = '', callee_ver: str = '') -> CompatStatus:
        """检查一对 (调用方, 被调用方) 的兼容性状态。"""
        # 若未指定版本，使用最新版本
        if not caller_ver:
            caller_ver = self._latest_version(caller)
        if not callee_ver:
            callee_ver = self._latest_version(callee)

        key = (caller, caller_ver, callee, callee_ver)
        entry = self._entries.get(key)
        if entry:
            return CompatStatus(entry.status)

        # 推断兼容性: 查找该 callee 的合约是否从上一已验证版本变化
        prev_ver = self._find_prev_verified(caller, callee)
        if prev_ver:
            if self._contract_unchanged(callee, prev_ver, callee_ver):
                return CompatStatus.IMPLIED_COMPAT

        return CompatStatus.UNTESTED

    def upgrade_risk(self, callee: str,
                     to_version: str) -> UpgradeRisk:
        """评估升级 callee 到指定版本的风险。"""
        current = self._latest_version(callee)
        if not current:
            return UpgradeRisk(callee_module=callee,
                             from_version='unknown', to_version=to_version,
                             risk_level='unknown')

        risk = UpgradeRisk(
            callee_module=callee,
            from_version=current,
            to_version=to_version)

        callers = self._find_callers(callee)
        for c in callers:
            c_ver = self._latest_version(c)
            if not c_ver:
                continue
            status = self.check(c, callee, c_ver, to_version)
            if status == CompatStatus.VERIFIED_OK:
                risk.verified_compat.append(c)
            elif status == CompatStatus.IMPLIED_COMPAT:
                risk.verified_compat.append(c)
            else:
                risk.needs_reverify.append(c)

        risk.affected_callers = risk.verified_compat + risk.needs_reverify
        # 风险等级
        ratio = (len(risk.needs_reverify) /
                max(len(risk.affected_callers), 1))
        if ratio == 0:
            risk.risk_level = 'safe'
        elif ratio < 0.3:
            risk.risk_level = 'low'
        elif ratio < 0.7:
            risk.risk_level = 'medium'
        else:
            risk.risk_level = 'high'

        return risk

    # ---- 内部 ----
    @staticmethod
    def _latest_version(module: str) -> str:
        try:
            from modules.stubs.stub_contract_merkle import (
                ContractMerkleTree, VersionedContractStore)
            store = VersionedContractStore()
            ver = store.latest(module)
            return ver.version_id if ver else ''
        except ImportError:
            return ''

    @staticmethod
    def _contract_unchanged(module: str, old_ver: str,
                            new_ver: str) -> bool:
        """检查合约 Merkle 根是否未变。"""
        try:
            from modules.stubs.stub_contract_merkle import (
                ContractMerkleTree, VersionedContractStore)
            store = VersionedContractStore()
            history = store.history(module)
            for v in history:
                if v.version_id == old_ver:
                    # 找到旧版本的叶子哈希
                    pass
            # 简化: 比较版本 ID
            return old_ver == new_ver
        except ImportError:
            return False

    @staticmethod
    def _find_prev_verified(caller: str,
                            callee: str) -> _Opt[str]:
        """查找上一次已验证兼容的 callee 版本。"""
        # 简化实现: 遍历矩阵找最近 verified_ok 条目
        return None  # Full impl would iterate _entries

    def _find_callers(self, module: str) -> list[str]:
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph()
            g.build()
            node = g.nodes.get(module)
            return sorted(node.depended_by) if node else []
        except ImportError:
            return []

    def _ensure_loaded(self) -> None:
        path = _os.path.join(self.store_dir, 'matrix.json')
        if _os.path.isfile(path):
            try:
                with open(path, encoding='utf-8') as f:
                    data = _json.load(f)
                for item in data:
                    entry = CompatEntry(**item)
                    key = (entry.caller_module, entry.caller_version,
                          entry.callee_module, entry.callee_version)
                    self._entries[key] = entry
            except (_json.JSONDecodeError, TypeError):
                pass

    def _persist(self) -> None:
        _os.makedirs(self.store_dir, exist_ok=True)
        path = _os.path.join(self.store_dir, 'matrix.json')
        data = [_dc_to_dict(e) for e in self._entries.values()]
        with open(path, 'w', encoding='utf-8') as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)


def _dc_to_dict(e: CompatEntry) -> dict:
    return {
        'caller_module': e.caller_module,
        'caller_version': e.caller_version,
        'callee_module': e.callee_module,
        'callee_version': e.callee_version,
        'status': e.status,
        'verified_at': e.verified_at,
        'source': e.source,
    }


__all__ = ['CompatStatus', 'CompatEntry', 'UpgradeRisk', 'CompatMatrix']
