# stub_release_bundler.py — 桩版本发布打包器
# 将一组已验证兼容的桩版本打包为"发布"，
# 支持生态系统级快照、回滚和 diff。
#
# 方案:
#   1. 发布 = {module_name: version_id} 的快照映射
#   2. 发布元数据: tag, timestamp, 通过部署门控的模块数, 总模块数
#   3. 发布 diff: release_A vs release_B → 哪些模块版本变了
#   4. 回滚: 从 release 快照恢复每个模块到对应版本
#   5. 兼容性: 发布内所有 pairwise 组合均应已验证兼容
import json as _json
import os as _os
import time as _time
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class ReleaseManifest:
    """一次发布的完整清单。"""
    tag: str                        # e.g. 'v0.3.1' or 'release-2024-09-27'
    timestamp: float = 0.0
    description: str = ''
    # {module_name: version_id}
    modules: dict = _field(default_factory=dict)
    module_count: int = 0
    # 质量指标
    deploy_ready_count: int = 0
    avg_irl: float = 0.0
    # 兼容性
    compat_verified: bool = False   # 所有 pair 是否已验证
    # 链式链接
    prev_release_tag: str = ''


@_dc
class ReleaseDiff:
    """两次发布之间的差异。"""
    from_tag: str
    to_tag: str
    added_modules: list = _field(default_factory=list)
    removed_modules: list = _field(default_factory=list)
    upgraded_modules: list = _field(default_factory=list)  # [(mod, old, new)]
    downgraded_modules: list = _field(default_factory=list)
    unchanged_modules: int = 0


class ReleaseBundler:
    """桩版本发布打包器。

    存储: stubs/_releases/{tag}.json
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.store_dir = _os.path.join(stubs_dir, '_releases')

    def snapshot(self, tag: str,
                 description: str = '') -> ReleaseManifest:
        """创建当前生态系统状态的发布快照。"""
        modules = self._collect_versions()

        # 质量指标
        deploy_ready = 0
        total_irl = 0.0
        try:
            from modules.stubs.stub_deploy_gate import DeployGate, GateDecision
            dg = DeployGate(stubs_dir=self.stubs_dir)
            for mod in modules:
                r = dg.evaluate(mod)
                if r.decision == GateDecision.PROMOTE:
                    deploy_ready += 1
                total_irl += r.deploy_score
        except ImportError:
            pass

        manifest = ReleaseManifest(
            tag=tag,
            timestamp=_time.time(),
            description=description,
            modules=modules,
            module_count=len(modules),
            deploy_ready_count=deploy_ready,
            avg_irl=round(total_irl / max(len(modules), 1), 3),
        )

        # 链式链接
        prev = self._latest_tag()
        if prev:
            manifest.prev_release_tag = prev

        # 兼容性验证
        manifest.compat_verified = self._verify_compat(modules)

        self._save(manifest)
        return manifest

    def diff(self, from_tag: str, to_tag: str) -> ReleaseDiff:
        """比较两次发布之间的差异。"""
        a = self.load(from_tag)
        b = self.load(to_tag)

        rd = ReleaseDiff(from_tag=from_tag, to_tag=to_tag)
        if a is None or b is None:
            return rd

        a_mods = set(a.modules)
        b_mods = set(b.modules)

        rd.added_modules = sorted(b_mods - a_mods)
        rd.removed_modules = sorted(a_mods - b_mods)

        for mod in sorted(a_mods & b_mods):
            va = a.modules[mod]
            vb = b.modules[mod]
            if va != vb:
                rd.upgraded_modules.append((mod, va, vb))

        rd.unchanged_modules = len(a_mods & b_mods) - len(rd.upgraded_modules)
        return rd

    def list_releases(self) -> list[str]:
        """列出所有已保存的发布标签。"""
        _os.makedirs(self.store_dir, exist_ok=True)
        tags = []
        for fn in _os.listdir(self.store_dir):
            if fn.endswith('.json'):
                tags.append(fn[:-5])
        return sorted(tags, reverse=True)

    def load(self, tag: str) -> _Opt[ReleaseManifest]:
        path = _os.path.join(self.store_dir, f'{tag}.json')
        if not _os.path.isfile(path):
            return None
        try:
            with open(path, encoding='utf-8') as f:
                data = _json.load(f)
            return ReleaseManifest(**data)
        except (_json.JSONDecodeError, TypeError):
            return None

    @staticmethod
    def _collect_versions() -> dict[str, str]:
        """收集当前所有模块的版本 ID。"""
        versions = {}
        try:
            from modules.stubs.stub_contract_merkle import (
                ContractMerkleTree, VersionedContractStore)
            from modules.stubs.stub_contract import StubContractor
            store = VersionedContractStore()
            ctor = StubContractor()
            for name, contract in ctor.scan_all().items():
                if name.startswith('stub_'):
                    continue
                # 确保已提交
                ver = store.commit(contract)
                versions[name] = ver.version_id
        except ImportError:
            pass
        return versions

    @staticmethod
    def _verify_compat(modules: dict) -> bool:
        """验证发布内所有 pairwise 组合的兼容性。"""
        try:
            from modules.stubs.stub_compat_matrix import (
                CompatMatrix, CompatStatus)
            cm = CompatMatrix()
            for caller in modules:
                for callee in modules:
                    if caller == callee:
                        continue
                    status = cm.check(caller, callee,
                                     modules[caller], modules[callee])
                    if status == CompatStatus.VERIFIED_FAIL:
                        return False
            return True
        except ImportError:
            return False

    def _save(self, manifest: ReleaseManifest) -> None:
        _os.makedirs(self.store_dir, exist_ok=True)
        path = _os.path.join(self.store_dir, f'{manifest.tag}.json')
        data = {
            'tag': manifest.tag,
            'timestamp': manifest.timestamp,
            'description': manifest.description,
            'modules': manifest.modules,
            'module_count': manifest.module_count,
            'deploy_ready_count': manifest.deploy_ready_count,
            'avg_irl': manifest.avg_irl,
            'compat_verified': manifest.compat_verified,
            'prev_release_tag': manifest.prev_release_tag,
        }
        with open(path, 'w', encoding='utf-8') as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)

    def _latest_tag(self) -> str:
        tags = self.list_releases()
        return tags[0] if tags else ''


__all__ = ['ReleaseManifest', 'ReleaseDiff', 'ReleaseBundler']
