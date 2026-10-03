# coding: utf-8
"""
上下文版本化 — 为钩子管道提供写时复制 (CoW) 的上下文快照与版本溯源.

设计目标:
  1. 每次钩子执行前后的 context 可被版本化, 形成内容寻址快照
  2. 相邻版本间仅存储键级增量, 降低 O(n) 全量拷贝的空间开销
  3. 版本 ID 由 SHA-256 派生, 天然防篡改, 满足审计链的完整性要求

不用 git 对象模型: git 以文件为粒度, 本模块以 dict 键为粒度做增量 —
  context 通常含数十键, 单次执行仅触碰其中 2~5 个, 键级增量把存储开销
  从 O(N*K) 降至 O(N*d) (d << K).

与 provenance_tracker 的关系:
  ContextVersionStore 是存储层, ProvenanceGraph 是关系层 —
  前者回答 "某个版本长什么样", 后者回答 "版本之间如何演化而来".
"""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# 版本间存储的键级增量: prev_version → (changed_keys, key_value_map)
_DeltaEntry = Tuple[Optional[str], Tuple[str, ...], Dict[str, Any]]

# 哨兵: 标记键在旧版本中不存在, 逆向重建时应删除
class _KeyWasAbsent:
    """prev_vals 中的哨兵值 — 表示该键在上一个版本中不存在."""
    __slots__ = ()
    def __repr__(self): return '<absent>'


_KEY_WAS_ABSENT = _KeyWasAbsent()


class ContextVersion:
    """内容寻址的上下文版本标识符.

    version_id 由 (parent_version_id, changed_keys_sorted, value_hashes) 联合哈希生成,
    任一字段变化即产生新版本, 保证版本的不可变性.
    """

    __slots__ = ('version_id', 'parent_id', 'timestamp', 'changed_keys', 'hook_name')

    def __init__(
        self, version_id: str, parent_id: Optional[str] = None,
        changed_keys: Tuple[str, ...] = (), hook_name: str = '',
    ):
        self.version_id = version_id
        self.parent_id = parent_id
        self.timestamp = time.time()
        self.changed_keys = changed_keys
        self.hook_name = hook_name

    def __repr__(self) -> str:
        return (f'ContextVersion(id={self.version_id[:10]}.., '
                f'parent={self.parent_id[:10] if self.parent_id else None}.., '
                f'changed={list(self.changed_keys)})')


def _stable_hash(obj: Any) -> str:
    """对任意 JSON 可序列化对象产生确定性 SHA-256 摘要.

    排序键保证 dict 的序列化确定性; 对不可序列化对象回退到 repr().
    这不是密码学用途的哈希 — 速度优先于抗碰撞.
    """
    try:
        raw = json.dumps(obj, sort_keys=True, default=repr).encode('utf-8')
    except (TypeError, ValueError):
        raw = repr(obj).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _key_hash(key: str, value: Any) -> str:
    """单键值的稳定哈希, 用于增量比较."""
    return _stable_hash({key: value})


class ContextVersionStore:
    """键级增量的上下文版本仓库.

    空间策略:
      - root (首个版本): 全量存储键值对
      - 后续版本: 仅存储变更键的旧值 (用于回滚) 与新值
      - 版本间通过 parent 链回溯重建任意历史版本
      - 线性链上的最新版本保持全量缓存以避免回溯开销

    典型用例:
      store = ContextVersionStore()
      v0 = store.commit(context, hook_name='init')
      context['result'] = 42
      v1 = store.commit(context, parent=v0, hook_name='analyze')
      old = store.reconstruct(v0)  # 回溯到 v0
    """

    def __init__(self, max_undo_depth: int = 64):
        self._versions: Dict[str, ContextVersion] = {}
        self._full_snapshot: Optional[Dict[str, Any]] = None  # 最新版本的全量缓存
        self._latest_id: Optional[str] = None
        self._deltas: Dict[str, _DeltaEntry] = {}  # version_id → delta
        self._root_id: Optional[str] = None
        self._max_undo = max_undo_depth  # 保留的版本栈深度, 超出部分做压缩

    def commit(
        self, context: Dict[str, Any],
        parent: Optional['ContextVersion'] = None,
        hook_name: str = '',
    ) -> ContextVersion:
        """将当前 context 提交为一个新版本.

        若提供 parent, 计算 parent 到当前 context 的增量;
        否则作为根版本 (root), 全量存储.
        """
        parent_id = parent.version_id if parent else None
        changed: List[str] = []
        prev_vals: Dict[str, Any] = {}

        if parent is not None and self._full_snapshot is not None:
            # 对照最新全量缓存计算差量
            for k in set(self._full_snapshot) | set(context):
                old = self._full_snapshot.get(k)
                new = context.get(k)
                if _key_hash(k, old) != _key_hash(k, new):
                    changed.append(k)
                    if k in self._full_snapshot:
                        prev_vals[k] = old  # 键值被修改, 记录旧值
                    else:
                        prev_vals[k] = _KEY_WAS_ABSENT  # 新键, 逆向时需删除
        else:
            changed = list(context.keys())

        changed_t = tuple(sorted(changed))

        # 构建版本 ID: 将父版本、变更键集、变更值哈希合并
        payload = {
            'parent': parent_id or '',
            'keys': changed_t,
            'values': {k: _stable_hash(context.get(k)) for k in changed_t},
        }
        version_id = _stable_hash(payload)

        version = ContextVersion(
            version_id=version_id, parent_id=parent_id,
            changed_keys=changed_t, hook_name=hook_name,
        )

        self._versions[version_id] = version
        self._deltas[version_id] = (parent_id, changed_t, dict(prev_vals))
        self._full_snapshot = dict(context)
        self._latest_id = version_id
        if self._root_id is None:
            self._root_id = version_id

        self._compact_if_needed()
        return version

    def reconstruct(self, version: ContextVersion) -> Dict[str, Any]:
        """沿 parent 链回溯, 重建任意历史版本.

        从最新全量快照出发, 沿 parent 链逆向施加增量旧值,
        直到抵达目标版本. 时间复杂度 O(depth_diff).
        """
        if version.version_id == self._latest_id:
            return dict(self._full_snapshot) if self._full_snapshot else {}

        chain: List[_DeltaEntry] = []
        cur = self._latest_id
        while cur is not None and cur != version.version_id:
            delta = self._deltas.get(cur)
            if delta is None:
                break
            chain.append(delta)
            cur = delta[0]

        if cur != version.version_id and version.version_id not in self._versions:
            raise KeyError(f'版本 {version.version_id[:12]} 不在存储中')

        result = dict(self._full_snapshot) if self._full_snapshot else {}
        for _, _, old_vals in chain:
            for k, v in old_vals.items():
                if v is _KEY_WAS_ABSENT:
                    # 该键在当前版本新增, 回溯到旧版本时应移除
                    result.pop(k, None)
                elif v is not None:
                    result[k] = v
                elif k in result:
                    del result[k]
        return result

    def diff(
        self, v1: ContextVersion, v2: ContextVersion,
    ) -> Dict[str, Tuple[Any, Any]]:
        """返回两个版本之间的键级差异 {key: (v1_val, v2_val)}."""
        ctx1 = self.reconstruct(v1) if v1.version_id != self._latest_id else dict(self._full_snapshot or {})
        ctx2 = self.reconstruct(v2) if v2.version_id != self._latest_id else dict(self._full_snapshot or {})

        all_keys = set(ctx1) | set(ctx2)
        diffs = {}
        for k in all_keys:
            a, b = ctx1.get(k), ctx2.get(k)
            if _key_hash(k, a) != _key_hash(k, b):
                diffs[k] = (a, b)
        return diffs

    def get_version(self, version_id: str) -> Optional[ContextVersion]:
        return self._versions.get(version_id)

    def latest(self) -> Optional[ContextVersion]:
        if self._latest_id:
            return self._versions.get(self._latest_id)
        return None

    def root(self) -> Optional[ContextVersion]:
        if self._root_id:
            return self._versions.get(self._root_id)
        return None

    @property
    def version_count(self) -> int:
        return len(self._versions)

    def _compact_if_needed(self):
        """版本栈超过 max_undo_depth 时, 将最老版本做全量快照压缩.

        压缩策略: 选 root 的直接后继作为新的 root, 存储其全量上下文,
        丢弃其与旧 root 间的增量, 保持 undo 深度在可控范围内.
        """
        if len(self._versions) <= self._max_undo:
            return
        # 新 root 取版本列表中第 len - max_undo 个
        sorted_ids = list(self._versions.keys())
        # 版本以 commit 顺序追加, 取超出部分的下一个作为新 root
        excess = len(sorted_ids) - self._max_undo
        if excess <= 0:
            return
        new_root_id = sorted_ids[excess]
        old_root_id = self._root_id
        if new_root_id == old_root_id:
            return
        # 重建新 root 的全量上下文, 写入 _deltas 作为新的根增量
        new_root_ver = self._versions[new_root_id]
        full_ctx = self.reconstruct(new_root_ver)
        self._deltas[new_root_id] = (None, tuple(sorted(full_ctx.keys())), {})
        # 清理旧 root → 新 root 之间的版本
        for vid in sorted_ids[:excess]:
            self._deltas.pop(vid, None)
            self._versions.pop(vid, None)
        self._root_id = new_root_id
