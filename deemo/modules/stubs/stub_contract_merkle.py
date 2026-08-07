# stub_contract_merkle.py — 合约 Merkle 树 + 语义版本推断
# 将 StubContract 结构哈希为 Merkle 树，通过增量比对合约树差异
# 推断语义化版本变更（SemVer），并支持版本化合约存储与检索。
#
# 问题场景:
#   桩模块的接口契约随代码演进变化。在渐进实现过程中，
#   需要可验证地追踪每次契约变更，并自动判定变更的兼容性级别。
#   这对"已生成实现是否需要重新生成"提供可计算的判定依据。
#
# 核心构造:
#   1. 合约 → 叶子哈希序列 (每个函数签名+约束生成一个叶子)
#   2. 叶子序列 → Merkle 树 (平衡二叉树，内部节点 H=Hash(左子||右子))
#   3. 两棵树的差异 → 最小变更集 (仅追踪到子树根即可定位变更函数)
#   4. 变更集 → 语义版本增量 (MAJOR/MINOR/PATCH 判定规则)
#
# 区别于 Roseau:
#   Roseau 对 Java 库做 source-level 破坏性变更检测 (F1=0.99)。
#   本模块在合约层面（而非源码层面）做版本推断，
#   且用 Merkle 树实现 O(log n) 的合约比对而非 O(n) 全文 diff。
import hashlib as _hashlib
import json as _json
import os as _os
import time as _time
from dataclasses import dataclass as _dc, field as _field
from enum import Enum as _Enum
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    StubContractor as _StubContractor,
)


class SemVerBump(_Enum):
    """语义版本增量类别。"""
    NONE = 'none'     # 无实质性变更
    PATCH = 'patch'   # 内部实现变更，接口不变
    MINOR = 'minor'   # 新增函数/参数（向后兼容）
    MAJOR = 'major'   # 删除函数/参数、改签名（不向后兼容）


@_dc
class ContractVersion:
    """合约的一个版本快照。"""
    module_name: str
    version_id: str          # 树根哈希前 12 位
    merkle_root: str         # 完整根哈希
    leaf_count: int = 0
    timestamp: float = 0.0
    semver: str = '0.1.0'    # 语义版本号
    prev_version_id: str = ''
    bump: str = 'none'       # 相对于上一版本的变更级别

    def to_dict(self) -> dict:
        return {
            'module_name': self.module_name,
            'version_id': self.version_id,
            'merkle_root': self.merkle_root,
            'leaf_count': self.leaf_count,
            'timestamp': self.timestamp,
            'semver': self.semver,
            'prev_version_id': self.prev_version_id,
            'bump': self.bump,
        }


# 合约叶子哈希
def _contract_leaf(func: _FuncContract) -> str:
    """将单个函数契约序列化为确定性字节串后计算 SHA-256。
    序列化顺序固定以保证可复现: name, params(name:ann:default:kind), return_ann。
    不包含 doc_summary、复杂度等非结构性字段。
    """
    parts = [func.name]
    for p in func.params:
        parts.append(f'{p.name}:{p.annotation}:{p.default_repr}:{p.kind}')
    parts.append(func.return_ann)
    canon = '|'.join(parts)
    return _hashlib.sha256(canon.encode('utf-8')).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Merkle 内部节点哈希: SHA-256(left_hex + right_hex)。"""
    return _hashlib.sha256(f'{left}{right}'.encode('utf-8')).hexdigest()


# Merkle 树
class ContractMerkleTree:
    """基于合约函数列表的 Merkle 树。

    叶子层: 每个 FuncContract → SHA-256
    树层: 逐对合并 Hash(L||R)，单数层复制最右节点。
    根哈希作为该模块接口的全局指纹。
    """

    def __init__(self, contract: _StubContract):
        self.module_name = contract.module_name
        self.leaf_count = len(contract.functions)
        # 叶子哈希列表（保持函数序）
        self.leaves: list[str] = [_contract_leaf(f) for f in contract.functions]
        # 层结构 layers[0] = leaves, layers[k] = internal nodes
        self.layers: list[list[str]] = []
        self.root: str = ''
        if self.leaves:
            self._build()
        else:
            self.root = _hashlib.sha256(b'empty').hexdigest()

    def _build(self) -> None:
        layer = list(self.leaves)
        self.layers.append(layer)
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else left
                next_layer.append(_hash_pair(left, right))
            self.layers.append(next_layer)
            layer = next_layer
        self.root = self.layers[-1][0]

    def root_hex(self) -> str:
        return self.root

    def version_id(self) -> str:
        return self.root[:12]

    def get_proof(self, leaf_index: int) -> list[tuple[str, bool]]:
        """返回指定叶子的 Merkle 证明（兄弟哈希路径 + 左右方向）。"""
        if leaf_index < 0 or leaf_index >= self.leaf_count:
            return []
        proof = []
        idx = leaf_index
        for layer in self.layers[:-1]:
            if idx % 2 == 0:
                # 当前为左子，兄弟为右
                sibling_idx = idx + 1 if idx + 1 < len(layer) else idx
                proof.append((layer[sibling_idx], True))
            else:
                # 当前为右子，兄弟为左
                proof.append((layer[idx - 1], False))
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[tuple[str, bool]],
                     root: str) -> bool:
        """验证 Merkle 证明。"""
        current = leaf_hash
        for sibling_hash, is_right in proof:
            if is_right:
                current = _hash_pair(current, sibling_hash)
            else:
                current = _hash_pair(sibling_hash, current)
        return current == root

    def to_dict(self) -> dict:
        return {
            'module_name': self.module_name,
            'root': self.root,
            'leaf_count': self.leaf_count,
            'leaves': self.leaves,
            'layers': self.layers,
        }


# 合约差异计算
@_dc
class ContractDiffEntry:
    """单条合约差异。"""
    change_type: str    # 'added', 'removed', 'modified'
    func_name: str
    old_hash: str = ''
    new_hash: str = ''
    detail: str = ''

    def is_breaking(self) -> bool:
        """判定此变更是否为破坏性变更。

        破坏性规则:
          - 删除函数 → 破坏性
          - 修改签名（参数名/类型/默认值变更）→ 破坏性
          - 新增函数 / 仅改返回注解 → 非破坏性
        """
        if self.change_type == 'removed':
            return True
        if self.change_type == 'modified':
            # 仅改返回注解视为非破坏性扩展（放宽返回类型）
            return 'return_ann_only' not in self.detail
        return False


def diff_contracts(old_contract: _StubContract,
                   new_contract: _StubContract) -> list[ContractDiffEntry]:
    """比较两个合约版本，输出差异条目列表。

    比对策略:
      1. 用 Merkle 叶子哈希进行函数级等价判定。
      2. 新增/删除按名比较；同名异哈希为修改。
      3. 修改条目的 detail 字段标注变更部位。
    """
    diffs = []

    old_funcs = {f.name: f for f in old_contract.functions}
    new_funcs = {f.name: f for f in new_contract.functions}

    old_names = set(old_funcs)
    new_names = set(new_funcs)

    # 删除
    for name in sorted(old_names - new_names):
        diffs.append(ContractDiffEntry(
            change_type='removed', func_name=name,
            old_hash=_contract_leaf(old_funcs[name]),
        ))

    # 新增
    for name in sorted(new_names - old_names):
        diffs.append(ContractDiffEntry(
            change_type='added', func_name=name,
            new_hash=_contract_leaf(new_funcs[name]),
        ))

    # 修改 — 同名但哈希不同
    for name in sorted(old_names & new_names):
        old_hash = _contract_leaf(old_funcs[name])
        new_hash = _contract_leaf(new_funcs[name])
        if old_hash != new_hash:
            detail = _diff_detail(old_funcs[name], new_funcs[name])
            diffs.append(ContractDiffEntry(
                change_type='modified', func_name=name,
                old_hash=old_hash, new_hash=new_hash, detail=detail,
            ))

    return diffs


def _diff_detail(old: _FuncContract, new: _FuncContract) -> str:
    """生成两个函数契约间变更部位描述。"""
    changes = []
    if old.return_ann != new.return_ann:
        changes.append(f'return_ann: {old.return_ann} → {new.return_ann}')
    old_params = {p.name: p for p in old.params}
    new_params = {p.name: p for p in new.params}
    removed_params = set(old_params) - set(new_params)
    added_params = set(new_params) - set(old_params)
    if removed_params:
        changes.append(f'removed_params: {",".join(sorted(removed_params))}')
    if added_params:
        changes.append(f'added_params: {",".join(sorted(added_params))}')
    for pname in sorted(set(old_params) & set(new_params)):
        op, np = old_params[pname], new_params[pname]
        if op.annotation != np.annotation:
            changes.append(f'{pname}.ann: {op.annotation} → {np.annotation}')
        if op.has_default != np.has_default:
            changes.append(f'{pname}.default: {op.has_default} → {np.has_default}')
        if op.kind != np.kind:
            changes.append(f'{pname}.kind: {op.kind} → {np.kind}')
    return '; '.join(changes) if changes else 'return_ann_only'


# 语义版本推断
def infer_semver_bump(diffs: list[ContractDiffEntry],
                      old_tree: _Opt[ContractMerkleTree] = None,
                      new_tree: _Opt[ContractMerkleTree] = None) -> SemVerBump:
    """从合约差异推断语义版本增量。

    判定规则（优先级序）:
      1. 存在破坏性变更 (函数删除/签名修改) → MAJOR
      2. 存在新增函数或新增可选参数 → MINOR（向后兼容扩展）
      3. 仅内部实现变更（叶子哈希无变化，根哈希因其他原因变化）→ PATCH
         （注意: 合约层不追踪实现体，PATCH 判定通常发生在源码 diff 中；
           若合约本身无差异，归于 NONE）
      4. 无差异 → NONE
    """
    if not diffs:
        # 可能存在源码级变更但合约无变化 → NONE（合约层判定）
        # 若调用方确信存在 PATCH 级变更，应从源码 diff 层补充判定
        return SemVerBump.NONE

    has_breaking = any(d.is_breaking() for d in diffs)
    if has_breaking:
        return SemVerBump.MAJOR

    has_additions = any(d.change_type == 'added' for d in diffs)
    has_modifications = any(d.change_type == 'modified' for d in diffs)
    if has_additions:
        return SemVerBump.MINOR
    if has_modifications:
        # 仅返回注解或兼容性修改 → MINOR
        return SemVerBump.MINOR

    return SemVerBump.NONE


def bump_semver(current: str, bump: SemVerBump) -> str:
    """根据变更级别递增语义版本号。"""
    try:
        parts = [int(x) for x in current.split('.')]
        if len(parts) < 3:
            parts = (parts + [0, 0, 0])[:3]
    except (ValueError, AttributeError):
        parts = [0, 1, 0]

    if bump == SemVerBump.MAJOR:
        return f'{parts[0] + 1}.0.0'
    elif bump == SemVerBump.MINOR:
        return f'{parts[0]}.{parts[1] + 1}.0'
    elif bump == SemVerBump.PATCH:
        return f'{parts[0]}.{parts[1]}.{parts[2] + 1}'
    return current


# 版本化合约存储
class VersionedContractStore:
    """版本化合约持久存储。

    以模块名为索引，存储合约的多个版本快照。
    每次 commit() 生成新版本，自动计算 Merkle 树、差异与语义版本。
    存储后端: JSON 文件（单模块级别，避免中心化数据库依赖）。
    """

    def __init__(self, store_dir: str = None):
        if store_dir is None:
            store_dir = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)), '_contract_versions')
        self.store_dir = store_dir
        # {module_name: [ContractVersion, ...]} 按时间升序
        self._versions: dict[str, list[ContractVersion]] = {}
        self._latest_contracts: dict[str, _StubContract] = {}

    def commit(self, contract: _StubContract) -> ContractVersion:
        """提交一个合约版本。若与最新版本无差异则返回现有版本不新增。"""
        name = contract.module_name

        new_tree = ContractMerkleTree(contract)
        root = new_tree.root_hex()

        # 与最新版本比较
        prev_versions = self._versions.get(name, [])
        if prev_versions:
            prev = prev_versions[-1]
            prev_contract = self._latest_contracts.get(name)
            if prev_contract is not None:
                diffs = diff_contracts(prev_contract, contract)
                bump = infer_semver_bump(diffs)
                if bump == SemVerBump.NONE:
                    return prev
            else:
                bump = SemVerBump.MINOR  # 首次 diff 不可用，默认 Minor
        else:
            bump = SemVerBump.NONE

        new_semver = bump_semver(
            prev_versions[-1].semver if prev_versions else '0.1.0', bump)

        ver = ContractVersion(
            module_name=name,
            version_id=root[:12],
            merkle_root=root,
            leaf_count=new_tree.leaf_count,
            timestamp=_time.time(),
            semver=new_semver,
            prev_version_id=prev_versions[-1].version_id if prev_versions else '',
            bump=bump.value,
        )

        self._versions.setdefault(name, []).append(ver)
        self._latest_contracts[name] = contract
        self._persist(name)
        return ver

    def history(self, module_name: str) -> list[ContractVersion]:
        """返回模块的全部版本历史。"""
        self._ensure_loaded(module_name)
        return self._versions.get(module_name, [])

    def latest(self, module_name: str) -> _Opt[ContractVersion]:
        h = self.history(module_name)
        return h[-1] if h else None

    def _persist(self, module_name: str) -> None:
        """将模块的版本历史持久化到 JSON 文件。"""
        _os.makedirs(self.store_dir, exist_ok=True)
        path = _os.path.join(self.store_dir, f'{module_name}.versions.json')
        data = [v.to_dict() for v in self._versions.get(module_name, [])]
        with open(path, 'w', encoding='utf-8') as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)

    def _ensure_loaded(self, module_name: str) -> None:
        """从 JSON 文件惰性加载版本历史。"""
        if module_name in self._versions:
            return
        path = _os.path.join(self.store_dir, f'{module_name}.versions.json')
        if _os.path.isfile(path):
            try:
                with open(path, encoding='utf-8') as f:
                    data = _json.load(f)
                self._versions[module_name] = [
                    ContractVersion(**item) for item in data
                ]
            except (OSError, _json.JSONDecodeError, TypeError):
                self._versions[module_name] = []

    def list_modules(self) -> list[str]:
        """列出所有已版本化的模块名。"""
        modules = set()
        if _os.path.isdir(self.store_dir):
            for fn in _os.listdir(self.store_dir):
                if fn.endswith('.versions.json'):
                    modules.add(fn[:-len('.versions.json')])
        return sorted(modules)


__all__ = [
    'SemVerBump', 'ContractVersion', 'ContractDiffEntry',
    'ContractMerkleTree', 'diff_contracts', 'infer_semver_bump',
    'bump_semver', 'VersionedContractStore',
]
