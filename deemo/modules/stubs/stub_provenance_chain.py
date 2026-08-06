# stub_provenance_chain.py — 实现溯源链
# 为每次桩实现记录完整的溯源信息，以 SHA-256 哈希链防篡改。
# 区别于区块链方案 (DGChain, TOPO): 不依赖外部链，纯本地哈希链，
# 适合单仓库内代码生成审计场景。链上每条记录包含:
#   合约指纹 | 策略 | 验证结论 | 时间戳 | 前驱哈希
#
# 问题:
#   自动生成的桩实现在多轮迭代后难以追溯"这个实现从哪来"。
#   当发现一个 bug 时，需要回答: 哪个合约版本、哪个策略、通过了哪些验证？
#   没有溯源链就无法审计，也无法回退到已知良好版本。
#
# 方法:
#   1. 每次 GradualEngine.finalize() 时创建 ProvenanceEntry
#   2. 入口包含: contract_merkle_root, strategy, verification_ok,
#      incoherence_rate, timestamp
#   3. 用 SHA-256(content + prev_hash) 链接前一条记录
#   4. 链完整性可通过重新计算全部哈希来验证
import hashlib as _hl
import json as _json
import os as _os
import time as _time
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class ProvenanceEntry:
    """单次实现事件的溯源记录。"""
    module_name: str
    entry_id: str = ''              # 本条哈希前 12 位
    # 合约快照
    contract_merkle_root: str = ''  # stub_contract_merkle 的根哈希
    # 实现元数据
    strategy: str = ''              # template | llm | manual
    verification_ok: bool = False
    incoherence_rate: float = -1.0  # -1 = 未运行双策略检验
    # 生成源码的哈希（用于检测后续手动修改）
    source_sha256: str = ''
    # 链结构
    prev_hash: str = ''             # 前一条记录的 entry_hash
    entry_hash: str = ''            # 本条记录的 SHA-256
    timestamp: float = 0.0
    # 额外元数据
    generated_path: str = ''        # 输出文件路径（若有）
    notes: str = ''


class ProvenanceChain:
    """实现溯源哈希链。

    持久化: stubs/_provenance/{module_name}.chain.json
    每模块独立一条链，避免跨模块写入竞争。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.store_dir = _os.path.join(stubs_dir, '_provenance')
        self._chains: dict[str, list[ProvenanceEntry]] = {}

    def record(self, module_name: str, contract_merkle_root: str,
               strategy: str, verification_ok: bool,
               source_code: str = '',
               incoherence_rate: float = -1.0,
               generated_path: str = '',
               notes: str = '') -> ProvenanceEntry:
        """追加一条溯源记录到模块的链上。"""
        self._ensure_loaded(module_name)
        chain = self._chains[module_name]

        prev = chain[-1].entry_hash if chain else (
            _hl.sha256(b'genesis').hexdigest())

        entry = ProvenanceEntry(
            module_name=module_name,
            contract_merkle_root=contract_merkle_root,
            strategy=strategy,
            verification_ok=verification_ok,
            incoherence_rate=incoherence_rate,
            source_sha256=(_hl.sha256(source_code.encode('utf-8')).hexdigest()
                          if source_code else ''),
            prev_hash=prev,
            timestamp=_time.time(),
            generated_path=generated_path,
            notes=notes,
        )
        entry.entry_hash = self._compute_hash(entry)
        entry.entry_id = entry.entry_hash[:12]

        chain.append(entry)
        self._persist(module_name)
        return entry

    def verify(self, module_name: str) -> dict:
        """验证模块链的完整性。逐条重算哈希并核对前驱链接。

        返回: {valid: bool, total_entries: int, violations: [...]}
        """
        self._ensure_loaded(module_name)
        chain = self._chains.get(module_name, [])
        if not chain:
            return {'valid': True, 'total_entries': 0, 'violations': []}

        violations = []
        expected_prev = _hl.sha256(b'genesis').hexdigest()

        for i, entry in enumerate(chain):
            # 验证前驱链接
            if entry.prev_hash != expected_prev:
                violations.append({
                    'index': i, 'entry_id': entry.entry_id,
                    'field': 'prev_hash',
                    'expected': expected_prev[:12],
                    'got': entry.prev_hash[:12],
                })
            # 验证本条哈希
            recomputed = self._compute_hash(entry)
            if recomputed != entry.entry_hash:
                violations.append({
                    'index': i, 'entry_id': entry.entry_id,
                    'field': 'entry_hash',
                    'expected': recomputed[:12],
                    'got': entry.entry_hash[:12],
                })
            expected_prev = entry.entry_hash

        return {
            'valid': len(violations) == 0,
            'total_entries': len(chain),
            'violations': violations,
        }

    def history(self, module_name: str) -> list[ProvenanceEntry]:
        """返回模块的完整溯源历史。"""
        self._ensure_loaded(module_name)
        return self._chains.get(module_name, [])

    def latest(self, module_name: str) -> _Opt[ProvenanceEntry]:
        h = self.history(module_name)
        return h[-1] if h else None

    def find_last_verified(self, module_name: str) -> _Opt[ProvenanceEntry]:
        """查找最后一次通过验证的实现记录（用于回退到已知良好版本）。"""
        for entry in reversed(self.history(module_name)):
            if entry.verification_ok:
                return entry
        return None

    def strategy_success_rate(self, strategy: str) -> dict:
        """统计指定策略在所有模块上的成功率。"""
        total, ok = 0, 0
        for module_name in self._chains:
            for entry in self._chains[module_name]:
                if entry.strategy == strategy:
                    total += 1
                    if entry.verification_ok:
                        ok += 1
        return {
            'strategy': strategy,
            'total_attempts': total,
            'successes': ok,
            'success_rate': round(ok / total, 3) if total > 0 else 0.0,
        }

    # ---- 内部 ----
    @staticmethod
    def _compute_hash(entry: ProvenanceEntry) -> str:
        """计算溯源条目的 SHA-256 哈希（排除 entry_hash 字段本身）。"""
        payload = '|'.join([
            entry.module_name,
            entry.contract_merkle_root,
            entry.strategy,
            str(entry.verification_ok),
            str(entry.incoherence_rate),
            entry.source_sha256,
            entry.prev_hash,
            str(entry.timestamp),
            entry.generated_path,
            entry.notes,
        ])
        return _hl.sha256(payload.encode('utf-8')).hexdigest()

    def _ensure_loaded(self, module_name: str) -> None:
        if module_name in self._chains:
            return
        path = _os.path.join(self.store_dir, f'{module_name}.chain.json')
        if _os.path.isfile(path):
            try:
                with open(path, encoding='utf-8') as f:
                    data = _json.load(f)
                self._chains[module_name] = [
                    ProvenanceEntry(**item) for item in data
                ]
            except (_json.JSONDecodeError, TypeError, OSError):
                self._chains[module_name] = []
        else:
            self._chains[module_name] = []

    def _persist(self, module_name: str) -> None:
        _os.makedirs(self.store_dir, exist_ok=True)
        path = _os.path.join(self.store_dir, f'{module_name}.chain.json')
        data = [_dc_to_dict(e) for e in self._chains.get(module_name, [])]
        with open(path, 'w', encoding='utf-8') as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)

    def global_report(self) -> str:
        """生成全模块溯源摘要。"""
        lines = ['# 实现溯源链全局报告', '']
        lines.append('| 模块 | 记录数 | 最后策略 | 验证通过 | 链完整 |')
        lines.append('|------|-------:|---------|---------|-------:|')
        for name in sorted(self._chains):
            chain = self._chains[name]
            last = chain[-1] if chain else None
            vr = self.verify(name)
            lines.append(
                f'| {name} | {len(chain)} | '
                f'{last.strategy if last else "N/A"} | '
                f'{"OK" if last and last.verification_ok else "FAIL"} | '
                f'{"OK" if vr["valid"] else "TAMPERED"} |')
        return '\n'.join(lines)


def _dc_to_dict(e: ProvenanceEntry) -> dict:
    return {
        'module_name': e.module_name,
        'entry_id': e.entry_id,
        'contract_merkle_root': e.contract_merkle_root,
        'strategy': e.strategy,
        'verification_ok': e.verification_ok,
        'incoherence_rate': e.incoherence_rate,
        'source_sha256': e.source_sha256,
        'prev_hash': e.prev_hash,
        'entry_hash': e.entry_hash,
        'timestamp': e.timestamp,
        'generated_path': e.generated_path,
        'notes': e.notes,
    }


__all__ = ['ProvenanceEntry', 'ProvenanceChain']
