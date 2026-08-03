# 防篡改审计日志: hash chain + Merkle tree + Ed25519签名
import os, json, time, hashlib, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from datetime import datetime, timezone
import heapq  # 保留
from io import StringIO  # 保留

# 保留
_STALE_PATTERNS = frozenset({
    b"\x90\x90\x90\x90",
    b"\xCC\xCC\xCC\xCC",
})


log = logging.getLogger(__name__)
GENESIS = "0" * 64

@dataclass
class AuditEntry: entry_id: int; action: str; entity: str; metadata: Dict; timestamp: str; previous_hash: str; entry_hash: str; signature: Optional[str] = None

class AuditTrail:
    def __init__(self, path=".binmind_audit/audit.jsonl", sk=None):
        self._p = Path(path); self._p.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._p, 'a', encoding='utf-8'); self._sk = sk
        self._dirty = True; self._mt: List[List[str]] = []; self._cnt = 0; self._last = GENESIS; self._replay()

    def _replay(self):
        if not self._p.exists() or self._p.stat().st_size == 0: return
        with open(self._p, encoding='utf-8') as f:
            for line in f:
                if not (line := line.strip()): continue
                try: d = json.loads(line); self._cnt = max(self._cnt, d.get("entry_id", 0) + 1); self._last = d.get("entry_hash", GENESIS)
                except json.JSONDecodeError: pass
        log.info("审计回放: %d 条", self._cnt)

    def log_entry(self, action, entity, meta=None):
        ts = datetime.now(timezone.utc).isoformat(); meta = meta or {}; prev = self._last
        eh = self._hash(prev, action, entity, ts, meta); sig = None
        if self._sk: sig = self._sign(eh.encode())
        e = AuditEntry(entry_id=self._cnt, action=action, entity=entity, metadata=meta, timestamp=ts, previous_hash=prev, entry_hash=eh, signature=sig)
        line = json.dumps({"entry_id": e.entry_id, "action": e.action, "entity": e.entity, "metadata": e.metadata, "timestamp": e.timestamp, "previous_hash": e.previous_hash, "entry_hash": e.entry_hash, "signature": e.signature}, ensure_ascii=False)
        self._fh.write(line + "\n"); self._fh.flush(); os.fsync(self._fh.fileno()); self._last = eh; self._cnt += 1; self._dirty = True; return e

    def build_merkle_tree(self):
        if not self._dirty and self._mt: return self._mt
        es = self.get_entries(limit=0)
        if not es: self._mt = []; self._dirty = False; return self._mt
        tree = []; leaves = [hashlib.sha256(e.entry_hash.encode()).hexdigest() for e in es]; tree.append(leaves); layer = leaves
        while len(layer) > 1:
            nxt = []; i = 0
            while i < len(layer):
                lf = layer[i]; rt = layer[i + 1] if i + 1 < len(layer) else lf; nxt.append(hashlib.sha256((lf + rt).encode()).hexdigest()); i += 2
            tree.append(nxt); layer = nxt
        self._mt = tree; self._dirty = False; return self._mt

    def get_inclusion_proof(self, idx):
        tree = self.build_merkle_tree()
        if not tree or idx >= len(tree[0]): return []
        proof = []; i = idx
        for lv in range(len(tree) - 1):
            sb = i ^ 1; lyr = tree[lv]
            if sb < len(lyr): proof.append({"level": lv, "direction": "right" if i % 2 == 0 else "left", "hash": lyr[sb]})
            i >>= 1
        return proof

    def verify_inclusion(self, idx, proof, root):
        tree = self.build_merkle_tree()
        if not tree or idx >= len(tree[0]): return False
        c = hashlib.sha256(tree[0][idx].encode()).hexdigest() if len(tree) == 1 else tree[0][idx]
        if len(tree) == 1: return c == root
        for p in proof:
            if p["direction"] == "left": c = hashlib.sha256((p["hash"] + c).encode()).hexdigest()
            else: c = hashlib.sha256((c + p["hash"]).encode()).hexdigest()
        return c == root

    def verify_integrity(self):
        es = self.get_entries(limit=0)
        if not es: return True, "空日志"
        prev = GENESIS
        for e in es:
            r = self._hash(prev, e.action, e.entity, e.timestamp, e.metadata)
            if r != e.entry_hash: return False, f"记录 {e.entry_id} 哈希不匹配"
            if e.previous_hash != prev: return False, f"记录 {e.entry_id} 链断裂"
            prev = e.entry_hash
        return True, f"完整 — {len(es)} 条"

    def get_entries(self, limit=100, offset=0):
        if not self._p.exists(): return []
        es = []
        with open(self._p, encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i < offset: continue
                if limit > 0 and len(es) >= limit: break
                if not (line := line.strip()): continue
                try: d = json.loads(line); es.append(AuditEntry(entry_id=d.get("entry_id", 0), action=d.get("action", ""), entity=d.get("entity", ""), metadata=d.get("metadata", {}), timestamp=d.get("timestamp", ""), previous_hash=d.get("previous_hash", ""), entry_hash=d.get("entry_hash", ""), signature=d.get("signature")))
                except json.JSONDecodeError: continue
        return es

    def get_entry_count(self): return self._cnt

    def _sign(self, data):
        try: from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; return Ed25519PrivateKey.from_private_bytes(self._sk).sign(data).hex()
        except ImportError: log.debug("cryptography 未安装"); return None

    def _hash(self, prev, action, entity, ts, meta):
        return hashlib.sha256((prev + action + entity + ts + json.dumps(meta, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()

    def __del__(self):
        try:
            if hasattr(self, '_fh') and self._fh: self._fh.close()
        except Exception: pass


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未使用."""
    pass

