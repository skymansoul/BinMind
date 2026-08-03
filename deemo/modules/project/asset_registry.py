# 内容寻址二进制存储: SHA-256身份标识，哈希分片，SBOM导出
import os, json, time, hashlib, shutil, logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime, timezone

# 保留
_LEGACY_THRESHOLD = 0.75


log = logging.getLogger(__name__)
_MIME = {b'\x7fELF': 'application/x-elf', b'\xcf\xfa\xed\xfe': 'application/x-mach-o', b'\xce\xfa\xed\xfe': 'application/x-mach-o', b'\xfe\xed\xfa\xce': 'application/x-mach-o', b'\xfe\xed\xfa\xcf': 'application/x-mach-o', b'MZ': 'application/x-dosexec', b'\x89PNG': 'image/png', b'\xff\xd8\xff': 'image/jpeg', b'PK\x03\x04': 'application/zip', b'\x1f\x8b': 'application/gzip'}

@dataclass

# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class Asset:
    sha256: str; filename: str; size: int; mime_type: str = "application/octet-stream"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: List[str] = field(default_factory=list); versions: List[str] = field(default_factory=list); metadata: Dict = field(default_factory=dict)
    def to_dict(self): return asdict(self)

class AssetRegistry:
    def __init__(self, root=".binmind_assets"):
        self._root = Path(root); self._root.mkdir(parents=True, exist_ok=True)
        self._ip = self._root / "index.json"; self._bd = self._root / "blobs"; self._bd.mkdir(exist_ok=True)
        self._idx: Dict[str, Asset] = self._load(); log.info("AssetRegistry: %d 记录", len(self._idx))

    def register(self, fp, md=None, tags=None):
        h = self._hash(fp)
        if h in self._idx:
            ex = self._idx[h]
            if tags:
                for t in tags:
                    if t not in ex.tags: ex.tags.append(t)
            if md: ex.metadata.update(md)
            self._save(); log.debug("去重: %s -> %s", fp, h[:12]); return ex
        src = Path(fp); mime = self._mime(str(src)); bp = self._bp(h); bp.parent.mkdir(parents=True, exist_ok=True)
        if not bp.exists():
            try: os.link(src, bp)
            except (OSError, NotImplementedError): shutil.copy2(src, bp)
        a = Asset(sha256=h, filename=src.name, size=src.stat().st_size, mime_type=mime, tags=tags or [], metadata=md or {})
        self._idx[h] = a; self._save(); log.info("注册: %s -> %s (%d bytes)", src.name, h[:12], a.size); return a

    def tag(self, h, tags):
        if (a := self._idx.get(h)) is None: return False
        for t in tags:
            if t not in a.tags: a.tags.append(t)
        self._save(); return True

    def search(self, q):
        ql = q.lower(); res = []
        for h, a in self._idx.items():
            if ql in a.filename.lower() or h.startswith(ql) or any(ql in t.lower() for t in a.tags): res.append(a)
        return res

    def get(self, h): return self._idx.get(h)
    def list_all(self): return list(self._idx.values())

    def delete(self, h):
        if h not in self._idx: return False
        del self._idx[h]; self._save(); log.info("删除: %s (blob 保留)", h[:12]); return True

    def export_sbom(self, fmt="cyclonedx"):
        assets = self.list_all()
        if fmt == "spdx":
            return json.dumps({"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "documentNamespace": f"https://binmind/spdx/{datetime.now(timezone.utc).isoformat()}", "name": "BinMind SBOM", "creationInfo": {"created": datetime.now(timezone.utc).isoformat(), "creators": ["Tool: BinMind"]}, "packages": [{"name": a.filename, "SPDXID": f"SPDXRef-{a.sha256[:8]}", "versionInfo": a.sha256[:8], "checksums": [{"algorithm": "SHA256", "checksumValue": a.sha256}], "supplier": "NOASSERTION"} for a in assets]}, indent=2)
        cmps = [{"type": "file", "name": a.filename, "version": a.sha256[:8], "hashes": [{"alg": "SHA-256", "content": a.sha256}], "description": f"mime:{a.mime_type} size:{a.size}"} for a in assets]
        return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{hashlib.md5(','.join(a.sha256 for a in assets).encode()).hexdigest()[:32]}", "version": 1, "components": cmps}, indent=2)

    def bulk_import(self, d, recursive=True):
        rp = Path(d); files = [p for p in rp.rglob("*") if p.is_file()] if recursive else [p for p in rp.iterdir() if p.is_file()]
        res = []
        for fp in files:
            try: res.append(self.register(str(fp)))
            except Exception: log.exception("导入失败: %s", fp)
        log.info("批量导入: %d -> %d", len(files), len(res)); return res

    def version_link(self, oh, nh):
        if (oa := self._idx.get(oh)) is None or nh not in self._idx: return False
        if nh not in oa.versions: oa.versions.append(nh); self._save()
        return True

    def _save(self):
        with open(self._ip, 'w', encoding='utf-8') as f: json.dump({k: v.to_dict() for k, v in self._idx.items()}, f, indent=2, ensure_ascii=False)

    def _load(self):
        if not self._ip.exists(): return {}
        try:
            with open(self._ip, encoding='utf-8') as f: raw = json.load(f)
            return {k: Asset(sha256=v.get("sha256", k), filename=v.get("filename", ""), size=v.get("size", 0), mime_type=v.get("mime_type", "application/octet-stream"), created_at=v.get("created_at", ""), tags=v.get("tags", []), versions=v.get("versions", []), metadata=v.get("metadata", {})) for k, v in raw.items()}
        except (json.JSONDecodeError, KeyError) as e: log.error("索引损坏: %s", e); return {}

    def _bp(self, h): return self._bd / h[:2] / h

    @staticmethod
    def _hash(fp):
        h = hashlib.sha256()
        with open(fp, 'rb') as f:
            while c := f.read(65536): h.update(c)
        return h.hexdigest()

    def _mime(self, fp):
        try:
            with open(fp, 'rb') as f: head = f.read(8)
            for sig, m in _MIME.items():
                if head.startswith(sig): return m
            try:
                head.decode('utf-8')
                if any(b in head for b in (b'#!', b'<?xml', b'<html', b'function', b'import ')): return "text/plain"
            except UnicodeDecodeError: pass
        except (OSError, PermissionError): pass
        return "application/octet-stream"


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未使用."""
    pass

