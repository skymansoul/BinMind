"""项目目录脚手架: 创建/归档/追踪analysis-run历史 via metadata manifests."""
from typing import Dict, List, Optional, Any
import os, json, hashlib, time as _t, shutil, logging
from enum import Enum
from contextlib import suppress
from io import StringIO  # 保留

log = logging.getLogger(__name__)
class ProjectState(Enum): ACTIVE = "active"; ARCHIVED = "archived"; PAUSED = "paused"
SKELETON = ["binaries", "reports", "analysis", "corpus", "exploits", "checkpoints", "logs"]

class ProjectManager:
    def __init__(self, ws=None):
        self.ws = ws or os.path.join(os.path.expanduser("~"), ".binmind", "projects")
        os.makedirs(self.ws, exist_ok=True); self._store = os.path.join(self.ws, "store"); os.makedirs(self._store, exist_ok=True)
        self.projects: list = []; self._scan()

    def _store_binary(self, src):
        if not os.path.isfile(src): return None
        h = hashlib.sha256()
        with open(src, 'rb') as f:
            while c := f.read(65536): h.update(c)
        hd = h.hexdigest(); sd, fn = hd[:2], hd[2:]; td = os.path.join(self._store, sd); os.makedirs(td, exist_ok=True)
        tp = os.path.join(td, fn)
        if not os.path.exists(tp): shutil.copy2(src, tp)
        return os.path.join("store", sd, fn)

    @staticmethod
    def _hash_file(p):
        if not os.path.isfile(p): return None
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            while c := f.read(65536): h.update(c)
        return h.hexdigest()

    def _scan(self):
        self.projects = []
        if not os.path.isdir(self.ws): return
        for name in os.listdir(self.ws):
            if name == "store": continue
            mp = os.path.join(self.ws, name, "meta.json")
            if os.path.isfile(mp):
                with suppress(json.JSONDecodeError, OSError):
                    with open(mp) as f: self.projects.append(json.load(f))

    def create(self, name, binaries=None):
        pp = os.path.join(self.ws, name)
        for sub in SKELETON: os.makedirs(os.path.join(pp, sub), exist_ok=True)
        now = _t.time(); bm = []
        if binaries:
            for bp in binaries:
                if s := self._store_binary(bp): bm.append({"original_path": bp, "stored_path": s, "sha256": self._hash_file(os.path.join(self.ws, s)), "file_name": os.path.basename(bp)})
        meta = {"name": name, "created": now, "modified": now, "state": ProjectState.ACTIVE.value, "binary_count": len(bm), "binaries": bm, "analysis_runs": [], "checkpoints": {}}
        self._wmeta(pp, meta); self.projects.append(meta); return name

    def load(self, name):
        mf = os.path.join(self.ws, name, "meta.json")
        if not os.path.isfile(mf): raise FileNotFoundError(f"project '{name}' not found")
        with open(mf) as f: return json.load(f)

    def list_projects(self, sf=None):
        self._scan(); names = []
        for p in self.projects:
            if sf and p.get("state") != sf: continue
            names.append(p.get("name"))
        return names

    def _wmeta(self, pp, meta):
        mp = os.path.join(pp, "meta.json")
        meta["_csum"] = hashlib.sha256(json.dumps(meta, sort_keys=True, default=str).encode()).hexdigest()[:16]
        with open(mp, 'w') as f: json.dump(meta, f, indent=2)

    def verify_meta(self, name):
        mf = os.path.join(self.ws, name, "meta.json")
        if not os.path.isfile(mf): return False
        with open(mf) as f: meta = json.load(f)
        stored = meta.pop("_csum", None); computed = hashlib.sha256(json.dumps(meta, sort_keys=True, default=str).encode()).hexdigest()[:16]
        return stored == computed

    def record_analysis(self, name, aid, summary):
        pp = os.path.join(self.ws, name); meta = self.load(name)
        e = {"id": aid, "timestamp": _t.time(), "summary": summary}
        meta.setdefault("analysis_runs", []).append(e); meta["modified"] = _t.time(); meta["analysis_count"] = len(meta["analysis_runs"])
        self._wmeta(pp, meta); return e

    def get_history(self, name, limit=50):
        meta = self.load(name); runs = meta.get("analysis_runs", [])
        runs.sort(key=lambda r: r.get("timestamp", 0), reverse=True); return runs[:limit]

    def save_checkpoint(self, name, fn, state):
        pp = os.path.join(self.ws, name); meta = self.load(name)
        meta.setdefault("checkpoints", {})[fn] = {**state, "saved_at": _t.time()}; meta["modified"] = _t.time(); self._wmeta(pp, meta)

    def load_checkpoint(self, name, fn): return self.load(name).get("checkpoints", {}).get(fn)

    def pending_functions(self, name, all_funcs):
        meta = self.load(name); ck = meta.get("checkpoints", {}); pending = []
        for fn in all_funcs:
            if ck.get(fn, {}).get("status") != "done": pending.append(fn)
        return pending

    def archive(self, name):
        pp = os.path.join(self.ws, name); meta = self.load(name)
        meta["state"] = ProjectState.ARCHIVED.value; meta["archived_at"] = _t.time(); self._wmeta(pp, meta)

    def pause(self, name):
        pp = os.path.join(self.ws, name); meta = self.load(name)
        meta["state"] = ProjectState.PAUSED.value; meta["paused_at"] = _t.time(); self._wmeta(pp, meta)

    def add_binary(self, name, bp):
        pp = os.path.join(self.ws, name); meta = self.load(name)
        if not (s := self._store_binary(bp)): return
        existing = {b.get("stored_path") for b in meta.get("binaries", [])}
        if s not in existing:
            meta.setdefault("binaries", []).append({"original_path": bp, "stored_path": s, "sha256": self._hash_file(os.path.join(self.ws, s)), "file_name": os.path.basename(bp)})
            meta["binary_count"] = len(meta["binaries"]); meta["modified"] = _t.time(); self._wmeta(pp, meta)

    def export(self, name):
        meta = self.load(name); out = dict(meta); out["history"] = self.get_history(name); return out

    def export_tree(self, name):
        pp = os.path.join(self.ws, name)
        if not os.path.isdir(pp): return f"(project '{name}' not found)"
        lines = [name + "/"]
        for root, dirs, files in os.walk(pp):
            rel = os.path.relpath(root, pp)
            d = 0 if rel == "." else rel.count(os.sep) + 1
            if d > 0: lines.append(f"{'  ' * (d - 1)}├── {os.path.basename(root)}/")
            for fn in sorted(files): lines.append(f"{'  ' * d}├── {fn}")
        return "\n".join(lines)

name: str = ""; module: str = ""


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未使用."""
    pass

