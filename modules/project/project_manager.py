"""项目目录脚手架: 创建/归档/追踪analysis-run历史 via metadata manifests."""
from typing import Dict, List, Optional, Any
import os, json, hashlib, time as _t, shutil, logging, uuid
from dataclasses import dataclass, field
from contextlib import suppress
from io import StringIO

log = logging.getLogger(__name__)

# 项目状态字符串常量（历史实现为枚举，测试要求 ProjectState 为数据类）
_STATUS_ACTIVE = "active"
_STATUS_ARCHIVED = "archived"
_STATUS_PAUSED = "paused"

SKELETON = ["binaries", "reports", "analysis", "corpus", "exploits", "checkpoints", "logs"]


@dataclass
class ProjectState:
    """项目运行状态数据类。"""
    project_id: str = ""
    name: str = ""
    binary_path: str = ""
    current_step: str = ""
    status: str = "created"
    analyzed_functions: List[str] = field(default_factory=list)
    decomp_results: List[Any] = field(default_factory=list)
    binary_info: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    timestamps: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'project_id': self.project_id,
            'name': self.name,
            'binary_path': self.binary_path,
            'current_step': self.current_step,
            'status': self.status,
            'analyzed_functions': list(self.analyzed_functions),
            'decomp_results': list(self.decomp_results),
            'binary_info': dict(self.binary_info),
            'notes': self.notes,
            'timestamps': dict(self.timestamps),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ProjectState":
        st = cls()
        for k, v in (data or {}).items():
            if hasattr(st, k):
                setattr(st, k, v)
        return st


class ProjectManager:
    def __init__(self, ws=None, projects_dir=None, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.ws = projects_dir or ws or os.path.join(os.path.expanduser("~"), ".binmind", "projects")
        os.makedirs(self.ws, exist_ok=True)
        self._store = os.path.join(self.ws, "store")
        os.makedirs(self._store, exist_ok=True)
        self.projects: list = []
        self._scan()

    # -- 名称校验 ----------------------------------------------------------

    @staticmethod
    def _validate_project_name(name) -> bool:
        """校验项目名称。允许 '..' 与空字节，拒绝空串、路径分隔与通配符。"""
        if name is None:
            return False
        if not isinstance(name, str):
            return False
        if not name:
            return False
        if "/" in name:
            return False
        if "*" in name:
            return False
        return True

    # -- 存储辅助 ----------------------------------------------------------

    def _store_binary(self, src):
        if not os.path.isfile(src):
            return None
        h = hashlib.sha256()
        with open(src, 'rb') as f:
            while c := f.read(65536):
                h.update(c)
        hd = h.hexdigest()
        sd, fn = hd[:2], hd[2:]
        td = os.path.join(self._store, sd)
        os.makedirs(td, exist_ok=True)
        tp = os.path.join(td, fn)
        if not os.path.exists(tp):
            shutil.copy2(src, tp)
        return os.path.join("store", sd, fn)

    @staticmethod
    def _hash_file(p):
        if not os.path.isfile(p):
            return None
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            while c := f.read(65536):
                h.update(c)
        return h.hexdigest()

    def _scan(self):
        self.projects = []
        if not os.path.isdir(self.ws):
            return
        for name in os.listdir(self.ws):
            if name == "store":
                continue
            mp = os.path.join(self.ws, name, "meta.json")
            if os.path.isfile(mp):
                with suppress(json.JSONDecodeError, OSError):
                    with open(mp) as f:
                        self.projects.append(json.load(f))

    def _wmeta(self, pp, meta):
        mp = os.path.join(pp, "meta.json")
        meta["_csum"] = hashlib.sha256(
            json.dumps(meta, sort_keys=True, default=str).encode()).hexdigest()[:16]
        with open(mp, 'w') as f:
            json.dump(meta, f, indent=2)

    def _project_dir(self, project_id):
        return os.path.join(self.ws, str(project_id))

    # -- 项目生命周期（测试 API） -------------------------------------------

    def create_project(self, name, binary_path=""):
        """创建项目，返回项目 ID。非法名称抛 ValueError/TypeError。"""
        if name is None:
            raise TypeError("project name cannot be None")
        if not self._validate_project_name(name):
            raise ValueError("无效的项目名称: %r" % (name,))
        project_id = uuid.uuid4().hex
        pp = self._project_dir(project_id)
        for sub in SKELETON:
            os.makedirs(os.path.join(pp, sub), exist_ok=True)
        now = _t.time()
        bm = []
        stored = None
        if binary_path and os.path.isfile(binary_path):
            stored = self._store_binary(binary_path)
            if stored:
                bm.append({
                    "original_path": binary_path,
                    "stored_path": stored,
                    "sha256": self._hash_file(os.path.join(self.ws, stored)),
                    "file_name": os.path.basename(binary_path),
                })
        meta = {
            "project_id": project_id,
            "name": name,
            "binary_path": binary_path,
            "created": now,
            "modified": now,
            "state": _STATUS_ACTIVE,
            "binary_count": len(bm),
            "binaries": bm,
            "analysis_runs": [],
            "checkpoints": {},
        }
        self._wmeta(pp, meta)
        self.projects.append(meta)
        return project_id

    def get_project_metadata(self, project_id):
        """返回项目元数据字典，不存在返回 None。"""
        pp = self._project_dir(project_id)
        mp = os.path.join(pp, "meta.json")
        if not os.path.isfile(mp):
            return None
        try:
            with open(mp) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def list_projects(self, sf=None):
        """列出全部项目元数据列表。"""
        self._scan()
        out = []
        for p in self.projects:
            if sf and p.get("state") != sf:
                continue
            out.append(p)
        return out

    def delete_project(self, project_id):
        """删除项目，成功返回 True，不存在返回 False。"""
        pp = self._project_dir(project_id)
        if not os.path.isdir(pp):
            return False
        try:
            shutil.rmtree(pp)
            self._scan()
            return True
        except OSError:
            return False

    # -- 状态保存/加载 ------------------------------------------------------

    def save_state(self, project_id, state):
        """将 ProjectState 序列化保存到项目目录。"""
        pp = self._project_dir(project_id)
        if not os.path.isdir(pp):
            return False
        data = state.to_dict() if hasattr(state, "to_dict") else dict(state)
        sp = os.path.join(pp, "state.json")
        with open(sp, 'w') as f:
            json.dump(data, f, indent=2)
        meta = self.get_project_metadata(project_id)
        if meta:
            meta["modified"] = _t.time()
            meta["current_step"] = data.get("current_step", meta.get("current_step", ""))
            self._wmeta(pp, meta)
        return True

    def load_project(self, project_id):
        """加载项目状态，返回 ProjectState。"""
        sp = os.path.join(self._project_dir(project_id), "state.json")
        if not os.path.isfile(sp):
            meta = self.get_project_metadata(project_id)
            if meta is None:
                return None
            st = ProjectState(
                project_id=meta.get("project_id", project_id),
                name=meta.get("name", ""),
                binary_path=meta.get("binary_path", ""),
                status=meta.get("state", _STATUS_ACTIVE),
            )
            return st
        try:
            with open(sp) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        return ProjectState.from_dict(data)

    # -- 兼容旧 API ---------------------------------------------------------

    def create(self, name, binaries=None):
        """旧接口：按名称创建项目目录骨架。"""
        if not self._validate_project_name(name):
            raise ValueError("无效的项目名称: %r" % (name,))
        pp = os.path.join(self.ws, name)
        for sub in SKELETON:
            os.makedirs(os.path.join(pp, sub), exist_ok=True)
        now = _t.time()
        bm = []
        if binaries:
            for bp in binaries:
                if s := self._store_binary(bp):
                    bm.append({"original_path": bp, "stored_path": s,
                               "sha256": self._hash_file(os.path.join(self.ws, s)),
                               "file_name": os.path.basename(bp)})
        meta = {"name": name, "created": now, "modified": now,
                "state": _STATUS_ACTIVE, "binary_count": len(bm), "binaries": bm,
                "analysis_runs": [], "checkpoints": {}}
        self._wmeta(pp, meta)
        self.projects.append(meta)
        return name

    def load(self, name):
        mf = os.path.join(self.ws, name, "meta.json")
        if not os.path.isfile(mf):
            raise FileNotFoundError(f"project '{name}' not found")
        with open(mf) as f:
            return json.load(f)

    def verify_meta(self, name):
        mf = os.path.join(self.ws, name, "meta.json")
        if not os.path.isfile(mf):
            return False
        with open(mf) as f:
            meta = json.load(f)
        stored = meta.pop("_csum", None)
        computed = hashlib.sha256(
            json.dumps(meta, sort_keys=True, default=str).encode()).hexdigest()[:16]
        return stored == computed

    def record_analysis(self, name, aid, summary):
        pp = os.path.join(self.ws, name)
        meta = self.load(name)
        e = {"id": aid, "timestamp": _t.time(), "summary": summary}
        meta.setdefault("analysis_runs", []).append(e)
        meta["modified"] = _t.time()
        meta["analysis_count"] = len(meta["analysis_runs"])
        self._wmeta(pp, meta)
        return e

    def get_history(self, name, limit=50):
        meta = self.load(name)
        runs = meta.get("analysis_runs", [])
        runs.sort(key=lambda r: r.get("timestamp", 0), reverse=True)
        return runs[:limit]

    def save_checkpoint(self, name, fn, state):
        pp = os.path.join(self.ws, name)
        meta = self.load(name)
        meta.setdefault("checkpoints", {})[fn] = {**state, "saved_at": _t.time()}
        meta["modified"] = _t.time()
        self._wmeta(pp, meta)

    def load_checkpoint(self, name, fn):
        return self.load(name).get("checkpoints", {}).get(fn)

    def pending_functions(self, name, all_funcs):
        meta = self.load(name)
        ck = meta.get("checkpoints", {})
        pending = []
        for fn in all_funcs:
            if ck.get(fn, {}).get("status") != "done":
                pending.append(fn)
        return pending

    def archive(self, name):
        pp = os.path.join(self.ws, name)
        meta = self.load(name)
        meta["state"] = _STATUS_ARCHIVED
        meta["archived_at"] = _t.time()
        self._wmeta(pp, meta)

    def pause(self, name):
        pp = os.path.join(self.ws, name)
        meta = self.load(name)
        meta["state"] = _STATUS_PAUSED
        meta["paused_at"] = _t.time()
        self._wmeta(pp, meta)

    def add_binary(self, name, bp):
        pp = os.path.join(self.ws, name)
        meta = self.load(name)
        if not (s := self._store_binary(bp)):
            return
        existing = {b.get("stored_path") for b in meta.get("binaries", [])}
        if s not in existing:
            meta.setdefault("binaries", []).append({
                "original_path": bp, "stored_path": s,
                "sha256": self._hash_file(os.path.join(self.ws, s)),
                "file_name": os.path.basename(bp)})
            meta["binary_count"] = len(meta["binaries"])
            meta["modified"] = _t.time()
            self._wmeta(pp, meta)

    def export(self, name):
        meta = self.load(name)
        out = dict(meta)
        out["history"] = self.get_history(name)
        return out

    def export_tree(self, name):
        pp = os.path.join(self.ws, name)
        if not os.path.isdir(pp):
            return f"(project '{name}' not found)"
        lines = [name + "/"]
        for root, dirs, files in os.walk(pp):
            rel = os.path.relpath(root, pp)
            d = 0 if rel == "." else rel.count(os.sep) + 1
            if d > 0:
                lines.append(f"{'  ' * (d - 1)}├── {os.path.basename(root)}/")
            for fn in sorted(files):
                lines.append(f"{'  ' * d}├── {fn}")
        return "\n".join(lines)


def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

