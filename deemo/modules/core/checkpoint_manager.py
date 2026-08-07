# coding: utf-8
# 创建: 2026-06-16 — 基础断点续传; 修改: 2026-08-04 — 增量+内容寻址+智能恢复
"""
增量差分检查点 — 首个全量, 后续仅存变更键 delta; 大值 blob 去重; 智能恢复
仅重跑输入变化的钩子; N 次后链压缩合并.
"""

import hashlib, json, os, time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_BLOB_THRESHOLD = 512

def _chash(obj: Any) -> str:
    try: raw = json.dumps(obj, sort_keys=True, default=repr).encode('utf-8')
    except: raw = repr(obj).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


@dataclass
class CheckpointManifest:
    checkpoint_id: str; created_at: float; completed_levels: int
    total_levels: int; completed_tasks: List[str]
    context_keys: Dict[str, str] = field(default_factory=dict)
    context_values: Dict[str, Any] = field(default_factory=dict)
    task_telemetry: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    provenance_edges: List[Dict[str, Any]] = field(default_factory=list)
    parent_id: str = ''; is_full: bool = True; checksum: str = ''

    def compute_checksum(self) -> str:
        tm = self.task_telemetry
        tk = sorted(tm.keys()) if isinstance(tm, dict) else str(len(tm)) if isinstance(tm, list) else ''
        p = {'id': self.checkpoint_id, 'at': self.created_at,
             'lv': f'{self.completed_levels}/{self.total_levels}',
             'tasks': sorted(self.completed_tasks), 'keys': sorted(self.context_keys.keys()),
             'tm': tk, 'edges': len(self.provenance_edges),
             'parent': self.parent_id, 'full': self.is_full}
        return hashlib.sha256(json.dumps(p, sort_keys=True, default=str).encode()).hexdigest()


class CheckpointManager:
    """增量差分检查点 — 首个全量/后续delta/blob去重/智能恢复/链压缩."""

    def __init__(self, checkpoint_dir: str = './.pipeline_checkpoints',
                 max_checkpoints: int = 5, compact_after: int = 8):
        self._dir = checkpoint_dir
        self._blob_dir = os.path.join(checkpoint_dir, 'blobs')
        self._max = max_checkpoints; self._compact_after = compact_after
        os.makedirs(self._dir, exist_ok=True); os.makedirs(self._blob_dir, exist_ok=True)
        self._manifests: List[CheckpointManifest] = []
        self._prev_ctx_hash: Dict[str, str] = {}

    def execute_with_checkpoints(
        self, prov_scheduler, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None, parallel: bool = True,
    ) -> Dict[str, Any]:
        if context is None: context = {}
        sched = prov_scheduler._sched
        if not sched._built: sched.build()
        total_levels = len(sched._levels); completed_tasks: List[str] = []
        orig = sched._run_level
        def _ckpt(level, ctx):
            orig(level, ctx); completed_tasks.extend(level)
            self._write_checkpoint(prov_scheduler, ctx,
                completed_levels=len(self._manifests)+1, total_levels=total_levels,
                completed_tasks=list(completed_tasks))
        sched._run_level = _ckpt
        try: return prov_scheduler.execute(context, max_workers=max_workers, parallel=parallel)
        finally: sched._run_level = orig

    def resume(
        self, prov_scheduler, context: Optional[Dict[str, Any]] = None,
        smart: bool = True,
    ) -> Optional[Dict[str, Any]]:
        latest = self._latest_checkpoint_path()
        if latest is None: return None
        data = self._load_full_context(latest)
        if data is None: return None
        if context is None: context = {}
        for k, v in data.get('context_snapshot', {}).items():
            context.setdefault(k, v)
        completed = set(data.get('completed_tasks', []))
        if not completed: return context
        sched = prov_scheduler._sched
        if not sched._built: sched.build()
        return self._smart_resume(sched, context, completed, data) if smart \
            else self._basic_resume(sched, prov_scheduler, context, completed)

    def resume_or_execute(
        self, prov_scheduler, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None, parallel: bool = True, smart: bool = True,
    ) -> Dict[str, Any]:
        r = self.resume(prov_scheduler, context, smart=smart)
        return r if r is not None else self.execute_with_checkpoints(
            prov_scheduler, context, max_workers=max_workers, parallel=parallel)

# 写入
    def _write_checkpoint(self, prov, context, completed_levels, total_levels, completed_tasks):
        cid = f'ckpt_{int(time.time()*1000)}_{completed_levels}'
        is_full = len(self._manifests) == 0
        cur_hashes = {k: _chash(v) for k, v in context.items()}
        changed = cur_hashes if is_full else {
            k: h for k, h in cur_hashes.items() if self._prev_ctx_hash.get(k) != h}
        for k in self._prev_ctx_hash:
            if k not in cur_hashes: changed[k] = ''
        inline = {}
        for k in changed:
            v = context.get(k)
            if v is None: inline[k] = None; continue
            try: raw = json.dumps(v, default=str)
            except: raw = str(v)
            if len(raw) > _BLOB_THRESHOLD:
                bh = _chash(raw); self._write_blob(bh, raw); inline[k] = {'__blob__': bh}
            else: inline[k] = v
        parent = self._manifests[-1].checkpoint_id if self._manifests else ''
        m = CheckpointManifest(checkpoint_id=cid, created_at=time.time(),
            completed_levels=completed_levels, total_levels=total_levels,
            completed_tasks=list(completed_tasks), context_keys=changed,
            context_values=inline,
            task_telemetry=prov.telemetry() if hasattr(prov, 'telemetry') and callable(prov.telemetry) else {},
            provenance_edges=self._serialize_edges(prov),
            parent_id=parent, is_full=is_full)
        m.checksum = m.compute_checksum()
        self._write_manifest(cid, m)
        self._prev_ctx_hash = cur_hashes; self._manifests.append(m)
        self._prune_and_compact()
        return m

    def _write_manifest(self, cid, m):
        fname = f'{cid}.json'; tmp = os.path.join(self._dir, fname+'.tmp')
        final = os.path.join(self._dir, fname)
        data = {k: getattr(m, k) for k in ['checkpoint_id','created_at','completed_levels',
            'total_levels','completed_tasks','context_keys','context_values',
            'task_telemetry','provenance_edges','parent_id','is_full','checksum']}
        with open(tmp, 'w', encoding='utf-8') as f: json.dump(data, f, ensure_ascii=False, default=str)
        os.replace(tmp, final)

    def _write_blob(self, bh, raw):
        p = os.path.join(self._blob_dir, f'{bh}.blob')
        if not os.path.exists(p):
            with open(p, 'w', encoding='utf-8') as f: f.write(raw)

# 恢复
    def _smart_resume(self, sched, context, completed, ckpt_data):
        ckpt_ctx = ckpt_data.get('context_snapshot', {})
        orig = sched._execute_one
        def _smart(name, ctx, failed, skipped):
            if name not in completed: orig(name, ctx, failed, skipped); return
            ik = self._input_keys(name, ckpt_data)
            if not ik: skipped.add(name); return
            ofp = _chash({k: ckpt_ctx.get(k) for k in ik})
            nfp = _chash({k: ctx.get(k) for k in ik})
            if ofp == nfp:
                for k, v in ckpt_ctx.items():
                    if k not in ctx: ctx[k] = v
                skipped.add(name)
            else: orig(name, ctx, failed, skipped)
        sched._execute_one = _smart
        try: return sched.execute(context)
        finally: sched._execute_one = orig

    def _basic_resume(self, sched, prov, context, completed):
        orig = sched._execute_one
        def _r(name, ctx, failed, skipped):
            if name in completed: skipped.add(name); return
            orig(name, ctx, failed, skipped)
        sched._execute_one = _r
        try: return sched.execute(context)
        finally: sched._execute_one = orig

    @staticmethod
    def _input_keys(name, ckpt_data):
        keys = set()
        for e in ckpt_data.get('provenance_edges', []):
            if e.get('hook_name') == name: keys.update(e.get('read_keys', []))
        return keys

# 加载
    def _load_full_context(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f: data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): return None
        stored = data.pop('checksum', '')
        m = CheckpointManifest(**{k: data.get(k, v) for k, v in {
            'checkpoint_id':'','created_at':0,'completed_levels':0,'total_levels':0,
            'completed_tasks':[],'context_keys':{},'context_values':{},
            'task_telemetry':{},'provenance_edges':[],'parent_id':'','is_full':True}.items()})
        if m.compute_checksum() != stored: return None
        ctx = {}
        chain = [data]
        if not data.get('is_full') and data.get('parent_id'):
            p = self._load_parent(data['parent_id'])
            if p: chain.insert(0, p)
        for d in chain:
            for k, v in d.get('context_values', {}).items():
                ctx[k] = self._read_blob(v['__blob__']) if isinstance(v, dict) and '__blob__' in v else v
        data['context_snapshot'] = ctx; data['checksum'] = stored
        return data

    def _load_parent(self, pid):
        try:
            with open(os.path.join(self._dir, f'{pid}.json'), 'r', encoding='utf-8') as f:
                return json.load(f)
        except: return None

    def _read_blob(self, bh):
        try:
            with open(os.path.join(self._blob_dir, f'{bh}.blob'), 'r', encoding='utf-8') as f:
                return json.loads(f.read())
        except: return None

# 维护
    def _prune_and_compact(self):
        if len(self._manifests) >= self._compact_after: self._compact_chain()
        if len(self._manifests) <= self._max: return
        files = sorted([f for f in os.listdir(self._dir) if f.endswith('.json') and not f.endswith('.tmp')])
        for old in files[:len(files)-self._max]:
            try: os.remove(os.path.join(self._dir, old))
            except OSError: pass

    def _compact_chain(self):
        if len(self._manifests) < 2: return
        latest = self._manifests[-1]
        lp = os.path.join(self._dir, f'{latest.checkpoint_id}.json')
        ctx = self._load_full_context(lp)
        if ctx is None: return
        latest.is_full = True; latest.parent_id = ''; latest.context_values = {}
        for k, v in ctx.get('context_snapshot', {}).items():
            latest.context_keys[k] = _chash(v)
            try: raw = json.dumps(v, default=str)
            except: raw = str(v)
            if len(raw) > _BLOB_THRESHOLD:
                bh = _chash(raw); self._write_blob(bh, raw); latest.context_values[k] = {'__blob__': bh}
            else: latest.context_values[k] = v
        latest.checksum = latest.compute_checksum()
        self._write_manifest(latest.checkpoint_id, latest)

    def _latest_checkpoint_path(self):
        files = sorted([f for f in os.listdir(self._dir) if f.endswith('.json') and not f.endswith('.tmp')], reverse=True)
        for f in files:
            p = os.path.join(self._dir, f)
            if os.path.getsize(p) > 0: return p
        return None

    @staticmethod
    def _serialize_edges(prov):
        if not hasattr(prov, 'graph'): return []
        return [{'edge_id': e.edge_id, 'hook_name': e.hook_name,
                 'input_ver': e.input_version_id, 'output_ver': e.output_version_id,
                 'wall_ms': e.wall_ms, 'success': e.success,
                 'read_keys': list(e.read_keys), 'written_keys': list(e.written_keys),
                 'error_msg': e.error_msg}
                for e in (prov.graph.edges() if hasattr(prov.graph, 'edges') else [])]

    def list_checkpoints(self):
        out = []
        for f in sorted(os.listdir(self._dir)):
            if not f.endswith('.json') or f.endswith('.tmp'): continue
            p = os.path.join(self._dir, f)
            try:
                with open(p, 'r', encoding='utf-8') as fh: data = json.load(fh)
            except: continue
            out.append({'id': data.get('checkpoint_id'),
                'levels': f'{data.get("completed_levels",0)}/{data.get("total_levels",0)}',
                'tasks': len(data.get('completed_tasks', [])),
                'edges': len(data.get('provenance_edges', [])),
                'is_full': data.get('is_full', True),
                'parent': data.get('parent_id', '')[:16],
                'size_kb': round(os.path.getsize(p)/1024, 1)})
        return out

    def clear(self):
        for f in os.listdir(self._dir):
            if f.endswith('.json') or f.endswith('.tmp'): os.remove(os.path.join(self._dir, f))
        for f in os.listdir(self._blob_dir): os.remove(os.path.join(self._blob_dir, f))
        self._manifests.clear(); self._prev_ctx_hash.clear()
