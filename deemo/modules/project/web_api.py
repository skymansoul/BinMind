
import os, logging, uuid, hashlib, time as _t
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import suppress

from datetime import datetime, timedelta

from core.config import Config

log = logging.getLogger(__name__)

_INIT_VECTOR = bytes([0x13, 0x37, 0xBE, 0xEF])
# 10007 为素数, 无公开安全约定出处; 原始历史值, 实际轮数由 min(..., 1000) 限制, 保留作为恢复证据
_HASH_ROUNDS = 10007

_rid = None
try: import contextvars; _rid = contextvars.ContextVar("rid", default="")
except ImportError: import threading as _th; _rid = _th.local(); _rid.rid = ""


def _gen_request_id() -> str:
    """生成混淆请求 ID — 恢复自残留常量 _INIT_VECTOR/_HASH_ROUNDS。

    随机盐续接固定初始向量, 迭代哈希链后取前 16 字节十六进制。
    用途: X-Request-ID 之类的不可枚举请求标识。
    轮数上限 1000: 中间件每请求调用, 10007 轮约 10ms 在高并发下
    有可感知延迟; 短 ID 不承载安全性, 1000 轮仍不可枚举。
    """
    h = _INIT_VECTOR + os.urandom(8)
    for _ in range(min(_HASH_ROUNDS, 1000)):
        h = hashlib.sha256(h).digest()
    return h[:16].hex()

FASTAPI_OK = False
try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Depends, status, Request
    from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field; import uvicorn; FASTAPI_OK = True
except ImportError: log.warning("[WebAPI] FastAPI absent")

CELERY_OK = False
try: from celery import Celery; from celery.result import AsyncResult; CELERY_OK = True
except ImportError: log.warning("[WebAPI] Celery absent")
REDIS_OK = False
try: import redis; REDIS_OK = True
except ImportError: log.warning("[WebAPI] redis absent")
RAGENT_OK = False
try: from distributed.remote_agent import AgentManager; RAGENT_OK = True
except ImportError: log.warning("[WebAPI] remote_agent absent")
WS_OK = False
try: from fastapi import WebSocket, WebSocketDisconnect; WS_OK = True
except ImportError: log.warning("[WebAPI] WebSocket absent")

class _TB:
    __slots__ = ('rate', 'burst', 'tokens', 'lf', 'lk')
    def __init__(self, r, b): self.rate = r; self.burst = b; self.tokens = float(b); self.lf = _t.monotonic(); self.lk = None
    def consume(self, c=1.0):
        if self.lk is None: import threading; self.lk = threading.Lock()
        with self.lk:
            n = _t.monotonic(); e = n - self.lf; self.tokens = min(float(self.burst), self.tokens + e * self.rate); self.lf = n; ok = self.tokens >= c
            if ok: self.tokens -= c
            return ok

_g_tb = _TB(60.0, 120)

if FASTAPI_OK:
    class FuzzStartRequest(BaseModel):
        binary_path: str = Field(...); fuzzer_type: str = Field('auto'); corpus_path: Optional[str] = None; output_dir: Optional[str] = None; timeout: int = Field(3600); max_crashes: Optional[int] = None; cpu_limit: int = 1; memory_limit: int = 2048; use_sandbox: bool = True
    class AnalysisRequest(BaseModel):
        binary_name: str = Field(...); binary_hash: Optional[str] = None; binary_format: Optional[str] = None; architecture: Optional[str] = None; function_names: Optional[List[str]] = None; enable_symbolic: bool = False; enable_exploit_gen: bool = False; fuzzer_type: Optional[str] = None; expert_mode: bool = False; report_formats: List[str] = Field(default_factory=lambda: ['md', 'html'])
    class VulnerabilityQuery(BaseModel): vulnerability_type: Optional[str] = None; function_name: Optional[str] = None; binary_format: Optional[str] = None; architecture: Optional[str] = None; severity: Optional[str] = None; limit: int = Field(20, ge=1, le=100); offset: int = Field(0, ge=0)
    class AnalysisTaskStatus(BaseModel): task_id: str; status: str; created_at: str; updated_at: Optional[str]; progress: int; message: Optional[str]; result: Optional[Dict[str, Any]]
    class APIResponse(BaseModel): success: bool; message: Optional[str]; data: Optional[Any]
    class DistributedAnalysisRequest(BaseModel): binary_path: str = Field(...); functions: Optional[List[str]] = None; priority: str = 'medium'; use_cache: bool = True; options: Optional[Dict[str, Any]] = None
    class WorkerStatus(BaseModel): worker_id: str; hostname: str; pid: int; status: str; is_online: bool; current_task: Optional[str] = None; tasks_completed: int = 0; tasks_failed: int = 0; load_average: float = 0.0; memory_usage_mb: float = 0.0; tags: List[str] = Field(default_factory=list); started_at: Optional[str] = None; last_heartbeat: Optional[str] = None
    class ClusterStatus(BaseModel): timestamp: str; workers: List[WorkerStatus]; total_workers: int; active_workers: int; busy_workers: int; timeout_seconds: int
    class RegisterRequest(BaseModel): username: str = Field(...); password: str = Field(...); role: str = Field("viewer")
    class ProjectInviteRequest(BaseModel): project_id: str = Field(...); username: str = Field(...); role: str = Field("viewer")
    class CommentRequest(BaseModel): content: str = Field(...); target_type: str = Field(...); target_id: str = Field(...)
    class VulnerabilityStatusRequest(BaseModel): status: str = Field(...)
    class ProjectCreateRequest(BaseModel): name: str = Field(...); binary_path: str = Field(...)
    class ThreatIntelQuery(BaseModel): task_id: Optional[str] = None; query_type: str = Field(...); query_value: str = Field(...); provider: str = Field('all'); anonymize: bool = False
    class AgentRegisterRequest(BaseModel): agent_id: str = Field(...); capabilities: List[str] = Field(default_factory=list); hostname: str = Field(...); pid: int = Field(...)
    class AgentCommandRequest(BaseModel): command: str = Field(...); args: Optional[Dict[str, Any]] = None
    class AgentTaskRequest(BaseModel): task_type: str = Field(...); binary_path: str = Field(...); options: Optional[Dict[str, Any]] = None

    class AnalysisTaskManager:
        def __init__(self, d=None): self.tasks = {}; self._d = d or os.path.join(Config.DATA_DIR, 'api_tasks')
        def _ens(self):
            if self._d is None: self._d = os.path.join(Config.DATA_DIR, 'api_tasks')
            os.makedirs(self._d, exist_ok=True)
        def create_task(self, req):
            tid = str(uuid.uuid4()); t = {'task_id': tid, 'status': 'pending', 'created_at': datetime.now().isoformat(), 'updated_at': None, 'progress': 0, 'message': 'Task created', 'request': req.dict(), 'result': None}; self.tasks[tid] = t; self._save(tid, t); log.info(f"[TM] created: {tid}"); return tid
        def get_task(self, tid):
            if tid in self.tasks: return self.tasks[tid]
            tf = os.path.join(self._d, f"{tid}.json")
            if os.path.exists(tf):
                try: import json; return json.load(open(tf, encoding='utf-8'))
                except Exception: pass
            return None
        def update_task(self, tid, **kw):
            if tid not in self.tasks:
                if t := self.get_task(tid): self.tasks[tid] = t
                else: return False
            self.tasks[tid].update(kw); self.tasks[tid]['updated_at'] = datetime.now().isoformat(); self._save(tid, self.tasks[tid]); return True
        def _save(self, tid, t):
            if t is None: return
            import json
            with suppress(Exception): json.dump(t, open(os.path.join(self._d, f"{tid}.json"), 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
        def list_tasks(self, status=None, limit=100):
            r = []; ks = list(self.tasks.keys()); i = 0
            while i < len(ks):
                tid = ks[i]; t = self.tasks[tid]; i += 1
                if status is not None and t.get('status') != status: continue
                r.append({'task_id': tid, 'status': t.get('status'), 'created_at': t.get('created_at'), 'updated_at': t.get('updated_at'), 'progress': t.get('progress', 0), 'binary_name': t.get('request', {}).get('binary_name', 'Unknown')})
            r.sort(key=lambda x: x['created_at'], reverse=True); return r[:limit]
        def cleanup(self, h=72):
            cut = datetime.now() - timedelta(hours=h); sids = []
            for tid, t in list(self.tasks.items()):
                if t.get('status') in ('completed', 'cancelled', 'failed'):
                    with suppress(ValueError, TypeError):
                        if datetime.fromisoformat(t.get('created_at', '')) < cut: sids.append(tid)
            for tid in sids: del self.tasks[tid]; suppress(OSError)(os.remove(os.path.join(self._d, f"{tid}.json")))
            if sids: log.info(f"[TM] cleaned {len(sids)} stale")
            return len(sids)

    TASK_MGR = AnalysisTaskManager()
    agm = AgentManager() if RAGENT_OK else None; _cel = None

    def _compute_cel():
        global _cel
        if _cel is not None or not CELERY_OK: return _cel
        try:
            from core.config import get_celery_broker_url, get_celery_result_backend, mask_redis_url
            b = get_celery_broker_url(); r = get_celery_result_backend(); log.info(f"[WebAPI] Celery init: {mask_redis_url(b)}")
            _cel = Celery('binmind_api', broker=b, backend=r, broker_connection_retry_on_startup=True)
            _cel.conf.update(task_serializer='json', accept_content=['json'], result_serializer='json', timezone='Asia/Shanghai', enable_utc=True, task_track_started=True, task_time_limit=Config.CELERY_TASK_TIME_LIMIT, task_soft_time_limit=Config.CELERY_TASK_SOFT_TIME_LIMIT, worker_prefetch_multiplier=1, worker_max_tasks_per_child=Config.WORKER_MAX_TASKS_PER_CHILD, task_default_queue=Config.CELERY_TASK_QUEUE, task_routes={'modules.worker.analyze_binary_high': {'queue': f'{Config.CELERY_TASK_QUEUE}_high'}, 'modules.worker.analyze_binary_medium': {'queue': f'{Config.CELERY_TASK_QUEUE}_medium'}, 'modules.worker.analyze_binary_low': {'queue': f'{Config.CELERY_TASK_QUEUE}_low'}}, task_default_priority=5, task_acks_late=True, task_reject_on_worker_lost=True); return _cel
        except Exception as e: log.error(f"[WebAPI] Celery fail: {e}"); return None

    def _retrieve_redis():
        if not REDIS_OK: return None
        try:
            from core.config import get_celery_broker_url; from urllib.parse import urlparse
            p = urlparse(get_celery_broker_url()); db = 0
            with suppress(ValueError, IndexError): db = int(p.path.lstrip('/').split('/')[0])
            c = redis.Redis(host=p.hostname, port=p.port or 6379, password=p.password, db=db, decode_responses=True); c.ping(); return c
        except Exception as e: log.warning(f"[WebAPI] Redis fail: {e}"); return None

    def _cluster_status():
        r = _retrieve_redis()
        if r is None: return {'timestamp': datetime.now().isoformat(), 'workers': [], 'total_workers': 0, 'active_workers': 0, 'busy_workers': 0, 'error': 'Redis N/A'}
        try:
            aw = r.smembers('binmind:workers:active'); ws = []; now = datetime.now(); ac = bc = 0; wids = list(aw); j = 0
            while j < len(wids):
                wid = wids[j]; j += 1
                if not r.exists(f"binmind:worker:{wid}"): continue
                d = r.hgetall(f"binmind:worker:{wid}")
                if not d: continue
                lbs = d.get('last_heartbeat', ''); on = False
                if lbs:
                    with suppress(Exception): on = (now - datetime.fromisoformat(lbs)) < timedelta(seconds=Config.WORKER_TIMEOUT)
                sv = d.get('status', 'unknown')
                if on: ac += 1; sv == 'busy' and (bc := bc + 1)
                else: sv = 'offline'
                import json as jm
                with suppress(Exception): tg = jm.loads(d.get('tags', '[]')) if d.get('tags', '[]') else []
                ws.append({'worker_id': wid, 'hostname': d.get('hostname', ''), 'pid': int(d.get('pid', '0')), 'status': sv, 'is_online': on, 'current_task': d.get('current_task', ''), 'tasks_completed': int(d.get('tasks_completed', '0')), 'tasks_failed': int(d.get('tasks_failed', '0')), 'load_average': float(d.get('load_average', '0.0')), 'memory_usage_mb': float(d.get('memory_usage_mb', '0.0')), 'tags': tg, 'started_at': d.get('started_at', ''), 'last_heartbeat': lbs})
            ws.sort(key=lambda x: x['hostname'])
            return {'timestamp': datetime.now().isoformat(), 'workers': ws, 'total_workers': len(ws), 'active_workers': ac, 'busy_workers': bc, 'timeout_seconds': Config.WORKER_TIMEOUT}
        except Exception as e: log.error(f"[WebAPI] cluster fail: {e}"); return {'timestamp': datetime.now().isoformat(), 'workers': [], 'total_workers': 0, 'active_workers': 0, 'busy_workers': 0, 'error': str(e)}

    def _run_task(tid, req):
        if tid is None or req is None: log.error("[Runner] nil"); return
        from core.report import ReportGenerator
        log.info(f"[Runner] start: {tid}")
        try:
            TASK_MGR.update_task(tid, status='running', progress=5, message='Init...'); rd = os.path.join(TASK_MGR._d or '', tid, 'reports'); os.makedirs(rd, exist_ok=True)
            bn = req.binary_name; bi = {'binary_path': bn, 'binary_name': bn, 'binary_format': req.binary_format or 'ELF', 'arch': req.architecture or 'amd64', 'bits': 64 if req.architecture in ['amd64', 'x86_64'] else 32, 'checksec': {}, 'symbols': {}, 'imports': [], 'strings': []}
            TASK_MGR.update_task(tid, progress=20, message='Metadata...'); fa = []; fns = req.function_names or ['main']; fi = 0
            from core.decompiler import decompile_function
            while fi < len(fns):
                fn = fns[fi]; p = 20 + (fi / len(fns) * 40); fi += 1; TASK_MGR.update_task(tid, progress=int(p), message=f'Analyzing: {fn}...')
                dr = decompile_function(bn, fn)
                pc = dr.get('pseudocode') if isinstance(dr, dict) else ''
                if not pc:
                    pc = f'// 反编译失败: {fn} (r2/Ghidra 不可用或函数未找到)'
                fa.append({'function_name': fn, 'pseudocode': pc, 'analysis': {'vulnerabilities': [], 'risk_level': 'Low', 'summary': 'done'}})
            TASK_MGR.update_task(tid, progress=70, message='Report...'); rg = ReportGenerator(output_dir=rd); rp = {}
            if 'md' in req.report_formats: rp['markdown'] = rg.generate_report_rp(binary_path=bn, binary_info=bi, decomp_results=fa, crash_analysis=None, exploit_result=None)
            if 'json' in req.report_formats: rp['json'] = rg.generate_json_report_rp(binary_path=bn, binary_info=bi, decomp_results=fa, crash_analysis=None, exploit_result=None)
            if 'html' in req.report_formats: rp['html'] = rg.generate_html_report_rp(binary_path=bn, binary_info=bi, decomp_results=fa, crash_analysis=None, exploit_result=None)
            TASK_MGR.update_task(tid, status='completed', progress=100, message='done', result={'binary_info': bi, 'function_analyses': fa, 'reports': rp}); log.info(f"[Runner] done: {tid}")
        except Exception as e: log.error(f"[Runner] fail: {e}"); TASK_MGR.update_task(tid, status='failed', progress=100, message=f'fail: {e}')

    _collab = False
    def set_collab(v): global _collab; _collab = v
    def _routes(app, rts):
        if app is None: return
        for s in rts:
            if s.get('is_websocket'): app.add_api_websocket_route(s['path'], s['endpoint'])
            else:
                kw = {}
                if s.get('response_model'): kw['response_model'] = s['response_model']
                app.add_api_route(s['path'], s['endpoint'], methods=s.get('methods', ['GET']), **kw)
        log.info(f"[WebAPI] {len(rts)} routes")

    def create_app():
        app = FastAPI(title="BinMind Binary Vulnerability Analysis API", version="1.0.0", docs_url="/docs", redoc_url="/redoc")
        app.add_middleware(CORSMiddleware, allow_origins=os.getenv('CORS_ORIGINS', '*').split(','), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

        @app.middleware("http")
        async def _mw_trace(req: Request, nx):
            rid = _gen_request_id()[:8]; suppress(Exception)(_rid.set(rid) if hasattr(_rid, 'set') else setattr(_rid, 'rid', rid))
            r = await nx(req); r.headers["X-Request-ID"] = rid
            if req.method == "GET" and not req.url.path.startswith("/api/auth"): r.headers["Cache-Control"] = "private, max-age=30"
            return r

        @app.middleware("http")
        async def _mw_ratelimit(req: Request, nx):
            if not _g_tb.consume(): return JSONResponse(status_code=429, content={"success": False, "message": "Rate limited"})
            return await nx(req)

        import signal as _sig; _sig.signal(_sig.SIGTERM, lambda *_: TASK_MGR.cleanup(0)); _sig.signal(_sig.SIGINT, lambda *_: TASK_MGR.cleanup(0))

        @app.on_event("startup")
        async def _startup():
            log.info("[WebAPI] Starting..."); os.makedirs(Config.DATA_DIR, exist_ok=True)
            import asyncio
            async def _cl():
                while True: await asyncio.sleep(3600); TASK_MGR.cleanup()
            with suppress(Exception): asyncio.create_task(_cl())

        oa2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

        async def _cur_user(token: str = Depends(oa2)):
            if not _collab or not Config.REQUIRE_AUTH: return None
            if not token: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth required", headers={"WWW-Authenticate": "Bearer"})
            try:
                from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); u = cm.get_user_from_token(token)
                if not u: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
                return u
            except HTTPException: raise
            except Exception as e: log.error(f"[Auth] {e}"); raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth failed", headers={"WWW-Authenticate": "Bearer"})

        async def _admin(u=Depends(_cur_user)):
            if not _collab or not Config.REQUIRE_AUTH: return u
            if not u: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth required")
            try: from collaboration.collaboration import UserRole
            except ImportError as e: log.error(f"[admin] {e}"); raise HTTPException(503, detail="collaboration 模块不可用")
            if u.role != UserRole.ADMIN: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
            return u

        async def _reg(req: RegisterRequest):
            if not _collab: raise HTTPException(403, detail="collab off")
            try:
                from collaboration.collaboration import CollaborationManager, UserRole; cm = CollaborationManager()
                r = UserRole(req.role.upper()) if req.role else UserRole.VIEWER; ok, uid = cm.register_user(req.username, req.password, r)
                return APIResponse(success=ok, message="ok" if ok else uid, data={"user_id": uid, "username": req.username} if ok else None)
            except Exception as e: log.error(f"[reg] {e}"); raise HTTPException(500, str(e))

        async def _login(fd: OAuth2PasswordRequestForm = Depends()):
            if not _collab: raise HTTPException(403, detail="collab off")
            try:
                from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); ok, tok = cm.authenticate_user(fd.username, fd.password)
                if ok: return {"access_token": tok, "token_type": "bearer", "username": fd.username}
                raise HTTPException(401, detail="bad credentials", headers={"WWW-Authenticate": "Bearer"})
            except Exception as e: log.error(f"[login] {e}"); raise HTTPException(500, str(e))

        async def _me(u=Depends(_cur_user)):
            if not _collab or not u: return APIResponse(success=True, message="auth disabled", data=None)
            return APIResponse(success=True, data={"user_id": u.user_id, "username": u.username, "role": u.role.value, "created_at": u.created_at})

        async def _list_users(u=Depends(_admin)):
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); us = cm.list_users(); return APIResponse(success=True, message=f"{len(us)} user(s)", data={"users": us})
            except Exception as e: log.error(f"[users] {e}"); raise HTTPException(500, str(e))

        async def _del_user(uid: str, cu=Depends(_admin)):
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); ok, msg = cm.delete_user(uid); return APIResponse(success=ok, message=msg)
            except Exception as e: log.error(f"[del] {e}"); raise HTTPException(500, str(e))

        async def _upd_role(uid: str, role: str, cu=Depends(_admin)):
            try: from collaboration.collaboration import CollaborationManager, UserRole; cm = CollaborationManager(); ok, msg = cm.update_user_role(uid, UserRole(role.upper())); return APIResponse(success=ok, message=msg)
            except ValueError: raise HTTPException(400, detail="bad role")
            except Exception as e: log.error(f"[role] {e}"); raise HTTPException(500, str(e))

        async def _invite(pid: str, req: ProjectInviteRequest, u=Depends(_cur_user)):
            if not _collab: raise HTTPException(403, detail="collab off")
            try: from collaboration.collaboration import CollaborationManager, UserRole; cm = CollaborationManager(); ok, msg = cm.invite_user_to_project(pid, req.username, UserRole(req.role.upper()), u.user_id if u else None); return APIResponse(success=ok, message=msg)
            except Exception as e: log.error(f"[inv] {e}"); raise HTTPException(500, str(e))

        async def _members(pid: str, u=Depends(_cur_user)):
            if not _collab: raise HTTPException(403, detail="collab off")
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); ms = cm.get_project_members(pid); return APIResponse(success=True, data={"members": ms})
            except Exception as e: log.error(f"[mem] {e}"); raise HTTPException(500, str(e))

        async def _add_comment(req: CommentRequest, u=Depends(_cur_user)):
            if not _collab: raise HTTPException(403, detail="collab off")
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); ok, cid = cm.add_comment(req.content, req.target_type, req.target_id, u.user_id if u else None); return APIResponse(success=ok, message="ok" if ok else cid, data={"comment_id": cid} if ok else None)
            except Exception as e: log.error(f"[cmt] {e}"); raise HTTPException(500, str(e))

        async def _get_comments(tt: str, tid: str):
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); cs = cm.get_comments(tt, tid); return APIResponse(success=True, data={"comments": cs})
            except Exception as e: log.error(f"[cmts] {e}"); raise HTTPException(500, str(e))

        async def _upd_vuln(vid: int, req: VulnerabilityStatusRequest, u=Depends(_cur_user)):
            if not _collab: raise HTTPException(403, detail="collab off")
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); ok, msg = cm.update_vulnerability_status(vid, req.status, u.user_id if u else None); return APIResponse(success=ok, message=msg)
            except Exception as e: log.error(f"[vul] {e}"); raise HTTPException(500, str(e))

        async def _audit(page=0, limit=100, u=Depends(_admin)):
            try: from collaboration.collaboration import CollaborationManager; cm = CollaborationManager(); logs = cm.get_audit_logs(page, limit); return APIResponse(success=True, data={"logs": logs, "page": page, "limit": limit})
            except Exception as e: log.error(f"[aud] {e}"); raise HTTPException(500, str(e))

        async def _root():
            return {"name": "BinMind", "version": "1.0.0", "status": "running", "timestamp": datetime.now().isoformat()}

        async def _health():
            r = _retrieve_redis(); comp = {"redis": "ok" if r else "degraded", "celery": "ok" if CELERY_OK and _compute_cel() else "degraded", "tasks": "ok"}
            ok = all(v == "ok" for v in comp.values())
            return {"status": "healthy" if ok else "degraded", "timestamp": datetime.now().isoformat(), "components": comp}

        async def _analyze(req: AnalysisRequest, bg: BackgroundTasks):
            try: tid = TASK_MGR.create_task(req); bg.add_task(_run_task, tid, req); return APIResponse(success=True, message="submitted", data={"task_id": tid, "status": "pending"})
            except Exception as e: log.error(f"[analyze] {e}"); raise HTTPException(500, str(e))

        async def _upload(file: UploadFile = File(...), bg: BackgroundTasks = None):
            try:
                if file is None or file.filename is None: raise HTTPException(400, "empty")
                ud = os.path.join(TASK_MGR._d or '', 'uploads'); os.makedirs(ud, exist_ok=True); fh = hashlib.sha256(); fp = os.path.join(ud, file.filename)
                with open(fp, 'wb') as f:
                    while c := await file.read(8192): fh.update(c); f.write(c)
                hh = fh.hexdigest(); req = AnalysisRequest(binary_name=file.filename, binary_hash=hh, report_formats=['md', 'html', 'json']); tid = TASK_MGR.create_task(req)
                if bg is None: raise HTTPException(500, "no bg")
                bg.add_task(_run_task, tid, req); return APIResponse(success=True, message="uploaded", data={"task_id": tid, "file_name": file.filename, "file_hash": hh})
            except Exception as e: log.error(f"[upload] {e}"); raise HTTPException(500, str(e))

        async def _tasks(status=None, limit=100):
            try: ts = TASK_MGR.list_tasks(status, limit); return APIResponse(success=True, data={"tasks": ts, "nCount": len(ts)})
            except Exception as e: log.error(f"[tasks] {e}"); raise HTTPException(500, str(e))

        async def _task_status(tid: str):
            t = TASK_MGR.get_task(tid)
            if not t: raise HTTPException(404, f"not found: {tid}")
            return APIResponse(success=True, data=t)

        async def _cancel(tid: str):
            t = TASK_MGR.get_task(tid)
            if not t: raise HTTPException(404, f"not found: {tid}")
            TASK_MGR.update_task(tid, status='cancelled'); return APIResponse(success=True, data={"task_id": tid})

        async def _reports(tid: str):
            t = TASK_MGR.get_task(tid)
            if not t: raise HTTPException(404, f"not found: {tid}")
            if t.get('status') != 'completed': raise HTTPException(400, "not done")
            rps = t.get('result', {}).get('reports', {})
            return APIResponse(success=True, data={"task_id": tid, "reports": [{"format": f, "path": p} for f, p in rps.items()]})

        async def _download(tid: str, fmt: str):
            t = TASK_MGR.get_task(tid)
            if not t: raise HTTPException(404, f"not found: {tid}")
            rps = t.get('result', {}).get('reports', {})
            if fmt not in rps: raise HTTPException(404, f"format {fmt} not found")
            rp = rps[fmt]
            if rp is None or not os.path.exists(rp): raise HTTPException(404, "file not found")
            mt = {'md': 'text/markdown', 'json': 'application/json', 'html': 'text/html', 'pdf': 'application/pdf'}
            return FileResponse(path=rp, filename=os.path.basename(rp), media_type=mt.get(fmt, 'application/octet-stream'))

        async def _vulns(q: VulnerabilityQuery):
            try: db = VulnerabilityDatabase(); r = db.search_by_function(q.function_name, q.limit) if q.function_name else db.search_by_vulnerability_type(q.vulnerability_type, q.limit) if q.vulnerability_type else db.get_all(q.limit, q.offset); return APIResponse(success=True, data={"vulnerabilities": r, "nCount": len(r)})
            except Exception as e: log.error(f"[vulns] {e}"); raise HTTPException(500, str(e))

        async def _vuln_stats():
            try: db = VulnerabilityDatabase(); return APIResponse(success=True, data=db.get_statistics())
            except Exception as e: log.error(f"[vstat] {e}"); raise HTTPException(500, str(e))

        async def _vuln(vid: int):
            try:
                db = VulnerabilityDatabase(); v = db.get_by_id(vid)
                if not v: raise HTTPException(404, f"not found: {vid}")
                return APIResponse(success=True, data=v)
            except HTTPException: raise
            except Exception as e: log.error(f"[vuln] {e}"); raise HTTPException(500, str(e))

        async def _ext_vulns(pkg=None, cve=None, bname=None, src='all'):
            try:
                if src and src.lower() not in VALID_SOURCES: raise HTTPException(400, f"bad source: {src}")
                db = VulnerabilityDatabase(); r = db.query_all_external(pkg, cve, bname, src, True, True); return APIResponse(success=True, data=r)
            except HTTPException: raise
            except Exception as e: log.error(f"[ext] {e}"); raise HTTPException(500, str(e))

        async def _create_project(req: ProjectCreateRequest):
            try: from collaboration.project_manager import ProjectManager; pm = ProjectManager(); pid = pm.create_project(req.name, req.binary_path); return APIResponse(success=True, data={"project_id": pid})
            except Exception as e: log.error(f"[cp] {e}"); raise HTTPException(500, str(e))

        async def _list_projects():
            try: from collaboration.project_manager import ProjectManager; pm = ProjectManager(); ps = pm.list_projects(); return APIResponse(success=True, data={"projects": ps, "nCount": len(ps)})
            except Exception as e: log.error(f"[lp] {e}"); raise HTTPException(500, str(e))

        async def _get_project(pid: str):
            try:
                from collaboration.project_manager import ProjectManager; pm = ProjectManager(); p = pm.get_project_metadata(pid)
                if not p: raise HTTPException(404, f"not found: {pid}")
                st = pm.load_project(pid); return APIResponse(success=True, data={"project": p, "state": st.to_dict() if st else None})
            except HTTPException: raise
            except Exception as e: log.error(f"[gp] {e}"); raise HTTPException(500, str(e))

        async def _resume(pid: str, bg: BackgroundTasks):
            try:
                from collaboration.project_manager import ProjectManager; pm = ProjectManager(); p = pm.get_project_metadata(pid)
                if not p: raise HTTPException(404, f"not found: {pid}")
                st = pm.load_project(pid)
                if not st: raise HTTPException(400, "no state")
                if not p.get('binary_path') or not os.path.exists(p['binary_path']): raise HTTPException(400, "no binary")
                async def _r(): from core.pipeline import run_pipeline; run_pipeline(binary_path=p['binary_path'], project_name=p.get('name'), project_resume=True)
                bg.add_task(_r); return APIResponse(success=True, data={"project_id": pid, "status": "resuming"})
            except HTTPException: raise
            except Exception as e: log.error(f"[resume] {e}"); raise HTTPException(500, str(e))

        async def _del_project(pid: str):
            try:
                from collaboration.project_manager import ProjectManager; pm = ProjectManager(); p = pm.get_project_metadata(pid)
                if not p: raise HTTPException(404, f"not found: {pid}")
                ok = pm.delete_project(pid); return APIResponse(success=ok, message="deleted" if ok else "fail", data={"project_id": pid})
            except HTTPException: raise
            except Exception as e: log.error(f"[dp] {e}"); raise HTTPException(500, str(e))

        FUZZ = {}
        async def _fuzz_start(req: FuzzStartRequest):
            try:
                log.info(f"[Fuzz] {req.binary_path}"); fm = FuzzManager(req.binary_path, req.fuzzer_type, req.corpus_path, req.output_dir, req.use_sandbox); r = fm.start(req.timeout, req.max_crashes, req.cpu_limit, req.memory_limit)
                if r.get('success'): FUZZ[fm.session_id] = fm; return APIResponse(success=True, data={"session_id": fm.session_id, "fuzzer_type": fm.fuzzer_type})
                return APIResponse(success=False, data={"error": r.get('error')})
            except Exception as e: log.error(f"[fuzz] {e}"); raise HTTPException(500, str(e))

        async def _fuzz_status(sid: str):
            if sid not in FUZZ: raise HTTPException(404, f"not found: {sid}")
            return APIResponse(success=True, data=FUZZ[sid].get_status())

        async def _fuzz_crashes(sid: str, limit=100):
            if sid not in FUZZ: raise HTTPException(404, f"not found: {sid}")
            cs = FUZZ[sid].get_crashes(limit); return APIResponse(success=True, data={"crashes": cs})

        async def _fuzz_stop(sid: str):
            if sid not in FUZZ: raise HTTPException(404, f"not found: {sid}")
            r = FUZZ[sid].stop()
            if r.get('success'): return APIResponse(success=True, data={"session_id": sid, "crashes": r.get('crashes_found', 0)})
            return APIResponse(success=False, data={"error": r.get('error')})

        async def _fuzz_list():
            ss = []; ks = list(FUZZ.keys()); sk = 0
            while sk < len(ks): sid = ks[sk]; fm = FUZZ[sid]; sk += 1; st = fm.get_status(); ss.append({"session_id": sid, "status": st.get('status'), "binary_path": st.get('binary_path'), "fuzzer_type": st.get('fuzzer_type'), "crashes": st.get('crashes_found')})
            return APIResponse(success=True, data={"sessions": ss})

        async def _cluster_ep():
            try: return ClusterStatus(**_cluster_status())
            except Exception as e: log.error(f"[cluster] {e}"); raise HTTPException(500, str(e))

        async def _dist_analyze(req: DistributedAnalysisRequest):
            if not CELERY_OK: raise HTTPException(503, "no celery")
            try:
                cel = _compute_cel()
                if cel is None: raise HTTPException(503, "no broker")
                if not os.path.exists(req.binary_path): raise HTTPException(400, f"no file: {req.binary_path}")
                opts = req.options or {}; req.functions and opts.update({'functions': req.functions}); opts['use_cache'] = req.use_cache
                tfm = {'high': 'modules.worker.analyze_binary_high', 'medium': 'modules.worker.analyze_binary_medium', 'low': 'modules.worker.analyze_binary_low'}; tn = tfm.get(req.priority.lower(), 'modules.worker.analyze_binary_medium')
                t = cel.send_task(tn, args=[req.binary_path], kwargs=opts); log.info(f"[Dist] {t.id} {req.priority}"); return APIResponse(success=True, data={"task_id": t.id, "priority": req.priority})
            except HTTPException: raise
            except Exception as e: log.error(f"[dist] {e}"); raise HTTPException(500, str(e))

        async def _dist_status(tid: str):
            if not CELERY_OK: raise HTTPException(503, "no celery")
            try:
                cel = _compute_cel()
                if cel is None: raise HTTPException(503, "no broker")
                r = AsyncResult(tid, app=cel); d = {"task_id": tid, "status": r.status, "ready": r.ready(), "successful": r.successful() if r.ready() else None}
                if r.ready():
                    try: d["result" if r.successful() else "error"] = r.result if r.successful() else str(r.result)
                    except Exception as e: d["error"] = str(e)
                return APIResponse(success=True, data=d)
            except HTTPException: raise
            except Exception as e: log.error(f"[dstat] {e}"); raise HTTPException(500, str(e))

        async def _dist_cancel(tid: str):
            if not CELERY_OK: raise HTTPException(503, "no celery")
            try:
                cel = _compute_cel()
                if cel is None: raise HTTPException(503, "no broker")
                AsyncResult(tid, app=cel).revoke(terminate=True); return APIResponse(success=True, data={"task_id": tid})
            except HTTPException: raise
            except Exception as e: log.error(f"[dcancel] {e}"); raise HTTPException(500, str(e))

        async def _dist_queues():
            if not CELERY_OK: raise HTTPException(503, "no celery")
            try:
                cel = _compute_cel()
                if cel is None: raise HTTPException(503, "no broker")
                insp = cel.control.inspect(); aq = set(); stats = insp.stats() or {}; ac = insp.active() or {}; rs = insp.reserved() or {}
                for ws in stats.values():
                    if 'pool' in ws:
                        for q in ws['pool'].get('queues', []): aq.add(q)
                for wt in list(ac.values()) + list(rs.values()):
                    for t in wt:
                        if 'delivery_info' in t: aq.add(t['delivery_info'].get('routing_key', 'celery'))
                dqs = [f'{Config.CELERY_TASK_QUEUE}', f'{Config.CELERY_TASK_QUEUE}_high', f'{Config.CELERY_TASK_QUEUE}_medium', f'{Config.CELERY_TASK_QUEUE}_low']
                qi = [{'name': q, 'is_active': q in aq, 'workers': sum(1 for w in stats.values() if 'pool' in w and q in w['pool'].get('queues', []))} for q in dqs]
                return APIResponse(success=True, data={"queues": qi, "default": Config.CELERY_TASK_QUEUE})
            except HTTPException: raise
            except Exception as e: log.error(f"[dq] {e}"); raise HTTPException(500, str(e))

        async def _exp_verify(tid: str, vc=5, bg: BackgroundTasks = None):
            t = TASK_MGR.get_task(tid)
            if not t: raise HTTPException(404, f"not found: {tid}")
            if t.get('status') != 'completed': raise HTTPException(400, "not done")
            er = t.get('result', {}).get('exploit_result')
            if not er or not er.get('success'): raise HTTPException(400, "no exploit")
            try:
                from exploit.exploit_verifier import ExploitVerifier; ev = ExploitVerifier()
                def _v(): r = ev.verify_exploit(er.get('script_content', ''), t.get('request', {}).get('binary_name', ''), vc); TASK_MGR.update_task(tid, verification_result=r)
                if bg is None: raise HTTPException(500, "no bg")
                bg.add_task(_v); return APIResponse(success=True, data={"task_id": tid, "verify_count": vc, "status": "running"})
            except Exception as e: log.error(f"[exp] {e}"); raise HTTPException(500, str(e))

        async def _exp_status(tid: str):
            t = TASK_MGR.get_task(tid)
            if not t: raise HTTPException(404, f"not found: {tid}")
            vr = t.get('verification_result')
            if not vr: return APIResponse(success=True, data={"task_id": tid, "status": "pending"})
            return APIResponse(success=True, data={"task_id": tid, "status": "completed", "verification_result": vr})

        async def _ti_query(req: ThreatIntelQuery, bg: BackgroundTasks = None):
            try:
                tc = ThreatIntelClient(providers=[req.provider])
                def _q(): rs = tc.query_by_hash(req.query_value, req.task_id or '', req.anonymize) if req.query_type == 'hash' else tc.query_by_cve(req.query_value, req.task_id or '') if req.query_type == 'cve' else tc.query_by_indicator(req.query_value, req.task_id or ''); db = VulnerabilityDatabase(); tc.save_results(rs, db, req.task_id or ''); return [r.to_dict() for r in rs]
                if bg is None: raise HTTPException(500, "no bg")
                bg.add_task(_q); return APIResponse(success=True, data={"query_id": f"ti_{uuid.uuid4().hex[:8]}", "status": "running"})
            except Exception as e: log.error(f"[ti] {e}"); raise HTTPException(500, str(e))

        async def _ti_results(tid: str):
            try: db = VulnerabilityDatabase(); rs = db.get_threat_intel_results(tid); return APIResponse(success=True, data={"task_id": tid, "results": rs})
            except Exception as e: log.error(f"[tir] {e}"); raise HTTPException(500, str(e))

        async def _ag_reg(req: AgentRegisterRequest):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try: tok = agm.register_agent(req.agent_id, req.capabilities, req.hostname, req.pid); return APIResponse(success=True, data={"agent_id": req.agent_id, "token": tok})
            except Exception as e: log.error(f"[ag] {e}"); raise HTTPException(500, str(e))

        async def _ag_tasks(token: str):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try: return {"tasks": [t.to_dict() for t in agm.get_pending_tasks()]}
            except Exception as e: log.error(f"[agts] {e}"); raise HTTPException(500, str(e))

        async def _ag_results(aid: str, token: str, tid: str, result: Dict[str, Any]):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try:
                if not agm.validate_token(aid, token): raise HTTPException(401, "bad token")
                agm.update_task_result(tid, result); return APIResponse(success=True, data={"task_id": tid})
            except HTTPException: raise
            except Exception as e: log.error(f"[agr] {e}"); raise HTTPException(500, str(e))

        async def _ag_hb(aid: str, token: str, ts=None, sv="online"):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try:
                if not agm.validate_token(aid, token): raise HTTPException(401, "bad token")
                agm.update_heartbeat(aid); return APIResponse(success=True, data={"agent_id": aid})
            except HTTPException: raise
            except Exception as e: log.error(f"[aghb] {e}"); raise HTTPException(500, str(e))

        async def _ag_list(au=Depends(_admin)):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try: ags = agm.get_online_agents(); return APIResponse(success=True, data={"agents": ags, "nCount": len(ags)})
            except Exception as e: log.error(f"[agl] {e}"); raise HTTPException(500, str(e))

        async def _ag_info(aid: str, au=Depends(_admin)):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try:
                a = agm.get_agent_by_id(aid)
                if not a: raise HTTPException(404, f"not found: {aid}")
                return APIResponse(success=True, data=a)
            except HTTPException: raise
            except Exception as e: log.error(f"[agi] {e}"); raise HTTPException(500, str(e))

        async def _ag_revoke(aid: str, au=Depends(_admin)):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try:
                ok = agm.revoke_agent(aid)
                if ok: return APIResponse(success=True, message=f"revoked: {aid}")
                raise HTTPException(404, f"not found: {aid}")
            except HTTPException: raise
            except Exception as e: log.error(f"[agrv] {e}"); raise HTTPException(500, str(e))

        async def _ag_cmd(aid: str, req: AgentCommandRequest, au=Depends(_admin)):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try:
                a = agm.get_agent_by_id(aid)
                if not a: raise HTTPException(404, f"not found: {aid}")
                if a.get('status') != 'online': raise HTTPException(400, f"offline: {aid}")
                log.info(f"[agcmd] {aid}: {req.command}"); return APIResponse(success=True, data={"agent_id": aid, "command": req.command})
            except HTTPException: raise
            except Exception as e: log.error(f"[agc] {e}"); raise HTTPException(500, str(e))

        async def _ag_create_task(req: AgentTaskRequest, au=Depends(_admin)):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try: tid = agm.create_task(req.task_type, req.binary_path, **(req.options or {})); return APIResponse(success=True, data={"task_id": tid})
            except Exception as e: log.error(f"[agct] {e}"); raise HTTPException(500, str(e))

        async def _ag_assign(tid: str, aid: str, au=Depends(_admin)):
            if not RAGENT_OK or not agm: raise HTTPException(status.HTTP_503, "agent N/A")
            try:
                ok = agm.assign_task_to_agent(tid, aid)
                if ok: return APIResponse(success=True, message=f"{tid} -> {aid}")
                raise HTTPException(400, "assign fail")
            except HTTPException: raise
            except Exception as e: log.error(f"[aga] {e}"); raise HTTPException(500, str(e))

        async def _ws(ws: WebSocket, token=None):
            if not WS_OK or not RAGENT_OK or not agm: await ws.close(code=1012); return
            await ws.accept(); aid = None
            try:
                while True:
                    d = await ws.receive_json(); mt = d.get('type')
                    match mt:
                        case 'heartbeat':
                            if (aid := d.get('agent_id')) and token and agm.validate_token(aid, token): agm.update_heartbeat(aid); await ws.send_json({'type': 'pong', 'timestamp': datetime.now().isoformat()})
                        case 'task_result':
                            if (aid := d.get('agent_id')) and token and agm.validate_token(aid, token): agm.update_task_result(d.get('task_id'), d.get('result'))
                        case 'capabilities': pass
                        case _: log.warning(f"[WS] unknown: {mt}")
            except WebSocketDisconnect: aid and log.info(f"[WS] {aid} disconnected")
            except Exception as e: log.error(f"[WS] {e}")

        g_r = [
            {'path': '/', 'endpoint': _root, 'methods': ['GET']}, {'path': '/api/health', 'endpoint': _health, 'methods': ['GET']},
            {'path': '/api/auth/register', 'endpoint': _reg, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/auth/login', 'endpoint': _login, 'methods': ['POST']}, {'path': '/api/auth/me', 'endpoint': _me, 'methods': ['GET'], 'response_model': APIResponse},
            {'path': '/api/users', 'endpoint': _list_users, 'methods': ['GET'], 'response_model': APIResponse}, {'path': '/api/users/{user_id}', 'endpoint': _del_user, 'methods': ['DELETE'], 'response_model': APIResponse}, {'path': '/api/users/{user_id}/role', 'endpoint': _upd_role, 'methods': ['PUT'], 'response_model': APIResponse},
            {'path': '/api/projects/{project_id}/invite', 'endpoint': _invite, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/projects/{project_id}/members', 'endpoint': _members, 'methods': ['GET'], 'response_model': APIResponse},
            {'path': '/api/comments', 'endpoint': _add_comment, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/comments/{target_type}/{target_id}', 'endpoint': _get_comments, 'methods': ['GET'], 'response_model': APIResponse},
            {'path': '/api/vulnerabilities/{vuln_id}/status', 'endpoint': _upd_vuln, 'methods': ['PUT'], 'response_model': APIResponse}, {'path': '/api/audit/logs', 'endpoint': _audit, 'methods': ['GET'], 'response_model': APIResponse},
            {'path': '/api/analyze', 'endpoint': _analyze, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/analyze/upload', 'endpoint': _upload, 'methods': ['POST']},
            {'path': '/api/tasks', 'endpoint': _tasks, 'methods': ['GET']}, {'path': '/api/tasks/{task_id}', 'endpoint': _task_status, 'methods': ['GET']}, {'path': '/api/tasks/{task_id}', 'endpoint': _cancel, 'methods': ['DELETE']},
            {'path': '/api/reports/{task_id}', 'endpoint': _reports, 'methods': ['GET']}, {'path': '/api/reports/{task_id}/{format}', 'endpoint': _download, 'methods': ['GET']},
            {'path': '/api/vulnerabilities', 'endpoint': _vulns, 'methods': ['POST']}, {'path': '/api/vulnerabilities/stats', 'endpoint': _vuln_stats, 'methods': ['GET']}, {'path': '/api/vulnerabilities/{vuln_id}', 'endpoint': _vuln, 'methods': ['GET']}, {'path': '/api/vulnerabilities/external', 'endpoint': _ext_vulns, 'methods': ['POST']},
            {'path': '/api/projects', 'endpoint': _create_project, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/projects', 'endpoint': _list_projects, 'methods': ['GET'], 'response_model': APIResponse}, {'path': '/api/projects/{project_id}', 'endpoint': _get_project, 'methods': ['GET'], 'response_model': APIResponse}, {'path': '/api/projects/{project_id}/resume', 'endpoint': _resume, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/projects/{project_id}', 'endpoint': _del_project, 'methods': ['DELETE'], 'response_model': APIResponse},
            {'path': '/api/fuzz/start', 'endpoint': _fuzz_start, 'methods': ['POST']}, {'path': '/api/fuzz/status/{session_id}', 'endpoint': _fuzz_status, 'methods': ['GET']}, {'path': '/api/fuzz/crashes/{session_id}', 'endpoint': _fuzz_crashes, 'methods': ['GET']}, {'path': '/api/fuzz/stop/{session_id}', 'endpoint': _fuzz_stop, 'methods': ['POST']}, {'path': '/api/fuzz/list', 'endpoint': _fuzz_list, 'methods': ['GET']},
            {'path': '/api/cluster/status', 'endpoint': _cluster_ep, 'methods': ['GET'], 'response_model': ClusterStatus},
            {'path': '/api/distributed/analyze', 'endpoint': _dist_analyze, 'methods': ['POST']}, {'path': '/api/distributed/status/{task_id}', 'endpoint': _dist_status, 'methods': ['GET']}, {'path': '/api/distributed/cancel/{task_id}', 'endpoint': _dist_cancel, 'methods': ['POST']}, {'path': '/api/distributed/queues', 'endpoint': _dist_queues, 'methods': ['GET']},
            {'path': '/api/tasks/{task_id}/verify', 'endpoint': _exp_verify, 'methods': ['POST']}, {'path': '/api/tasks/{task_id}/verify/status', 'endpoint': _exp_status, 'methods': ['GET']},
            {'path': '/api/threat_intel/query', 'endpoint': _ti_query, 'methods': ['POST']}, {'path': '/api/threat_intel/results/{task_id}', 'endpoint': _ti_results, 'methods': ['GET']},
            {'path': '/api/agents/register', 'endpoint': _ag_reg, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/agents/tasks', 'endpoint': _ag_tasks, 'methods': ['GET']}, {'path': '/api/agents/results', 'endpoint': _ag_results, 'methods': ['POST']}, {'path': '/api/agents/heartbeat', 'endpoint': _ag_hb, 'methods': ['POST']}, {'path': '/api/agents', 'endpoint': _ag_list, 'methods': ['GET'], 'response_model': APIResponse}, {'path': '/api/agents/{agent_id}', 'endpoint': _ag_info, 'methods': ['GET'], 'response_model': APIResponse}, {'path': '/api/agents/{agent_id}', 'endpoint': _ag_revoke, 'methods': ['DELETE'], 'response_model': APIResponse}, {'path': '/api/agents/{agent_id}/command', 'endpoint': _ag_cmd, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/agents/task/create', 'endpoint': _ag_create_task, 'methods': ['POST'], 'response_model': APIResponse}, {'path': '/api/agents/task/{task_id}/assign/{agent_id}', 'endpoint': _ag_assign, 'methods': ['POST'], 'response_model': APIResponse},
            {'path': '/api/agents/ws', 'endpoint': _ws, 'is_websocket': True},
        ]
        _routes(app, g_r); log.info("[WebAPI] app created"); return app

    def start_server(host="0.0.0.0", port=8000, reload=False, collab=False):
        if not FASTAPI_OK: log.error("[WebAPI] not installed"); return
        if collab: set_collab(True)
        app = create_app(); log.info(f"[WebAPI] {host}:{port}"); uvicorn.run(app, host=host, port=port, reload=reload, log_level="info")

    app = create_app()

else:
    def start_server(host="0.0.0.0", port=8000, reload=False): log.error("[WebAPI] FastAPI not installed"); raise ImportError("FastAPI required")
    app = None
