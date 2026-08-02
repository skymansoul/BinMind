# Pipeline infra v0.5 — WorkerPool/Pipeline, ctx mgr, dry-run, timeout guard
import heapq,threading,time,uuid,hashlib,logging,os,json
from enum import Enum,auto; from dataclasses import dataclass,field
from typing import Any,Callable,Dict,List,Optional
from concurrent.futures import ThreadPoolExecutor

logger=logging.getLogger(__name__)
_DM=4096; _DC=80; _DT=600; _SI=30.0
_HAS_PS=False
try: import psutil; _HAS_PS=True
except: psutil=None

def _mu():
    if not _HAS_PS: return 0.0
    try: return psutil.virtual_memory().used/(1024*1024)
    except: return 0.0
def _cu():
    if not _HAS_PS: return 0.0
    try: return psutil.cpu_percent(interval=0.1)
    except: return 0.0
def _tid():
    try: from . import current_trace_id; return current_trace_id()
    except: return'000000000000'
def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

class Status(Enum): PENDING=auto();RUNNING=auto();COMPLETED=auto();FAILED=auto();CANCELLED=auto();TIMED_OUT=auto();DRY_RUN=auto()

@dataclass(order=True)
class Task:
    task_id:str=field(compare=False);task_type:str=field(compare=False);payload:Any=field(compare=False)
    priority:int=5;status:Status=Status.PENDING;created_at:float=field(default_factory=time.time)
    retries:int=0;max_retries:int=3;timeout_sec:float=_DT;op_timeout:float=0.0
    cid:str=field(default_factory=_tid);_seq:int=0;dry_run:bool=False
    def __repr__(self): return f"Task({self.task_id[:8]},{self.task_type})"
    def timed_out(self,st): return(time.time()-st)>self.timeout_sec if self.timeout_sec>0 else False

class TaskQueue:
    def __init__(self,n="dq"): self._h=[]; self._lk=threading.Lock(); self._dd={}; self._ctr=0; self._nm=n; self._cs=set(); self._ti={}
    def _dg(self,tt,pl): return f"{tt}:{hashlib.md5(str(pl).encode()).hexdigest()}"
    def push(self,t):
        with self._lk: d=self._dg(t.task_type,t.payload)
        if d in self._dd: return False
        self._ctr+=1; t._seq=self._ctr; self._dd[d]=t.created_at; self._ti[t.task_id]=t; heapq.heappush(self._h,(t.priority,t._seq,t)); return True
    def pop(self):
        with self._lk:
            while self._h: p,s,t=heapq.heappop(self._h)
            if t.task_id in self._cs: self._cs.discard(t.task_id); self._ti.pop(t.task_id,None); continue
            self._ti.pop(t.task_id,None); return t
        return None
    def repush(self,t,np=None):
        if np is not None: t.priority=np
        with self._lk: self._ti[t.task_id]=t; heapq.heappush(self._h,(t.priority,t._seq,t))
    def remove(self,tid):
        with self._lk:
            if tid in self._ti: self._cs.add(tid); return True
            return False
    def drain(self):
        with self._lk: r=[]
        while self._h: _,_,t=heapq.heappop(self._h)
        if t.task_id not in self._cs: r.append(t)
        self._ti.clear(); self._cs.clear(); return r
    @property
    def size(self): return len(self._h)
    @property
    def is_empty(self): return len(self._h)==0

class WorkerPool:
    def __init__(self,nw=4,q=None,ml=_DM,cl=_DC,tt=_DT,dr=False): self.nw=nw; self.q=q or TaskQueue(); self._hd={}; self._ex=None; self._fs=[]; self._rn=threading.Event(); self._pa=threading.Event(); self._pa.set(); self._st={"c":0,"f":0,"x":0,"r":0,"t":0}; self._sl=threading.Lock(); self._ml=ml; self._cl=cl; self._tt=tt; self._at={}; self._dr=dr
    def __enter__(self): self.start(); return self
    def __exit__(self,*_): self.stop(); return False
    def reg(self,tt,fn): self._hd[tt]=fn
    def start(self):
        if self._ex is not None: return
        self._rn.set(); self._pa.set(); self._ex=ThreadPoolExecutor(max_workers=self.nw); self._fs=[self._ex.submit(self._wl)for _ in range(self.nw)]
    def stop(self):
        self._rn.clear(); self._pa.set()
        if self._ex: self._ex.shutdown(wait=True,cancel_futures=True); self._ex=None
    def pause(self): self._pa.clear()
    def resume(self): self._pa.set()
    @property
    def is_paused(self): return not self._pa.is_set()
    def _th(self): return _HAS_PS and(_mu()>self._ml or _cu()>self._cl)
    def _wl(self):
        try: from . import is_shutting_down,OpTimeout
        except: is_shutting_down=lambda:False; OpTimeout=lambda s,l:object()
        while self._rn.is_set()and not is_shutting_down():
            self._pa.wait()
            if self._th(): time.sleep(1.0); continue
            try: t=self.q.pop()
            except: time.sleep(0.05); continue
            if t is None: time.sleep(0.05); continue
            if self._dr or t.dry_run: t.status=Status.DRY_RUN; _inc('wp.dry',1); continue
            h=self._hd.get(t.task_type)
            if h is None: continue
            st=time.time(); self._at[t.task_id]=st
            try:
                if t.op_timeout>0:
                    with OpTimeout(t.op_timeout,f"Task {t.task_id[:8]}"): t.status=Status.RUNNING; h(t.payload)
                else: t.status=Status.RUNNING; h(t.payload)
                t.status=Status.COMPLETED; self._st["c"]+=1; _inc('wp.ok',1)
            except TimeoutError: t.status=Status.TIMED_OUT; self._st["t"]+=1; _inc('wp.to',1)
            except Exception as e: t.status=Status.FAILED; t.retries+=1; self._st["f"]+=1; _inc('wp.fail',1); logger.error("[%s]fail %s:%s",t.cid[:6],t.task_id[:8],e)
            if t.retries<t.max_retries: self.q.repush(t,np=t.priority+1); self._st["r"]+=1
            finally: self._at.pop(t.task_id,None)
    @property
    def stats(self):
        with self._sl: return dict(self._st)

class BatchRunner:
    def __init__(self,q,p,prog=''): self.q=q; self.p=p; self._cl=threading.Event(); self._pc=None; self._cc=None; self._pf=prog; self._ls=0.0
    def _sv(self,c,t):
        if not self._pf: return
        n=time.time()
        if n-self._ls<_SI: return
        self._ls=n
        try:
            with open(self._pf+'.tmp','w')as f: json.dump({'c':c,'t':t,'ts':n},f)
            os.replace(self._pf+'.tmp',self._pf)
        except OSError: pass
    def run(self,ts,op=None,od=None):
        tot=len(ts); sub=sum(1 for t in ts if not self._cl.is_set()and self.q.push(t))
        for t in ts:
            if self._cl.is_set(): t.status=Status.CANCELLED
        self._pc=op; self._cc=od; st=time.time()
        while True:
            d=self.p.stats["c"]+self.p.stats["f"]+self.p.stats["t"]
            if d>=sub: break
            el=time.time()-st; eta=0
            if d>0: eta=(sub-d)/(d/el)
            if self._pc: self._pc(d,sub,eta)
            self._sv(d,sub)
            if self._cl.is_set(): break; time.sleep(0.1)
        el=time.time()-st
        r={"total":sub,"c":self.p.stats["c"],"f":self.p.stats["f"],"r":self.p.stats["r"],"t":self.p.stats["t"],"x":sum(1 for t in ts if t.status==Status.CANCELLED),"elapsed":el}
        if self._cc: self._cc(r)
        return r
    def cancel(self): self._cl.set()

class Pipeline:
    def __init__(self,n="p"): self.n=n; self._ss=[]; self._dp={}; self._ps=[]; self._dr=False
    def __enter__(self): return self
    def __exit__(self,*_):
        for p in self._ps: p.stop()
        return False
    def dry(self,v=True): self._dr=v
    def add_stage(self,n,fn,w=2,deps=None):
        self._ss.append({"n":n,"h":fn,"w":w,"q":TaskQueue(f"{self.n}/{n}")})
        if deps: self._dp[n]=deps
    def pause(self):
        for p in self._ps: p.pause()
    def resume(self):
        for p in self._ps: p.resume()
    def run(self,it):
        rs={}; cb=it; done=set()
        for i,sd in enumerate(self._ss):
            sn=sd["n"]; um=[d for d in self._dp.get(sn,[])if d not in done]
            if um: logger.warning("stage %s unmet:%s",sn,um); continue
            logger.info("===[%d/%d]:%s [%s]===",i+1,len(self._ss),sn,_tid())
            pl=WorkerPool(sd["w"],sd["q"],dr=self._dr); pl.reg("default",sd["h"]); self._ps.append(pl); pl.start()
            ts=[Task(str(uuid.uuid4()),"default",item if not rs else{**item,"__prev":rs},5,dry_run=self._dr)for item in cb]
            sr=BatchRunner(sd["q"],pl).run(ts); pl.stop(); rs[sn]=sr; done.add(sn)
        return rs

_ac=0
def make_tasks(items,tt="analyze",pri=5,tmo=_DT,dr=False,opto=0.0):
    global _ac; ts=[]
    for item in items: _ac+=1; ts.append(Task(f"{tt}_{_ac}_{uuid.uuid4().hex[:6]}",tt,item,pri,Status.PENDING,time.time(),0,3,tmo,opto,_tid(),_ac,dr))
    return ts
