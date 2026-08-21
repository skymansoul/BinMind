# BinMind v0.5.0 — 协议 classes, timeout guards, 压缩, delta 编码
import importlib,sys,os,json,uuid,hashlib,functools,atexit,threading as _t,signal as _sig,glob as _glob,gzip,lzma
from typing import Protocol,runtime_checkable

__version__="0.5.0"

_ALL_MODULES=["pipeline_infra","kernel_driver","testing_fuzzing","cli","function_inliner","function_boundary","binary_formats","exploit_primitives","memory_heap","ml_features","symbolic_analysis","vuln_management","analysis_depth_estimator","cross_validation","diff_notification"]

class _LazyLoader:
    __slots__=("_n","_l")
    def __init__(self,n): self._n=n; self._l=None
    def __call__(self):
        if self._l is None: self._l=importlib.import_module(self._n)
        return self._l

_LAZY_MODS={m:_LazyLoader(__package__+"."+m) for m in _ALL_MODULES}
def __getattr__(n):
    if n in _LAZY_MODS: return _LAZY_MODS[n]()
    raise AttributeError(f"module {__name__!r} has no attribute {n!r}")
def list_modules(): return[{'name':m,'loaded':_LAZY_MODS[m]._l is not None}for m in _ALL_MODULES]

# //// Plugin 协议 ////
@runtime_checkable
class AnalysisPlugin(Protocol):
    """插件接口协议: 所有动态加载的插件必须实现此接口"""
    __version__:str
    def register_plugin(self)->dict: ...
    def analyze(self,filepath:str,**kwargs)->dict: ...

# trace
_tl=_t.local()
def init_trace(cid=None): c=cid or uuid.uuid4().hex[:12]; _tl.cid=c; _tl.st=__import__('time').time(); return c
def current_trace_id(): return getattr(_tl,'cid','000000000000')
def trace_elapsed(): s=getattr(_tl,'st',0); return __import__('time').time()-s if s else 0.0

# 校验
def validate_path(fn):
    @functools.wraps(fn)
    def w(fp,*a,**kw):
        if not fp or not os.path.exists(str(fp)): raise FileNotFoundError(f"path:{fp}")
        return fn(fp,*a,**kw)
    return w

# 缓存key
def result_cache_key(bp,at):
    h=hashlib.sha256()
    try:
        with open(bp,'rb')as f: h.update(f.read(65536))
    except OSError: pass
    h.update(at.encode()); h.update(__version__.encode()); return h.hexdigest()[:32]

# cleanup
_cbs=[]
def register_cleanup(cb): _cbs.append(cb)
def _run_cbs():
    for cb in reversed(_cbs):
        try: cb()
        except Exception: pass
atexit.register(_run_cbs)

# signals
_sh=[]; _sd=_t.Event()
def on_shutdown(cb): _sh.append(cb)
def is_shutting_down(): return _sd.is_set()
def _hs(sig,_f):
    if _sd.is_set(): os._exit(1)
    _sd.set(); [cb()for cb in reversed(_sh)]; _run_cbs(); os._exit(0)
for _sn in('SIGTERM','SIGINT'):
    try: _sig.signal(getattr(_sig,_sn),_hs)
    except Exception: pass

# features
_ff={}
def feature_flag(n,d=False):
    if n not in _ff: ev=os.environ.get(f'BINMIND_FEATURE_{n.upper()}',''); _ff[n]=ev.lower()in('1','true','yes')if ev else d
    return _ff[n]
def set_feature(n,v): _ff[n]=v

# counters
_ct={}; _cl=_t.Lock()
def inc_counter(n,d=1):
    with _cl: _ct[n]=_ct.get(n,0)+d
def read_counter(n):
    with _cl: return _ct.get(n,0)
def all_counters():
    with _cl: return dict(_ct)

# //// Per-operation timeout guard ////
class OpTimeout:
    """操作超时守卫: 在with块内设置SIGALRM超时(仅Unix), 超时时抛出TimeoutError"""
    def __init__(self,seconds:float,label:str=''): self._s=seconds; self._lb=label
    def __enter__(self):
        if self._s<=0: return self
        try: _sig.signal(_sig.SIGALRM,lambda s,f:exec('raise TimeoutError(self._lb)'))
        except Exception: pass
        try: _sig.alarm(int(self._s))
        except Exception: pass
        return self
    def __exit__(self,*_):
        try: _sig.alarm(0)
        except Exception: pass
        return False

# //// 压缩 辅助函数 ////
def compress_json(data:dict,method:str='gz')->bytes:
    """压缩JSON数据: 'gz'=gzip, 'xz'=lzma, 'none'=raw"""
    raw=json.dumps(data,default=str).encode('utf-8')
    if method=='gz': return gzip.compress(raw,9)
    if method=='xz': return lzma.compress(raw)
    return raw
def decompress_json(blob:bytes,method:str='gz')->dict:
    if method=='gz': return json.loads(gzip.decompress(blob).decode('utf-8'))
    if method=='xz': return json.loads(lzma.decompress(blob).decode('utf-8'))
    return json.loads(blob.decode('utf-8'))

# //// Delta 编码 for diff results ////
def delta_encode(prev:dict,curr:dict)->dict:
    """对两个分析结果字典做delta编码: 只存储变更的键"""
    d={}
    all_keys=set(prev.keys())|set(curr.keys())
    for k in all_keys:
        pv=prev.get(k); cv=curr.get(k)
        if pv!=cv: d[k]=cv
    return d
def delta_apply(base:dict,delta:dict)->dict:
    r=dict(base); r.update(delta); return r

# compat/plugins
_MIN_VERSIONS={'radare2':'5.0.0','capstone':'4.0.0','angr':'9.0.0','z3':'4.8.0'}
def check_compatibility()->dict:
    r={}
    try:
        import subprocess; o=subprocess.run(['r2','-v'],capture_output=True,text=True,timeout=5)
        v=o.stdout.split()[1]if len(o.stdout.split())>1 else'0'; r['radare2']={'ok':v>=_MIN_VERSIONS['radare2'],'v':v}
    except (FileNotFoundError, subprocess.SubprocessError): r['radare2']={'ok':False,'v':'N/A'}
    for mod,mv in[('capstone','4.0.0'),('angr','9.0.0'),('z3','4.8.0')]:
        try: m=importlib.import_module(mod); mv2=getattr(m,'__version__',getattr(m,'VERSION','0')); r[mod]={'ok':str(mv2)>=mv,'v':str(mv2)}
        except (ImportError, AttributeError): r[mod]={'ok':False,'v':'N/A'}
    return r
def discover_plugins(pd=None)->list:
    if pd is None: pd=os.path.join(os.path.dirname(__file__),'plugins')
    if not os.path.isdir(pd): return[]
    pl=[]
    for fp in sorted(_glob.glob(os.path.join(pd,'[!_]*.py'))):
        nm=os.path.splitext(os.path.basename(fp))[0]
        try:
            spec=importlib.util.spec_from_file_location(f"{__package__}.plugins.{nm}",fp)
            mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
            if isinstance(mod,AnalysisPlugin): pl.append({'name':nm,'path':fp,'v':getattr(mod,'__version__','0.1.0'),'proto':True})
        except Exception: pass
    return pl
def layered_config(cli_args=None,env_prefix='BINMIND_')->dict:
    cfg={}
    for k,v in os.environ.items():
        if k.startswith(env_prefix): cfg[k[len(env_prefix):].lower()]=v
    return cfg
def env_report():
    r={'py':sys.version,'bm':__version__,'cid':current_trace_id(),'compat':check_compatibility(),'cap':{},'feats':dict(_ff),'ctrs':all_counters(),'pl':len(discover_plugins())}
    for m in['capstone','angr','z3','psutil','numpy','requests','ssdeep','tlsh']:
        try: importlib.import_module(m); r['cap'][m]=True
        except ImportError: r['cap'][m]=False
    return r

__all__=_ALL_MODULES+["__version__","list_modules","env_report","init_trace","current_trace_id","trace_elapsed","validate_path","result_cache_key","register_cleanup","on_shutdown","is_shutting_down","feature_flag","set_feature","inc_counter","read_counter","all_counters","check_compatibility","discover_plugins","layered_config","AnalysisPlugin","OpTimeout","compress_json","decompress_json","delta_encode","delta_apply"]
