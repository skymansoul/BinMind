# Fuzzing v0.5 — LibFuzzer/AFL++, dry-run, checkpoint, op timeout
import os,sys,json,time,shutil,hashlib,subprocess,threading,logging
from dataclasses import dataclass,field; from typing import Any,Dict,List,Optional

logger=logging.getLogger(__name__)
_CSO={'null-deref':1,'heap-buffer-overflow-read':3,'heap-buffer-overflow':5,'use-after-free':7,'double-free':7,'stack-overflow':8,'segfault':2,'unknown':0}

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class FR: ec:int;uc:int;cp:float;eps:float;el:float=0.0;cfs:List[str]=field(default_factory=list);ro:str="";cs:Dict[str,str]=field(default_factory=dict)
@dataclass class FC: cid:str;t:str;ht:str;sd:str;dur:int;st:str;fgs:List[Dict]=field(default_factory=list);sa:float=0.0;ca:float=0.0;ckpt:str=''

class AFLH:
    def __init__(self,d="/tmp/fh"): self.d=d; os.makedirs(d,exist_ok=True)
    def gen(self,t,it="stdin",tf="LLVMFuzzerTestOneInput",ms=65536):
        src=f"""#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
extern int {tf}(const uint8_t*,size_t);
int main(){{uint8_t b[{ms}];ssize_t n=read(0,b,sizeof(b));if(n>0){tf}(b,(size_t)n);return 0;}}"""
        p=os.path.join(self.d,f"h_{os.path.basename(t)}.c")
        with open(p,"w")as f: f.write(src); return p

class ADG:
    @staticmethod
    def from_strings(bp,out,ml=2,xl=32):
        ts=set()
        try:
            o=subprocess.run(["r2","-q","-c","izzq",bp],capture_output=True,text=True,timeout=30)
            for l in o.stdout.splitlines(): s=l.strip()
            if ml<=len(s)<=xl and all(32<=ord(c)<127 for c in s): ts.add(s)
        except: pass
        if not ts: return 0
        with open(out,"w")as f:
            for t in sorted(ts)[:500]: f.write(f'"{t}"\n')
        return len(ts)

class LFR:
    def __init__(self,t,cd,ad=""): self.t=t; self.cd=cd; self.ad=ad or f"{cd}_a"; [os.makedirs(d,exist_ok=True)for d in(self.cd,self.ad)]
    def run(self,to=3600,j=1,dp=None,dr=False,opto=0):
        if dr: return FR(0,0,0.0,0.0,0.0,ro="DRY-RUN")
        cmd=[self.t,self.cd,f"-max_total_time={to}",f"-jobs={j}",f"-artifact_prefix={self.ad}/"]
        if dp: cmd.append(f"-dict={dp}")
        st=time.time()
        try: p=subprocess.run(cmd,capture_output=True,text=True,timeout=(opto if opto>0 else to+60)); el=time.time()-st
        except subprocess.TimeoutExpired: el=time.time()-st; return FR(-2,0,0.0,0.0,el,ro="TIMEOUT")
        return self._p(p,el)
    def _p(self,p,el):
        o=p.stdout+"\n"+p.stderr; cov=0.0; eps=0.0
        for l in o.splitlines():
            for pt in l.split():
                if"cov:"in pt:
                    try: cov=float(pt.split(":")[1])
                    except: pass
                elif pt.startswith("exec/s:"):
                    try: eps=float(pt.split(":")[1])
                    except: pass
        cfs=[]
        if os.path.isdir(self.ad): cfs=[os.path.join(self.ad,f)for f in os.listdir(self.ad)]
        return FR(p.returncode,len(cfs),cov,eps,el,cfs,o[:4096],_cls(o))

class AFLR:
    def __init__(self,t,id,od): self.t=t; self.id=id; self.od=od; [os.makedirs(d,exist_ok=True)for d in(id,od)]
    def run(self,tms=1000,dur=3600,dp='',dr=False):
        if dr: return FR(0,0,0.0,0.0,0.0,ro="DRY-RUN")
        afl=os.environ.get('AFL_PATH','afl-fuzz'); cmd=[afl,'-i',self.id,'-o',self.od,'-t',str(tms),'-V',str(dur)]
        if dp: cmd.extend(['-x',dp])
        cmd.extend(['--',self.t,'@@']); st=time.time()
        try: p=subprocess.run(cmd,capture_output=True,text=True,timeout=dur+120); el=time.time()-st
        except: el=time.time()-st; return FR(-2,0,0.0,0.0,el)
        cd=os.path.join(self.od,'crashes'); cfs=[os.path.join(cd,f)for f in os.listdir(cd)if f!='README.txt']if os.path.isdir(cd)else[]
        return FR(p.returncode,len(cfs),0.0,0.0,el,cfs)

def _cls(o): return{ct:l.strip()[:120]for l in o.splitlines()for ct in _CSO if ct in l.lower()and ct not in locals().get('s',set())}

class CM:
    def __init__(self): self._cp={}; self._lk=threading.Lock(); self._ct=0; self._dr=False
    def __enter__(self): return self
    def __exit__(self,*_):
        for cid in list(self._cp.keys()): self.stop(cid)
        return False
    def dry(self,v=True): self._dr=v
    def start(self,t,cfg):
        self._ct+=1; cid=f"f_{self._ct}_{int(time.time())}"; ck=cfg.get("ckpt",f"/tmp/fckpt_{cid}.json")
        c=FC(cid,t,cfg.get("ht","stdin"),cfg.get("sd","/tmp/seeds"),cfg.get("dur",3600),"starting",[],time.time(),0.0,ck)
        with self._lk: self._cp[cid]=c
        if not self._dr: threading.Thread(target=self._rn,args=(cid,cfg),daemon=True).start()
        return c
    def resume(self,ckf):
        if not os.path.exists(ckf): return None
        with open(ckf,'r')as f: st=json.load(f); return self.start(st.get('t',''),st.get('cfg',{}))
    def stop(self,cid):
        with self._lk: c=self._cp.get(cid)
        if c: c.st="stopped"; c.ca=time.time()
    def fgs(self,cid):
        with self._lk: c=self._cp.get(cid); return list(c.fgs)if c else[]
    def _rn(self,cid,cfg):
        with self._lk: c=self._cp.get(cid)
        if c is None: return; c.st="running"
        try:
            r=LFR(cfg["t"],cfg.get("corpus",f"/tmp/c_{cid}"),cfg.get("arts",f"/tmp/a_{cid}")).run(cfg.get("dur",3600),cfg.get("jobs",1),cfg.get("dict"),opto=cfg.get("opto",0))
            fs=[{"f":cf,"sz":os.path.getsize(cf)if os.path.isfile(cf)else 0,"ts":time.time()}for cf in r.cfs]
            if c.ckpt:
                try:
                    with open(c.ckpt,'w')as f: json.dump({"t":cfg["t"],"el":r.el,"cfg":cfg,"fgs":len(fs)},f)
                except: pass
            _inc('fz.ok',1); _inc('fz.cr',r.uc)
            with self._lk: c2=self._cp.get(cid)
            if c2: c2.fgs=fs; c2.st="completed"; c2.ca=time.time()
        except Exception as e: logger.error("Fuzz %s fail:%s",cid,e); _inc('fz.fail',1)
