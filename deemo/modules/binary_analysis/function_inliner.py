# Function inliner v0.5 — hot/cold, recursion guard, cache model v2, dry-run
import os,struct,subprocess,logging,re
from dataclasses import dataclass,field; from typing import Any,Dict,List,Set

logger=logging.getLogger(__name__)
def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class CS: addr:int;tf:int;ib:bytes;sz:int;mn:str=""
@dataclass class CGS: t:int;lvs:int;inl:int;sav:int;cand:List[int]=field(default_factory=list);rec:List[int]=field(default_factory=list);hot:List[int]=field(default_factory=list);cold:List[int]=field(default_factory=list)

class FI:
    def __init__(self,bp): self.bp=bp; self._a=self._da()
        with open(bp,"rb")as f: self._raw=bytearray(f.read())
        self._cg:Dict[int,Set[int]]={}; self._cc:Dict[int,int]={}; self._bcg(); self._dr=False

    def __enter__(self): return self
    def __exit__(self,*_): return False
    def dry(self,v=True): self._dr=v
    def _da(self): return{".elf":"x86",".so":"x86",".o":"x86"}.get(os.path.splitext(self.bp)[1].lower(),"unknown")

    def _bcg(self):
        try:
            import json as _j; r2=subprocess.run(["r2","-q","-c","agj",self.bp],capture_output=True,text=True,timeout=30)
            g=_j.loads(r2.stdout)if r2.stdout.strip()else[]
            def _w(n,p=None):
                a=n.get('offset',0)
                if a and p: self._cg.setdefault(p,set()).add(a)
                for c in n.get('children',[]): _w(c,a)
            for n in(g if isinstance(g,list)else[g]): _w(n)
            for cl,cs in self._cg.items():
                if cl not in self._cc: self._cc[cl]=0
                for c in cs: self._cc[c]=self._cc.get(c,0)+1
        except: pass

    def det_rec(self):
        W,G,B=0,1,2; color={n:W for n in self._cg}; rec=[]
        def dfs(n):
            color[n]=G
            for c in self._cg.get(n,set()):
                if color.get(c,W)==G: rec.append(n); return True
                elif color.get(c,W)==W and dfs(c): return True
            color[n]=B; return False
        [dfs(n)for n in list(self._cg.keys())if color.get(n,W)==W]; return rec

    def hc(self):
        h,c=[],[]
        for a in self._cg: cl=self._cc.get(a,0); sz=self.gs(a)
        if cl>=5 and 0<sz<=200: h.append(a)
        elif cl==0 and sz>0: c.append(a)
        return h,c

    def cv2(self,fa,d=0):
        sz=self.gs(fa); cc=len(self.sc(fa)); ncl=self.ncl(fa); bs=cc*5-(cc*(sz-1)); cl=sz/64; cp=cl*d*cc*0.15; nb=bs-cp
        return{"sz":sz,"cc":cc,"ncl":ncl,"bs":bs,"cp":round(cp,2),"net":round(nb,2),"ok":nb>0 and sz<=256}

    def sc(self,fa):
        ss=[]
        try:
            import json as _j; r2=subprocess.run(["r2","-q","-c",f"pDj {fa}",self.bp],capture_output=True,text=True,timeout=20)
            ins=_j.loads(r2.stdout)if r2.stdout.strip()else[]
        except: return ss
        for i in ins:
            mn=i.get("opcode",i.get("disasm","")); a=i.get("offset",0); sz=i.get("size",0)
            if"call"in str(mn).lower():
                t=0
                if"jump"in i: t=i.get("jump",0)
                elif mn.startswith("call ")and mn[5:].startswith("0x"):
                    try: t=int(mn[5:].split()[0],16)
                    except: pass
                ss.append(CS(a,t,b"",sz,str(mn)))
        return ss

    def il(self,fa):
        try: r2=subprocess.run(["r2","-q","-c",f"afi~call {fa}",self.bp],capture_output=True,text=True,timeout=10); return len([l for l in r2.stdout.splitlines()if l.strip()])==0
        except: return False
    def gs(self,fa):
        try: r2=subprocess.run(["r2","-q","-c",f"afi~size {fa}",self.bp],capture_output=True,text=True,timeout=10); m=re.search(r'size[:=]\s*(\d+)',r2.stdout); return int(m.group(1))if m else 0
        except: return 0
    def ncl(self,fa):
        try:
            import json as _j; r2=subprocess.run(["r2","-q","-c",f"axtj @ {fa}",self.bp],capture_output=True,text=True,timeout=10)
            return len(_j.loads(r2.stdout)if r2.stdout.strip()else[])
        except: return 0
    def inline(self,cs,op=None):
        if self._dr: return b""
        d=bytearray(self._raw); self._nop(d,cs.addr,cs.sz); cd=self._efb(cs.tf)
        if cd: self._ins(d,cs.addr+cs.sz,cd)
        r=bytes(d)
        if op:
            with open(op,"wb")as f: f.write(r)
        return r
    def _nop(self,d,a,sz):
        if a<0 or a+sz>len(d): return
        for i in range(sz): d[a+i]=0x90
    def _ins(self,d,off,ins):
        if off<0 or off>len(d): return; e=off+len(ins)
        if e<=len(d): d[off:e]=ins
    def _efb(self,fa):
        sz=self.gs(fa)
        if sz==0 or fa<=0: return b""
        if fa+sz<=len(self._raw): return bytes(self._raw[fa:fa+sz])
        return b""
    def ben(self,fa):
        sz=self.gs(fa); cc=len(self.sc(fa)); ncl=self.ncl(fa); spc=5; si=sz-1; ts=(cc*spc)-(cc*si)
        return{"sz":sz,"cc":cc,"ncl":ncl,"sav":ts,"ok":sz<=20 and cc>=3,"lto":(ncl==1 and sz<=30)}

MI=20
def aio(bp,dr=False):
    inl=FI(bp)
    if dr: inl.dry(True)
    funcs=[]
    try:
        r2=subprocess.run(["r2","-q","-c","aflq",bp],capture_output=True,text=True,timeout=30)
        for l in r2.stdout.splitlines():
            p=l.strip().split()
            if p:
                try: funcs.append(int(p[0],16))
                except: continue
    except: pass
    t=len(funcs); lvs=0; inlbl=0; cand=[]
    for fa in funcs:
        if inl.il(fa): lvs+=1; sz=inl.gs(fa)
        if sz<=MI: inlbl+=1; cand.append(fa)
    est=inlbl*5; rec=inl.det_rec(); h,c=inl.hc(); _inc('inl.a',t); return CGS(t,lvs,inlbl,est,cand,rec,h,c)

def bi(bp,op,mf=10,dr=False):
    s=aio(bp,dr); inl=FI(bp)
    if dr: inl.dry(True); return 0
    ind=0; sk=set(s.rec); pr=s.hot+[f for f in s.cand if f not in s.hot]
    for fa in pr[:mf]:
        if fa in sk: continue
        for cs in inl.sc(fa):
            try: inl.inline(cs,op); ind+=1; _inc('inl.d',1)
            except: pass
    return ind
