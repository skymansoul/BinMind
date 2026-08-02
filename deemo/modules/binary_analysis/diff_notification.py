"""Diff notification v0.5 — channels, delta encoding for compressed diffs, dry-run"""
import os,json,logging,hashlib,time,glob as _g,threading
from dataclasses import dataclass,field; from enum import Enum; import typing

log=logging.getLogger(__name__)
class CT(str,Enum): NV="nv";VC="vc";VF="vf";FC="fc";NF="nf";FD="fd"
class NL(str,Enum): I="i";W="w";C="c"

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class AR: aid:str;ts:float;vulns:list=field(default_factory=list);funcs:list=field(default_factory=list);meta:dict=field(default_factory=dict)
@dataclass class DC: ct:str;lv:str;desc:str;dt:dict=field(default_factory=dict);ai:list=field(default_factory=list);ch:str=""
@dataclass class DR: aid:str;pid:typing.Optional[str];chs:list=field(default_factory=list);sm:dict=field(default_factory=dict);tr:bool=False;rh:str="";gr:float=0.0

class DA:
    _LG=100; _SP=5
    def __init__(self): self._vkf=["cve_id","fn","addr"]; self._fkf=["name","addr"]; self._rh=[]; self._mr=20; self._cc=[]; self._su={}; self._sw=300; self._dr=False
    def dry(self,v=True): self._dr=v
    def cmp(self,p,c):
        if self._dr: return DR(c.aid,p.aid if p else None,[],{"t":0},False,"dry",0.0)
        ch=[]; ch.extend(self._cv(p,c)); ch.extend(self._cf(p,c)); tr=len(ch)>self._LG
        if tr: ch=self._sc(ch)
        s=self._gs(ch); rh=self._crh(ch); self._th(rh); g=0.0
        if self._cc: pa=sum(self._cc[-5:])/len(self._cc[-5:])
        if pa>0: g=round((len(ch)-pa)/pa,2)
        self._cc.append(s["t"]); return DR(c.aid,p.aid if p else None,ch,s,tr,rh,g)

    # //// Delta report: 仅包含变更, 用于压缩传输 ////
    def delta(self,p,c):
        full=self.cmp(p,c); delta_sm={k:v for k,v in full.sm.items()if v>0}; return DR(full.aid,full.pid,full.chs,delta_sm,full.tr,full.rh,full.gr)

    def _crh(self,ch):
        h=hashlib.sha256(); [h.update(c.ct.encode())or h.update(c.desc.encode())for c in sorted(ch,key=lambda x:(x.ct,x.desc))]; return h.hexdigest()[:16]
    def _th(self,h): self._rh.append(h)
    def _sc(self,ch):
        bt={}; [bt.setdefault(c.ct,[]).append(c)for c in ch]; sp=[]
        for _,its in bt.items(): its.sort(key=lambda x:(0 if x.lv==NL.C else 1)); sp.extend(its[:self._SP])
        return sp
    def _cv(self,p,c):
        ch=[]; pv=self._iv(p.vulns); cv=self._iv(c.vulns); pk,ck=set(pv.keys()),set(cv.keys())
        for k in ck-pk: v=cv[k]; ch.append(DC(CT.NV,NL.C,f"new:{v.get('cve_id','?')}",v,[v.get('fn','')],hashlib.sha256(f"n:{k}".encode()).hexdigest()[:12]))
        for k in pk-ck: v=pv[k]; ch.append(DC(CT.VF,NL.I,f"fix:{v.get('cve_id','?')}",v,[v.get('fn','')],hashlib.sha256(f"f:{k}".encode()).hexdigest()[:12]))
        for k in pk&ck:
            if self._vc(pv[k],cv[k]): ch.append(DC(CT.VC,NL.W,f"chg:{cv[k].get('cve_id','?')}",{"p":pv[k],"c":cv[k]},[cv[k].get('fn','')],hashlib.sha256(f"c:{k}".encode()).hexdigest()[:12]))
        return ch
    def _cf(self,p,c):
        ch=[]; pf=self._if(p.funcs); cf=self._if(c.funcs); pk,ck=set(pf.keys()),set(cf.keys())
        for k in ck-pk: f=cf[k]; ch.append(DC(CT.NF,NL.I,f"new:{f.get('name','?')}",f,[f.get('name','')],hashlib.sha256(f"nf:{k}".encode()).hexdigest()[:12]))
        for k in pk-ck: f=pf[k]; ch.append(DC(CT.FD,NL.W,f"del:{f.get('name','?')}",f,[f.get('name','')],hashlib.sha256(f"df:{k}".encode()).hexdigest()[:12]))
        for k in pk&ck:
            if self._fc(pf[k],cf[k]): ch.append(DC(CT.FC,NL.W,f"chg:{cf[k].get('name','?')}",{"p":pf[k],"c":cf[k]},[cf[k].get('name','')],hashlib.sha256(f"cf:{k}".encode()).hexdigest()[:12]))
        return ch
    def _iv(self,vl): return{self._vk(v):v for v in vl}
    def _vk(self,v): parts=[str(v.get(f,""))for f in self._vkf if v.get(f)]; return":".join(parts)or str(id(v))
    def _if(self,fl): return{self._fk(f):f for f in fl}
    def _fk(self,f): parts=[str(f.get(fn,""))for fn in self._fkf if f.get(fn)]; return":".join(parts)or str(id(f))
    def _vc(self,p,c): return any(p.get(f)!=c.get(f)for f in["severity","status","confidence","description"])
    def _fc(self,p,c): return any(p.get(f)!=c.get(f)for f in["size","hash","complexity","is_vulnerable"])
    def _gs(self,ch):
        s={"nv":0,"fv":0,"cv":0,"nf":0,"df":0,"cf":0,"t":len(ch),"c":0,"w":0}
        for c in ch:
            if c.ct==CT.NV: s["nv"]+=1
            elif c.ct==CT.VF: s["fv"]+=1
            elif c.ct==CT.VC: s["cv"]+=1
            elif c.ct==CT.NF: s["nf"]+=1
            elif c.ct==CT.FD: s["df"]+=1
            elif c.ct==CT.FC: s["cf"]+=1
            if c.lv==NL.C: s["c"]+=1
            elif c.lv==NL.W: s["w"]+=1
        return s

class NC: pass
class ConsoleC(NC):
    def send(self,r):
        print("\n"+"="*60); hdr=f"Diff-{r.aid}"
        if r.tr: hdr+="[t]"
        if abs(r.gr)>0.5: hdr+=f" {'^'if r.gr>0 else'v'}{abs(r.gr):.0%}"
        print(hdr); [print(f"[{c.lv}]{c.desc}")for c in r.chs]; print("sm:"); [print(f"  {k}:{v}")for k,v in r.sm.items()if v>0]; print("="*60); return True
class WebhookC(NC):
    def __init__(self,u): self._u=u
    def send(self,r):
        try: import requests; return requests.post(self._u,json={"aid":r.aid,"rh":r.rh,"chs":[{"t":c.ct,"l":c.lv,"d":c.desc}for c in r.chs],"sm":r.sm},timeout=15).status_code==200
        except: return False
    def send_async(self,r): threading.Thread(target=lambda:self.send(r),daemon=True).start()
class SlackC(NC):
    def __init__(self,u,ch=""): self._u=u; self._ch=ch
    def send(self,r):
        try:
            import requests; c="danger"if r.sm.get("c",0)>0 else"warning"; t=f"*BinMind Diff* `{r.aid}`\n"
            for k in["nv","fv","cv"]: v=r.sm.get(k,0); t+=f"• {k}:{v}\n"if v>0 else""
            return requests.post(self._u,json={"attachments":[{"color":c,"text":t}]},timeout=15).status_code==200
        except: return False
class FileC(NC):
    def __init__(self,d,mx=100,arc=''): self._d=d; self._mx=mx; self._arc=arc
    def send(self,r):
        try:
            os.makedirs(self._d,exist_ok=True); fp=os.path.join(self._d,f"dr_{r.aid}.json")
            with open(fp,'w')as f: json.dump({"aid":r.aid,"rh":r.rh,"chs":[{"t":c.ct,"l":c.lv,"d":c.desc,"h":c.ch}for c in r.chs],"sm":r.sm},f,indent=2)
            ex=sorted(_g.glob(os.path.join(self._d,"dr_*.json")))
            if len(ex)>self._mx:
                for old in ex[:len(ex)-self._mx]:
                    if self._arc: os.makedirs(self._arc,exist_ok=True); os.rename(old,os.path.join(self._arc,os.path.basename(old)))
                    else:
                        try: os.unlink(old)
                        except: pass
            _inc('dif.saved',1); return True
        except Exception as e: log.error("Save:%s",e); return False

class NM:
    def __init__(self): self._ch=[]; self._sh=set(); self._mh=200; self._dr=False
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def dry(self,v=True): self._dr=v
    def add(self,c): self._ch.append(c)
    def rm(self,c):
        if c in self._ch: self._ch.remove(c)
    def notify(self,r):
        if self._dr: return
        if r.rh and r.rh in self._sh: return
        for c in self._ch:
            try: c.send(r)
            except: pass
        if r.rh: self._sh.add(r.rh); _inc('dif.sent',1)

_gm=None
def gnm():
    global _gm
    if _gm is None: _gm=NM()
    return _gm
def aan(p,c):
    a=DA(); r=a.cmp(p,c)
    if r.sm["t"]>0: gnm().notify(r)
    return r
