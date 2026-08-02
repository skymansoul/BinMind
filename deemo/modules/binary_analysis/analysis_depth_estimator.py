#!/usr/bin/env python3
"""Depth estimator v0.5 — LUT+kNN+HW+hardness+arch+mem+deadline, compression export"""
import logging,os,json,math,time,struct
from dataclasses import dataclass,field

logger=logging.getLogger(__name__)
_HWA=0.3; _HWB=0.1
_ACF={'x86':1.2,'x86_64':1.0,'arm':0.85,'arm64':0.9,'mips':1.1,'ppc':1.15,'riscv':0.8,'ebpf':0.5,'unknown':1.0}

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass
class DP: sz:int=0;nf:int=0;cpx:float=0.0;depth:int=1;est:float=0.0;conf:float=0.0;hd:dict=field(default_factory=dict);ci:float=0.0;arch:str='unknown';cm:bool=False;cd:bool=False;ps:list=field(default_factory=list)
    def ad(self):
        b={'sz':self.sz,'nf':self.nf,'cpx':self.cpx,'depth':self.depth,'est':self.est,'conf':self.conf,'arch':self.arch,'ci':[round(self.est*(1-self.ci),1),round(self.est*(1+self.ci),1)]if self.ci>0 else[self.est,self.est],'cm':self.cm,'cd':self.cd}
        if self.hd: b['hd']=self.hd
        if self.ps: b['ps']=self.ps
        return b
    def to_compressed(self,method='gz'):
        try: from . import compress_json; return compress_json(self.ad(),method)
        except: return json.dumps(self.ad()).encode()

class HWR:
    def __init__(self,a=_HWA,b=_HWB): self.a=a;self.b=b;self.l=0.0;self.t=0.0;self.p=False
    def up(self,o):
        if not self.p: self.l=o;self.t=0.0;self.p=True;return
        pl=self.l;self.l=self.a*o+(1-self.a)*(self.l+self.t);self.t=self.b*(self.l-pl)+(1-self.b)*self.t
    def fc(self,s=1): return self.l+s*self.t
    @property
    def r(self): return self.l+self.t

class ADE:
    _SL=((10*1024,1),(100*1024,2),(1024*1024,3),(100*1024*1024,4)); _FL=((50,1),(200,2),(1000,3),(10000,4))
    _DL={1:'q',2:'n',3:'d',4:'x'}; _HT={'e':0.7,'m':0.4,'h':0.0}

    def __init__(self,hp='',mb=0,dl=0): self._h=[]; self._rt=HWR(); self._ld=None; self._mb=mb; self._dl=dl; self._dr=False; self._lh(hp)
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def dry(self,v=True): self._dr=v

    def _lh(self,p):
        if not p or not os.path.isfile(p): return
        try:
            with open(p,'r',encoding='utf-8')as f: raw=json.load(f)
            if isinstance(raw,list): self._h=raw; [self._rt.up((r.get('functions',1)*_ACF.get(r.get('architecture','unknown'),1.0))/r.get('actual_time_sec',0))for r in raw if r.get('actual_time_sec',0)>0]
        except: pass

    def _lk(self,v,l):
        for th,lv in l:
            if v<=th: return lv
        return l[-1][1]

    def _cm(self,d,nf):
        if self._mb<=0: return d,False; e=nf*d*50
        if e<=self._mb: return d,False; lo,hi=1,d
        while lo<hi: mid=(lo+hi+1)//2; lo,hi=(mid,hi)if nf*mid*50<=self._mb else(lo,mid-1)
        return max(1,lo),True

    def _cd(self,d,es):
        if self._dl<=0: return d,False
        if es<=self._dl: return d,False
        return max(1,int(d*self._dl/max(es,1))),True

    def _da(self,bp):
        a='unknown'
        if not bp or not os.path.isfile(bp): return a
        try:
            import subprocess as sp; r=sp.run(['r2','-q','-c','ij; q',bp],capture_output=True,text=True,timeout=15,encoding='utf-8',errors='replace')
            info=json.loads(r.stdout)if r.stdout.strip()else{}; bins=info.get('bins',[{}])
            if bins: a=bins[0].get('arch','unknown')
        except:
            try:
                with open(bp,'rb')as fh: h=fh.read(64)
                if h[:4]==b'\x7fELF': a={3:'x86',62:'x86_64',40:'arm',183:'arm64',8:'mips',20:'ppc',243:'riscv',247:'ebpf'}.get(struct.unpack_from('<H',h,18)[0],'unknown')
            except: pass
        return a

    def _cal(self,sz,nf,cpx):
        if len(self._h)<5: return None,0.3
        hsz=[r.get('size',0)for r in self._h if r.get('size',0)>0]; hfn=[r.get('functions',0)for r in self._h if r.get('functions',0)>0]
        if not hsz or not hfn: return None,0.3; asz=sum(hsz)/len(hsz); afn=sum(hfn)/len(hfn); bd=float('inf'); bp=None
        for r in self._h:
            rs=r.get('size',0); rf=r.get('functions',0)
            if rs<=0 or rf<=0: continue; d=((sz/max(asz,1)-rs/max(asz,1))**2+(nf/max(afn,1)-rf/max(afn,1))**2)**0.5
            if d<bd: bd=d; bp=r.get('actual_depth')
        return bp,max(0.3,min(0.9,1.0-bd/3.0))

    def _ci(self,es):
        if len(self._h)<5: return 0.0
        errs=[(r.get('actual_time_sec',0)-r.get('estimated_time_sec',0))/r.get('estimated_time_sec',0)for r in self._h[-50:]if r.get('estimated_time_sec',0)>0]
        if len(errs)<3: return 0.0; me=sum(errs)/len(errs); v=sum((e-me)**2 for e in errs)/(len(errs)-1)
        return round(min(1.96*(v**0.5),2.0),3)

    def _hd(self,fs):
        d={'e':0,'m':0,'h':0}
        if not fs: return d
        for f in fs:
            ni=f.get('ninstr',0)
            if ni<=0: d['h']+=1; continue; bb=(ni-min(f.get('nargs',0),ni))/max(ni,1)
            if bb>=self._HT['e']: d['e']+=1
            elif bb>=self._HT['m']: d['m']+=1
            else: d['h']+=1
        return d

    def _ah(self,bd,hd):
        t=sum(hd.values())
        if t==0: return bd; adj=bd
        if hd['e']/t>=0.6 and bd<4: adj=bd+1
        if hd['h']/t>=0.5 and bd>1: adj=bd-1
        return adj

    def _ps(self,fp,bd):
        ss=[]
        try:
            import subprocess as sp; r=sp.run(['r2','-q','-c','iSj',fp],capture_output=True,text=True,timeout=15,encoding='utf-8',errors='replace')
            for s in json.loads(r.stdout)if r.stdout.strip()else[]: ss.append({'n':s.get('name',''),'vs':s.get('vsize',0),'ex':'x'in s.get('perm',''),'d':bd if'x'in s.get('perm','')else max(1,bd-2)})
        except: pass
        return ss

    def _pt(self,nf,d,cpx,a):
        br=self._rt.r if self._rt.p else 1.0; fr=max(0.001,self._rt.fc(3)); er=min(br,fr)if self._rt.p else br
        return(nf*d*(cpx/5.0)*_ACF.get(a,1.0))/max(0.001,er)*30.0

    def ef(self,bp):
        if bp is None: return 0,0,0.0,[],{},'unknown'
        sz=os.path.getsize(bp)if os.path.isfile(bp)else 0; a=self._da(bp); nf=0; cpx=1.0; fs=[]; hd={}
        try:
            import subprocess as sp; r=sp.run(['r2','-q','-c','aflj; q',bp],capture_output=True,text=True,timeout=60,encoding='utf-8',errors='replace')
            fs=json.loads(r.stdout.strip())if r.stdout.strip()else[]; nf=len(fs)
            if nf>0: t=sum(f.get('ninstr',0)+f.get('numargs',0)for f in fs); cpx=(t/nf)/10.0; hd=self._hd(fs)
        except: pass
        return sz,nf,min(max(cpx,0.1),10.0),fs,hd,a

    def est(self,bp):
        if self._dr: return DP(0,0,0.0,1,0.0,0.0,{},0.0,'unknown')
        sz,nf,cpx,fs,hd,a=self.ef(bp); cdepth,cconf=self._cal(sz,nf,cpx); ds=self._lk(sz,self._SL); dfn=self._lk(nf,self._FL)
        if cdepth is not None and cconf>0.6: bd=cdepth; conf=cconf
        else: bd=ds if ds>dfn else dfn; conf=min(0.3+len(self._h)*0.05,0.9)
        if hd: depth=self._ah(bd,hd)
        else: depth=bd
        if self._rt.p: est_t=self._pt(nf,depth,cpx,a)
        else: est_t=nf*30.0*depth*(cpx/5.0)*_ACF.get(a,1.0)
        cm=cd=False; depth,cm=self._cm(depth,nf); depth,cd=self._cd(depth,est_t); ci=self._ci(est_t); self._ld=depth; ps=self._ps(bp,depth); _inc('dep.est',1)
        return DP(sz,nf,round(cpx,1),depth,round(est_t,1),round(conf,2),hd,ci,a,cm,cd,ps)

    def rec(self,bp,ad,at):
        sz=os.path.getsize(bp)if os.path.isfile(bp)else 0; a=self._da(bp); self._h.append({'path':bp,'size':sz,'arch':a,'ad':ad,'at':at,'et':self._ld or at,'ts':time.time()})
        if at>0: self._rt.up((self._ld or 1)*_ACF.get(a,1.0)/at)
        if len(self._h)>200: self._h=self._h[-200:]

def ead(bp): return ADE().est(bp).ad()
