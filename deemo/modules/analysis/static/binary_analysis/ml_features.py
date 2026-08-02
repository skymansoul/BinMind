# ML features v0.5 — n-gram/CFG/MinHash/Graphlet/TF-IDF/Hashing, online, compression
import os,re,json,math,pickle,hashlib
from dataclasses import dataclass,field; from collections import Counter,defaultdict

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass
class FV: fn:str='';addr:int=0;bc:int=0;ec:int=0;ic:int=0;cyc:int=0;ab:float=0.0;cc:int=0;h2:Counter=field(default_factory=Counter);h3:Counter=field(default_factory=Counter);sf:dict=field(default_factory=dict);mh:list=field(default_factory=list);gl:dict=field(default_factory=dict);hf:list=field(default_factory=list)

    def tv(self):
        v=[float(self.bc),float(self.ec),float(self.ic),float(self.cyc),float(self.ab),float(self.cc)]
        t2=[x[1]for x in self.h2.most_common(32)]
        while len(t2)<32: t2.append(0.0); v.extend([float(x)for x in t2[:32]])
        t3=[x[1]for x in self.h3.most_common(16)]
        while len(t3)<16: t3.append(0.0); v.extend([float(x)for x in t3[:16]]); return v

    def thv(self,dim=128):
        if self.hf: return self.hf; vec=[0.0]*dim
        for(a,b),cnt in self.h2.items():
            for s in range(3): h=abs(hash((f"{a}|{b}",s)))%dim; vec[h]+=cnt*(1.0 if s%2==0 else-1.0)
        n=math.sqrt(sum(v*v for v in vec))
        if n>0: vec=[v/n for v in vec]
        self.hf=vec; return vec

def oh(d,n=2):
    try: from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    except ImportError: return Counter()
    md=Cs(CS_ARCH_X86,CS_MODE_64); ops=[i.mn for i in md.disasm(d,0)]
    if len(ops)<n: return Counter()
    return Counter(tuple(ops[i:i+n])for i in range(len(ops)-n+1))

def _mh(ngc,nh=64):
    if not ngc: return[0]*nh; sig=[float('inf')]*nh
    for gt,_ in ngc.items(): gs='|'.join(gt)
    for i in range(nh): h=hash((gs,i))&0x7FFFFFFFFFFFFFFF
    if h<sig[i]: sig[i]=h
    return sig

def mj(s1,s2):
    if len(s1)!=len(s2)or len(s1)==0: return 0.0
    return sum(1 for a,b in zip(s1,s2)if a==b)/len(s1)

def _gl(bl,ed):
    c={'2p':0,'2c':0,'3p':0,'3s':0,'3t':0}; adj=defaultdict(set)
    for e in ed: fr=e.get('from')or e.get('f',0); to=e.get('to')or e.get('t',0)
    if fr and to: adj[fr].add(to)
    nds=list(adj.keys())
    if len(nds)>500: import random; nds=random.sample(nds,500)
    for u in nds:
        for v in adj[u]:
            if v not in adj: continue; c['2p']+=1
            if u in adj[v]: c['2c']+=1
            for w in adj[v]:
                if w not in adj: continue; c['3p']+=1
                if u in adj[w]: c['3t']+=1
                elif v in adj[w]: c['3s']+=1
    return c

def ex(bp,fa):
    if not os.path.exists(bp): return None
    try:
        import subprocess; o=subprocess.check_output(['r2','-q','-c',f'afij @ {fa}',bp],stderr=subprocess.DEVNULL,timeout=15).decode(errors='ignore'); fj=json.loads(o)
    except: fj={}
    bl=fj.get('blocks',[])
    if not bl: return None
    ed=fj.get('edges',[]); nb=fj.get('nbbs',len(bl)); ni=fj.get('ninstr',0); nc=len(fj.get('calltype_refs',[])); ab=ni/max(nb,1); cy=max(len(ed)-nb+2,1)
    try:
        import subprocess as sp; pd=sp.check_output(['r2','-q','-c',f'pD {ni+10} @ {fa}',bp],stderr=sp.DEVNULL,timeout=10); h2=oh(pd,2); h3=oh(pd,3)
    except: h2=Counter(); h3=Counter()
    mh_s=_mh(h2,64); gl=_gl(bl,ed); sf={'nl':_cl(bl,ed),'mxb':max((b.get('ninstr',0)for b in bl),default=0),'mnb':min((b.get('ninstr',0)for b in bl),default=0),'ind':_mi(ed),'oud':_mo(ed)}
    return FV(fj.get('name',f'f_{fa:x}'),fa,nb,len(ed),ni,cy,round(ab,2),nc,h2,h3,sf,mh_s,gl)

def _cl(bl,ed): lps=0
for b in bl: bid=b.get('offset')
if bid is None: continue; inc=[e for e in ed if e.get('to')==bid]
if len(inc)>1 and any(f>=bid for f in[e.get('from')for e in inc]if f is not None): lps+=1
return lps
def _mi(ed): return max(Counter(e.get('to')for e in ed if e.get('to')is not None).values(),default=0)
def _mo(ed): return max(Counter(e.get('from')for e in ed if e.get('from')is not None).values(),default=0)

def batch(bp):
    r={}
    if not os.path.exists(bp): return r
    try:
        import subprocess; fs=json.loads(subprocess.check_output(['r2','-q','-c','aflj',bp],stderr=subprocess.DEVNULL,timeout=20).decode(errors='ignore'))
    except: fs=[]
    for f in fs:
        a=f.get('offset',f.get('vaddr',0)); sz=f.get('size',0)
        if a and sz>8:
            fv=ex(bp,a)
            if fv: r[a]=fv
    return r

def cos(v1,v2): d=sum(a*b for a,b in zip(v1,v2)); n1=math.sqrt(sum(a*a for a in v1)); n2=math.sqrt(sum(b*b for b in v2)); return d/(n1*n2)if n1 and n2 else 0.0
def _eu(a,b): return math.sqrt(sum((x-y)**2 for x,y in zip(a,b)))

class EI:
    def __init__(self,dim=54): self._e={}; self._d=dim; self._mc={}
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def add(self,n,f): self._e[n]=f.tv(); self._mc[n]=f.mh if f.mh else None
    def upd(self,n,f): self.add(n,f)
    def search(self,qf,k=5,mt=0.3):
        qv=qf.tv()
        if not self._e: return[]; cds=list(self._e.keys())
        if qf.mh and self._mc: cds=[n for n,s in self._mc.items()if s and mj(qf.mh,s)>=mt]
        if not cds: cds=list(self._e.keys()); ds=[]
        for n in cds:
            v=self._e.get(n)
            if v is None: continue; d=_eu(_al(v,qv),qv)if len(v)!=len(qv)else _eu(v,qv); ds.append((n,d)); ds.sort(key=lambda x:x[1])
        if len(ds)>k*2: ds=ds[:k]; ds.sort(key=lambda x:x[1]); return[(n,1.0/(1.0+d))for n,d in ds[:k]]
    def save(self,fp):
        with open(fp,'wb')as f: pickle.dump({'e':self._e,'d':self._d,'mc':self._mc},f)
    def load(self,fp):
        if not os.path.exists(fp): return False
        with open(fp,'rb')as f: d=pickle.load(f); self._e=d.get('e',{}); self._d=d.get('d',54); self._mc=d.get('mc',{}); return True
    def to_compressed(self,method='gz'):
        try: from . import compress_json; return compress_json({'e':self._e,'d':self._d,'mc':self._mc},method)
        except: return pickle.dumps({'e':self._e,'d':self._d,'mc':self._mc})

def _al(v1,v2): al=v1[:]
while len(al)<max(len(v1),len(v2)): al.append(0.0)
return al

@dataclass class FSR: ms:list=field(default_factory=list);tc:int=0
def cmp(b1,b2,tk=20):
    f1=batch(b1); f2=batch(b2); r=FSR()
    for fv1 in f1.values():
        v1=fv1.tv()
        for fv2 in f2.values(): s=cos(_al(v1,fv2.tv()),fv2.tv()); r.ms.append((fv1.fn,fv2.fn,s)); r.tc+=1
    r.ms.sort(key=lambda x:x[2],reverse=True); r.ms=r.ms[:tk]; return r

if __name__=='__main__':
    import sys
    if len(sys.argv)>1: fs=batch(sys.argv[1]); print(f"Extracted {len(fs)} funcs"); ei=EI(); [ei.add(fv.fn,fv)for fv in fs.values()]; print(f"Indexed {len(ei._e)}")
