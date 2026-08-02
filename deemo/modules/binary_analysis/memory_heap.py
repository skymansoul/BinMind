# Heap analysis v0.5 — UAF/DF/leak/spray/guard, snapshot, CVE match, dry-run
import os,re,json
from enum import Enum,auto; from dataclasses import dataclass,field; from collections import defaultdict

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

class AP(Enum): DF=auto();UAF=auto();LEAK=auto();RCH=auto();WF=auto();GP=auto();SP=auto()
@dataclass class AS: addr:int;sz:int;ct:str;clr:int
@dataclass class FS: addr:int;ptr:int;clr:int
@dataclass class HV: vt:AP;site:object;desc:str;sev:str;cve:str=''

_CV=[('CVE-2021-3156',0x100,AP.GP),('CVE-2022-0185',0x1000,AP.GP),('CVE-2023-25136',16,AP.DF)]

class HS:
    def __init__(self): self._al={}; self._fr=set(); self._ac=[]; self._hi=[]; self._st=[]; self._dr=False
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def dry(self,v=True): self._dr=v
    def ta(self,a,sz,ct,cl): s=AS(a,sz,ct,cl); self._al[a]=s; self._hi.append(('a',s)); self._st.append((len(self._hi),sz)); return s
    def tf(self,a,p,cl): s=FS(a,p,cl); self._hi.append(('f',s)); self._fr.add(p); return s
    def tac(self,p,cl): self._ac.append((p,cl))
    def spray(self,th=0.6):
        if len(self._st)<20: return False; sz=[x[1]for x in self._st]; return sz.count(max(set(sz),key=sz.count))/len(sz)>=th
    def gp(self,sz): P=4096; return sz>0 and(P-(sz%P))<128 and sz>P//2
    def snap(self): return{'al':{k:{'addr':v.addr,'sz':v.sz,'ct':v.ct,'clr':v.clr}for k,v in self._al.items()},'fr':list(self._fr),'st':self._st[:]}
    def restore(self,s): self._al={k:AS(**v)for k,v in s['al'].items()}; self._fr=set(s['fr']); self._st=s['st'][:]
    def det(self):
        if self._dr: return[]
        f=[]; fc=defaultdict(list)
        for et,ev in self._hi:
            if et=='f': fc[ev.ptr].append(ev)
        for p,evs in fc.items():
            if len(evs)>=2: f.append((AP.DF,evs[0],f"DF 0x{p:x}"))
        fp={ev.ptr:ev for et,ev in self._hi if et=='f'}
        for p,cl in self._ac:
            if p in fp: f.append((AP.UAF,fp[p],f"UAF 0x{p:x}"))
        fs={ev.ptr for et,ev in self._hi if et=='f'}
        for p,a in self._al.items():
            if p not in fs: f.append((AP.LEAK,a,f"Leak 0x{a.addr:x} sz={a.sz}"))
        rp={ev.addr:ev for et,ev in self._hi if et=='a'and ev.ct=='realloc'}
        if len(rp)>=3: f.append((AP.RCH,list(rp.values())[0],f"RChain:{len(rp)}"))
        for et,ev in self._hi:
            if et=='f'and ev.ptr not in self._al: f.append((AP.WF,ev,f"WFree 0x{ev.ptr:x}"))
        for p,a in self._al.items():
            if self.gp(a.sz): f.append((AP.GP,a,f"GP:{a.sz}B"))
        if self.spray(): f.append((AP.SP,None,"Spray"))
        return f

class PA:
    @staticmethod
    def an(als,frs):
        fbp={f.ptr:f for f in frs}; pr=[(a,fbp[a.addr])for a in als if a.addr in fbp]; ua=[a for a in als if a.addr not in fbp]; uf=[f for f in frs if f.ptr not in{a.addr for a in als}]
        return{'pr':pr,'ua':ua,'uf':uf,'ta':len(als),'tf':len(frs)}

HAF={'malloc','calloc','realloc','_Znwm','HeapAlloc','VirtualAlloc','RtlAllocateHeap','mmap'}
HFF={'free','_ZdlPv','HeapFree','VirtualFree','RtlFreeHeap','munmap'}

def _r2(fp,cmd,to=15):
    import subprocess
    try: return subprocess.check_output(['r2','-q','-c',cmd,fp],stderr=subprocess.DEVNULL,timeout=to).decode(errors='ignore')
    except: return''
def _fia(fp,fns):
    o=_r2(fp,'iaj'); r={}
    if not o: return r
    try:
        for imp in json.loads(o): n=imp.get('name',''); a=imp.get('plt',imp.get('vaddr',0))
        if any(fn in n for fn in fns)and a>0: r[a]=n
    except: pass
    return r
def _cx(fp,dr=False):
    if dr: return[],[]
    ai=_fia(fp,HAF); fi=_fia(fp,HFF); als=[]; frs=[]
    for ia,iname in ai.items():
        x=_r2(fp,f'axtj @ {ia}')
        if x:
            try:
                for xr in json.loads(x): cl=xr.get('from',0)
                if cl: als.append(AS(cl,_isz(fp,cl,iname),_cls(iname),cl))
            except: pass
    for ia,iname in fi.items():
        x=_r2(fp,f'axtj @ {ia}')
        if x:
            try:
                for xr in json.loads(x): cl=xr.get('from',0)
                if cl: frs.append(FS(cl,0,cl))
            except: pass
    return als,frs
def _cls(n): nl=n.lower()
if'realloc'in nl: return'realloc'
if'virtualalloc'in nl: return'valloc'
return'malloc'
def _isz(fp,a,fn):
    o=_r2(fp,f'pd -5 @ {a}')
    for s in re.findall(r'(?:push|mov.*),\s*(?:0x)?([0-9a-fA-F]+)',o):
        try: v=int(s,16 if any(c in s.lower()for c in'abcdef')else 10); return v if 0<v<0x10000000 else 0
        except: pass
    return 0
def _dhp(fp): f=[]; o=_r2(fp,'izz'); s=o.lower()
for kw in['fastbin','tcache','unsorted_bin','__free_hook']:
    if kw in s: f.append({'t':'glibc','k':kw})
for t,pat in[('hof',r'house.of.force'),('tcp',r'tcache|free.*\bfd\b'),('fbd',r'fastbin.*dup')]:
    if re.search(pat,s): f.append({'t':'exp','tech':t})
return f

def ah(bp,dr=False):
    if not os.path.exists(bp): return{'e':f'NF:{bp}'}
    if dr: return{'bp':bp,'als':0,'frs':0,'vulns':[],'dry':True}
    als,frs=_cx(bp); st=HS()
    for a in als: st.ta(a.addr,a.sz,a.ct,a.clr)
    for fr in frs: st.tf(fr.addr,fr.ptr,fr.clr)
    pts=st.det(); pa=PA.an(als,frs); eh=_dhp(bp)
    sm={AP.DF:'HIGH',AP.UAF:'HIGH',AP.WF:'MEDIUM',AP.LEAK:'LOW',AP.RCH:'LOW',AP.SP:'MEDIUM',AP.GP:'HIGH'}; vl=[]
    for pt,site,desc in pts:
        cm=''
        for ci,tsz,tp in _CV:
            if pt==tp and hasattr(site,'sz')and abs(site.sz-tsz)<0x10: cm=ci; break
        vl.append(HV(pt,site,desc,sm.get(pt,'LOW'),cm).__dict__)
    _inc('hp.a',1); _inc('hp.v',len(vl))
    return{'bp':bp,'als':len(als),'frs':len(frs),'pa':pa,'vulns':vl,'hints':eh,'spray':st.spray(),'t':len(vl),'snap':st.snap()}

if __name__=='__main__':
    import sys
    if len(sys.argv)>1: r=ah(sys.argv[1]); print(f"Bin:{r['bp']} A:{r['als']} F:{r['frs']} V:{r['t']} Spray:{r['spray']}")
    for v in r['vulns']: print(f"  [{v['sev']}] {v['desc']}{' ['+v['cve']+']' if v.get('cve')else''}")
