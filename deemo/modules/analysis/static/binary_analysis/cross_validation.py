#!/usr/bin/env python3
"""Cross-validation v0.5 — syscall prediction/strace, dry-run, per-input, op timeout"""
import logging,os,re,subprocess
from dataclasses import dataclass,field; from typing import List,Set,Dict; from collections import defaultdict

logger=logging.getLogger(__name__)
def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class VF: t:str;d:str;sc:float=0.0;dc:float=0.0;ag:float=0.0;ld:bool=False
@dataclass class CVR: ok:bool;fs:List[VF];sf:int=0;df:int=0;cf:int=0;ar:float=0.0;pc:dict=field(default_factory=dict);an:List[str]=field(default_factory=list);as_:bool=False;lh:bool=False;pis:List[dict]=field(default_factory=list)

def _dlp(o): return bool(re.search(r'ld\.so\.preload|LD_PRELOAD',o,re.I))
_MSS=[(['open','mmap','mprotect'],'sc_ld'),(['socket','connect','execve'],'rev_sh'),(['ptrace','waitpid','execve'],'inj'),(['memfd_create','write','fexecve'],'fless')]
def _dss(o):
    sc=re.findall(r'^(\w+)\(',o,re.M); f=[]
    for seq,lb in _MSS:
        si=0
        for c in sc:
            if si<len(seq)and c==seq[si]: si+=1
        if si==len(seq): f.append(lb)
    return f

class SP:
    _SP=[(r'\bexecve\b|\bsystem\b','exec'),(r'\bopen\b|\bfopen\b','open'),(r'\bread\b|\bfread\b','read'),(r'\bwrite\b|\bfwrite\b','write'),(r'\bconnect\b|\bsocket\b','net'),(r'\bmmap\b|\bmprotect\b|\bmunmap\b','mem'),(r'\bfork\b|\bclone\b','proc')]
    def __init__(self,bp): self._bp=bp; self._at:Dict[str,List[bool]]=defaultdict(list)
    def predict(self):
        p=set()
        try:
            r=subprocess.run(['r2','-q','-c','aaaa; pD $SS @ $S; q',self._bp],capture_output=True,text=True,timeout=120,encoding='utf-8',errors='replace'); d=r.stdout.lower()
            for pat,cat in self._SP:
                if re.search(pat,d,re.I): p.add(cat)
            r2=subprocess.run(['r2','-q','-c','iij; q',self._bp],capture_output=True,text=True,timeout=30)
            for pat,cat in self._SP:
                if re.search(pat,r2.stdout.lower(),re.I): p.add(cat)
        except: pass
        return p
    def ra(self,cat,ok):
        self._at[cat].append(ok)
        if len(self._at[cat])>50: self._at[cat]=self._at[cat][-50:]
    def gc(self,cat): h=self._at.get(cat,[]); return sum(1 for x in h if x)/len(h)if h else 0.5
    @property
    def oa(self):
        ar=[]; [ar.extend(r)for r in self._at.values()]; return sum(1 for x in ar if x)/len(ar)if ar else 0.5

class DO:
    _CR={'exec':[r'execve'],'open':[r'openat'],'read':[r'\bread\b'],'write':[r'\bwrite\b'],'net':[r'connect',r'socket',r'bind'],'mem':[r'mmap',r'mprotect',r'brk'],'proc':[r'fork',r'clone',r'vfork']}
    _AS=[(r'prctl\(PR_SET_NO_NEW_PRIVS','nnp'),(r'ptrace\(PTRACE_TRACEME','adb')]
    def __init__(self,bp): self._bp=bp
    def obs(self,to=10):
        obs=set(); an=[]; out=''
        try:
            r=subprocess.run(['strace','-f','-e','trace=all',self._bp],capture_output=True,text=True,timeout=to,encoding='utf-8',errors='replace'); out=r.stderr.lower()
            for cat,pats in self._CR.items():
                j=0
                while j<len(pats):
                    if re.search(pats[j],out): obs.add(cat); break
                    j+=1
            for sig,lb in self._AS:
                if re.search(sig,out): an.append(lb)
        except: pass
        return obs,an,out

class CV:
    def __init__(self,bp): self._bp=os.path.abspath(bp); self._pr=SP(bp); self._ob=DO(bp); self._dr=False
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def dry(self,v=True): self._dr=v
    def run(self):
        if self._dr: return CVR(True,[],0,0,0,0.0)
        pr=self._pr.predict(); obs,an,so=self._ob.obs(); fs=[]; cf=pr&obs; so_=pr-obs; do_=obs-pr; pc={}; as_=len(an)>=2; lh=_dlp(so); ss=_dss(so)
        for cat in cf: self._pr.ra(cat,True); fs.append(VF('ok',f'{cat}=',self._pr.gc(cat),1.0,1.0)); pc[cat]='ok'
        for cat in so_: self._pr.ra(cat,False); fs.append(VF('fp',f'{cat} so',self._pr.gc(cat),0.0,0.0,cat in('mem','proc'))); pc[cat]='fp'
        for cat in do_: fs.append(VF('new',f'{cat} do',0.0,1.0,0.0)); pc[cat]='new'
        for sl in ss: an.append(f'sus:{sl}')
        ag=len(cf)/max(1,len(pr|obs))
        if as_: ag=max(0.0,ag-0.3)
        if lh: ag=max(0.0,ag-0.2); _inc('cv.runs',1); return CVR(True,fs,len(pr),len(obs),len(cf),round(ag,2),pc,an,as_,lh)
    def rm(self,ins):
        ch=defaultdict(int); tr=0; pis=[]
        for inp in ins:
            try:
                r=subprocess.run(['strace','-f','-e','trace=all',self._bp],input=inp,capture_output=True,text=True,timeout=10); o=r.stderr.lower(); cfs=[]
                for cat,pats in self._ob._CR.items():
                    for pat in pats:
                        if re.search(pat,o): ch[cat]+=1; cfs.append(cat); break
                pis.append({'sz':len(inp),'cats':cfs,'an':_dss(o)}); tr+=1
            except: continue
        return{cat:round(hits/max(tr,1),2)for cat,hits in ch.items()},pis
    @property
    def pa(self): return self._pr.oa

def ccv(bp): return CV(bp)
