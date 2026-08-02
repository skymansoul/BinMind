# Function boundary v0.5 — prologue/epilogue/entropy/CFG/ebpf, dry-run, fused voting
import math,os,re,struct,subprocess,logging,json
from collections import defaultdict; from dataclasses import dataclass,field; from typing import Any,Dict,List

logger=logging.getLogger(__name__)
EBPF=b'\x95\x00\x00\x00\x00\x00\x00\x00'; XP=[b'\x55\x48\x89\xe5',b'\x55\x89\xe5',b'\x48\x83\xec']; XE=[b'\x5d\xc3',b'\xc9\xc3']; AP=[b'\x2d\xe9']; AE=[b'\xbd\xe8']; A64P=[b'\xa9\xbf']; A64E=[b'\xc0\x03\x5f\xd6']; MP=[b'\x27\xbd']; ME=[b'\x03\xe0\x00\x08']; RP=[b'\x01\x11']; RE=[b'\x82\x80']

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class FB: sa:int;ea:int;cf:float;dm:str;md:Dict[str,Any]=field(default_factory=dict)

class BD:
    def __init__(self,d,a="auto"): self._d=d; self._a=a if a!="auto"else self._g(); self._dr=False
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def dry(self,v=True): self._dr=v
    def _g(self):
        if len(self._d)<4: return"unknown"
        if self._d[:4]==b"\x7fELF": m=struct.unpack_from("<H",self._d,18)[0]; return{0x03:"x86",0x3E:"amd64",0x28:"arm",0xB7:"arm64",0x08:"mips",0xF3:"riscv",0xF7:"ebpf"}.get(m,"unknown")
        return"unknown"

    def dp(self):
        r=[]; am={"x86":(XP,XE),"amd64":(XP,XE),"arm":(AP,AE),"arm64":(A64P,A64E),"mips":(MP,ME),"riscv":(RP,RE)}
        pp,ep=am.get(self._a,(XP+AP+A64P+MP+RP,XE+AE+A64E+ME+RE)); ph=[]; eh=[]
        for p in pp:
            idx=0
            while True: idx=self._d.find(p,idx)
            if idx==-1: break; ph.append(idx); idx+=1
        for p in ep:
            idx=0
            while True: idx=self._d.find(p,idx)
            if idx==-1: break; eh.append(idx+len(p)); idx+=1
        ph.sort(); eh.sort()
        for pa in ph:
            be=None
            for ea in eh:
                if ea>pa: be=ea; break
            if be and be-pa<0x10000: r.append(FB(pa,be,0.9,"prologue"))
        return r

    def dpa(self):
        r=[]; i=0; n=len(self._d)
        while i<n-3:
            if self._d[i]in(0xCC,0x90)and self._d[i]==self._d[i+1]==self._d[i+2]:
                j=i
                while j<n and self._d[j]==self._d[i]: j+=1
                if j-i>=3: r.append(FB(j,j+64,0.55,"pad")); i=j
            else: i+=1
        return r

    def den(self):
        r=[]; ed=self._se()
        if len(ed)<3: return r
        for j in range(1,len(ed)-1): o,e=ed[j]; _,pe=ed[j-1]; _,ne=ed[j+1]; d=abs(e-pe)+abs(ne-e)
        if d>0.8: r.append(FB(o,o+64,0.6,"ent"))
        return r
    def _se(self,w=64,s=16):
        ent=[]
        for off in range(0,len(self._d)-w,s):
            c=self._d[off:off+w]; f=[0]*256; [f.__setitem__(b,f[b]+1)for b in c]; h=sum(-(x/w)*math.log2(x/w)for x in f if x>0); ent.append((off,h))
        return ent

    def dcfg(self,fp):
        r=[]
        try:
            o=subprocess.run(["r2","-q","-c","afij",fp],capture_output=True,text=True,timeout=30)
            for f in json.loads(o.stdout)if o.stdout.strip()else[]:
                a=f.get("offset",0); sz=f.get("size",0)
                if a>0 and sz>0: r.append(FB(a,a+sz,0.85,"cfg"))
        except: pass
        return r

    def debpf(self):
        if self._a!='ebpf': return[]
        r=[]; idx=0
        while True: idx=self._d.find(EBPF,idx)
        if idx==-1: break; r.append(FB(max(0,idx-64),idx+8,0.7,"ebpf")); idx+=1
        return r

    def fused(self,fp=''):
        ar=[]; ar.extend(self.dp()); ar.extend(self.dpa()); ar.extend(self.den())
        if self._a=='ebpf': ar.extend(self.debpf())
        if fp: ar.extend(self.dcfg(fp))
        return _dd(ar)

    def incr(self,ex,st,en):
        up=[b for b in ex if b.ea<st or b.sa>en]; rd=BD(self._d[st:en],self._a).fused()
        for b in rd: b.sa+=st; b.ea+=st
        return _dd(up+rd)

def mlbd(d,m=None): return BD(d).fused()
def fab(fp):
    with open(fp,"rb")as f: d=f.read()
    m=BD(d).fused(fp); m.sort(key=lambda b:b.sa); _inc('bnd.f',len(m)); return m

def _dd(b):
    if not b: return[]
    sb=sorted(b,key=lambda x:(x.sa,-x.cf)); m=[sb[0]]
    for x in sb[1:]:
        l=m[-1]; o=max(0,min(l.ea,x.ea)-max(l.sa,x.sa))
        if o/max(x.ea-x.sa,1)>0.7:
            if x.cf>l.cf: m[-1]=x
        else: m.append(x)
    return m

class BV:
    @staticmethod
    def render(b,dl,w=80):
        cv=bytearray(dl); [cv.__setitem__(i,1)for bd in b for i in range(max(0,bd.sa),min(dl,bd.ea+1))]; bs=max(dl//w,1); vis=[]
        for col in range(w): s=col*bs; e=min(s+bs,dl); r=sum(cv[s:e])/max(e-s,1); vis.append("#"if r>0.8 else"."if r>0.3 else" ")
        return f"[0]{'-'*(w-4)}[{dl}]\n{''.join(vis)}"
