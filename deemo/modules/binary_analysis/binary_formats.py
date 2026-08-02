# Binary formats v0.5 — MMapReader, chunked, COFF/eBPF/SPARC, compression export
import struct,os,math,hashlib,mmap
from enum import Enum,auto; from dataclasses import dataclass,field; from collections import Counter

class Arch(Enum): X86=auto();X86_64=auto();ARM=auto();ARM64=auto();MIPS=auto();PPC=auto();SPARC=auto();RISCV=auto();WASM=auto();EBPF=auto();UNKNOWN=auto()
class Endian(Enum): LITTLE=auto();BIG=auto()

@dataclass class SI: nm:str;va:int;vs:int;ro:int;rs:int;ent:float=0.0;wx:bool=False;enc:bool=False
@dataclass class BI: fp:str;fmt:str='';arch:Arch=Arch.UNKNOWN;end:Endian=Endian.LITTLE;bits:int=32;pkr:str='';ep:int=0;secs:list=field(default_factory=list);sha256:str='';ee:float=0.0;rvf:float=0.0;uw:bool=False;dbl:str=''

MAGIC={b'\x7fELF':'ELF',b'MZ':'PE',b'ZM':'PE',b'\xce\xfa\xed\xfe':'MO',b'\xcf\xfa\xed\xfe':'MO',b'BZh':'bzip2',b'\x1f\x8b':'gzip',b'PK\x03\x04':'ZIP',b'\x00asm':'WASM',b'\x4c\x01':'COFF'}
ELF_M={0x00:Arch.UNKNOWN,0x02:Arch.SPARC,0x03:Arch.X86,0x08:Arch.MIPS,0x14:Arch.PPC,0x28:Arch.ARM,0x3E:Arch.X86_64,0xB7:Arch.ARM64,0xF3:Arch.RISCV,0xF7:Arch.EBPF}
PE_M={0x014c:(Arch.X86,32),0x8664:(Arch.X86_64,64),0x01c0:(Arch.ARM,32),0xaa64:(Arch.ARM64,64)}
_CH=256*1024*1024; _LG=1024*1024*1024

def _ent(d):
    n=len(d); ent=0.0
    if n==0: return 0.0
    for c in Counter(d).values(): p=c/n; ent-=p*math.log2(p)
    return ent

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

class MMR:
    def __init__(self,fp,off=0,sz=None): self.fp=fp; self.off=off; self.sz=sz; self._f=None; self._m=None
    def __enter__(self):
        self._f=open(self.fp,'rb'); fsz=os.path.getsize(self.fp); rs=min(self.sz or fsz,fsz-self.off)
        self._m=mmap.mmap(self._f.fileno(),0,access=mmap.ACCESS_READ); return self._m[self.off:self.off+rs]
    def __exit__(self,*_):
        if self._m: self._m.close()
        if self._f: self._f.close()
        return False

def _rh(fp,n=64):
    with open(fp,'rb')as f: return f.read(n)
def _rb(fp,off,sz):
    fsz=os.path.getsize(fp)
    if fsz>_LG:
        try:
            with MMR(fp,off,min(sz,fsz-off))as d: return bytes(d)
        except: pass
    with open(fp,'rb')as f: f.seek(off); return f.read(min(sz,fsz-off))
def _rf(fp):
    sz=os.path.getsize(fp)
    if sz>_LG:
        try:
            with MMR(fp,0,sz)as d: return bytes(d)
        except: pass
    with open(fp,'rb')as f: return f.read()

def achunk(fp,ch=_CH):
    sz=os.path.getsize(fp)
    if sz<=_LG: return[analyze(fp)]
    chs=[]
    for off in range(0,min(sz,ch*4),ch): blob=_rb(fp,off,min(ch,sz-off)); ent=_ent(blob); sd=sum(1 for b in blob if 32<=b<127)/max(len(blob),1); chs.append({'off':off,'sz':len(blob),'ent':round(ent,2),'sd':round(sd,3)})
    return chs

def _pe(d):
    if len(d)<64: raise ValueError("short"); idt=d[:16]; cls,ed=idt[4],idt[5]; bits=64 if cls==2 else 32; end='>'if ed==2 else'<'; ee=Endian.BIG if ed==2 else Endian.LITTLE
    if bits==64: et,em,ev,ep=struct.unpack_from(f'{end}HHIQ',d,16); a=ELF_M.get(em,Arch.UNKNOWN)
    else: et,em,ev,ep=struct.unpack_from(f'{end}HHII',d,16); a=ELF_M.get(em,Arch.UNKNOWN)
    return{'bits':bits,'end':ee,'arch':a,'ep':ep}
def _pep(d):
    if len(d)<2 or d[:2]not in(b'MZ',b'ZM'): raise ValueError("Not PE")
    po=struct.unpack_from('<I',d,0x3C)[0]; r={'bits':32,'arch':Arch.UNKNOWN,'ep':0,'hp':False}
    if po==0 or po>len(d)-4: return r; m=struct.unpack_from('<H',d,po+4+4)[0]; pa=PE_M.get(m,(Arch.UNKNOWN,32)); r['arch']=pa[0]; r['bits']=pa[1]
    os_=po+24
    if len(d)>os_+16: mg=struct.unpack_from('<H',d,os_)[0]; r['ep']=struct.unpack_from('<I',d,os_+16)[0]
    return r
def _pdb(d):
    idx=d.find(b'.gnu_debuglink')
    if idx==-1: return''; s=idx+16; e=d.find(b'\x00',s); return d[s:e].decode('ascii',errors='replace')if e!=-1 else''

def dfmt(fp):
    d=_rh(fp,64)
    for sig,fmt in MAGIC.items():
        if d.startswith(sig): return fmt
    return'UNKNOWN'
def _da(fp):
    m={'x86':(Arch.X86,32),'amd64':(Arch.X86_64,64),'arm':(Arch.ARM,32),'aarch64':(Arch.ARM64,64),'mips':(Arch.MIPS,32),'sparc':(Arch.SPARC,32),'riscv':(Arch.RISCV,32),'ebpf':(Arch.EBPF,64)}
    try:
        import subprocess; o=subprocess.check_output(['r2','-q','-c','iI',fp],stderr=subprocess.DEVNULL,timeout=10).decode(errors='ignore')
        for l in o.splitlines():
            if'arch'in l.lower(): return m.get(l.split()[-1].strip().lower(),(Arch.UNKNOWN,32))
    except: pass
    return(Arch.UNKNOWN,32)
def _de(d):
    if len(d)<6: return Endian.LITTLE
    if d[:4]==b'\x7fELF': return Endian.BIG if d[5]==2 else Endian.LITTLE
    return Endian.LITTLE
def _rvf(ss):
    if len(ss)<2: return 0.0; va=sorted(s.va for s in ss if s.va>0)
    if len(va)<2: return 0.0; gps=[va[i]-va[i-1]for i in range(1,len(va))]
    if not gps: return 0.0; ag=sum(gps)/len(gps)
    if ag==0: return 0.0; v=sum((g-ag)**2 for g in gps)/len(gps)
    return round(1.0-min((v**0.5)/ag,1.0),2)
def _dp(fp):
    for kw,nm in{'upx':'UPX','aspack':'ASPack'}.items():
        if kw in os.path.basename(fp).lower(): return nm
    return''
def _ps(fp):
    ss=[]
    try:
        import subprocess,json; o=subprocess.check_output(['r2','-q','-c','iSj',fp],stderr=subprocess.DEVNULL,timeout=15).decode(errors='ignore')
        for s in json.loads(o): sec=SI(s.get('name',''),s.get('vaddr',0),s.get('vsize',0),s.get('paddr',0),s.get('size',0))
        try: raw=_rb(fp,sec.ro,min(sec.rs,4096)); sec.ent=_ent(raw); sec.enc=sec.ent>7.8 and Counter(raw).most_common(1)[0][1]/max(len(raw),1)<0.05
        except: sec.ent=0.0; ss.append(sec)
    except: pass
    return ss

def analyze(fp):
    fmt=dfmt(fp); info=BI(fp=fp,fmt=fmt); d=_rh(fp,512); info.end=_de(d)
    try: info.sha256=hashlib.sha256(_rf(fp)).hexdigest()
    except: pass
    try:
        if fmt=='ELF': h=_pe(d); info.arch=h['arch']; info.bits=h['bits']; info.end=h['end']; info.ep=h['ep']; info.dbl=_pdb(d)
        elif fmt=='PE': h=_pep(d); info.arch=h['arch']; info.bits=h['bits']; info.ep=h['ep']; info.uw=h.get('hp',False)
        else: at=_da(fp); info.arch=at[0]; info.bits=at[1]
    except: at=_da(fp); info.arch=at[0]; info.bits=at[1]
    info.pkr=_dp(fp); info.secs=_ps(fp)
    if info.ep>0:
        try: info.ee=_ent(_rb(fp,info.ep,256))
        except: info.ee=0.0
    info.rvf=_rvf(info.secs); _inc('fmt.a',1); return info

if __name__=='__main__':
    import sys
    if len(sys.argv)>1: r=analyze(sys.argv[1]); print(f"Fmt:{r.fmt} Arch:{r.arch.name} {r.bits}bit EP:0x{r.ep:x} SHA256:{r.sha256[:32]}...")
