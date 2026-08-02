# Kernel driver v0.5 — IOCTL/caps/IRP/WDF/eBPF/modinfo, dry-run, op timeout
import re,struct,subprocess,os,logging
from dataclasses import dataclass,field; from enum import Enum,auto; from typing import Any,Dict,List

logger=logging.getLogger(__name__)
def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class IC: code:int;fn:str;ac:str;ha:int
class DC(Enum): RP="RP";WP="WP";MIO="MIO";ANP="ANP";DMA="DMA";MSR="MSR";PIO="PIO";KEX="KEX"
@dataclass class DR: nm:str;pl:str;ios:List[IC]=field(default_factory=list);caps:List[DC]=field(default_factory=list);dg:List[str]=field(default_factory=list);meta:Dict[str,Any]=field(default_factory=dict);irp:Dict[int,int]=field(default_factory=dict);pt:List[str]=field(default_factory=list);sg:bool=False;fw:str='';mi:Dict[str,str]=field(default_factory=dict);eb:float=0.0;wd:List[str]=field(default_factory=list)

def _plat(fp):
    with open(fp,"rb")as f: h=f.read(128)
    if h[:2]==b"MZ": return"win_"+{0x8664:"x64",0x014C:"x86"}.get(struct.unpack_from("<H",h,struct.unpack_from("<I",h,0x3C)[0]+4)[0],"unk")
    if h[:4]==b"\x7fELF": return"linux_"+{0x3E:"x64",0x03:"x86",0x28:"arm",0xB7:"arm64",0xF7:"ebpf"}.get(struct.unpack_from("<H",h,18)[0],"unk")
    return"unknown"

def _mod(d): return{k:m.group(1).decode('ascii',errors='replace')for k,pat in{'lic':rb'license=([^\x00]+)','auth':rb'author=([^\x00]+)','ver':rb'vermagic=([^\x00]+)'}.items()if(m:=re.search(pat,d))}
def _ebr(d): r=0.0; t=d.decode('ascii',errors='ignore').lower()
for h in['bpf_probe_read','bpf_probe_write_user']:
    if h in t: r+=0.15
    return min(r,1.0)
def _wdf(d): t=d.decode('ascii',errors='ignore'); devs=[]
for m in re.finditer(r'WdfDeviceCreate|WdfControlDeviceInitAllocate|IoCreateDevice',t): devs.append(t[max(0,m.start()-40):m.end()+40].replace('\x00',' ').strip()[:80])
return devs[:20]

class IA:
    def __init__(self,fp): self.fp=fp; self.pl=_plat(fp); self._r2=subprocess.run(["r2","-v"],capture_output=True,timeout=5).returncode==0
    def ex(self):
        rs=[]
        if not self._r2: return rs
        if self.pl.startswith("win"): rs.extend(self._wi())
        elif self.pl.startswith("linux"): rs.extend(self._li())
        return rs
    def _wi(self):
        rs=[]
        try:
            for p in["DeviceIoControl","IRP_MJ_DEVICE_CONTROL"]:
                h=subprocess.run(["r2","-q","-c",f"/ {p}",self.fp],capture_output=True,text=True,timeout=30).stdout
                for l in h.splitlines():
                    m=re.match(r"0x[0-9a-fA-F]+",l.strip())
                    if m: rs.append(IC(0,p,"BUF",int(m.group(),16)))
        except: pass
        return rs
    def _li(self):
        rs=[]
        try:
            s=subprocess.run(["r2","-q","-c","is~ioctl",self.fp],capture_output=True,text=True,timeout=30).stdout
            for l in s.splitlines():
                p=l.split()
                if len(p)>=3:
                    try: a=int(p[1],16); nm=p[-1]
                    if"ioctl"in nm: rs.append(IC(0xA000,nm,"NEI",a))
                    except: continue
        except: pass
        return rs
    def rirp(self):
        d={}
        if not self.pl.startswith("win")or not self._r2: return d
        try:
            o=subprocess.run(["r2","-q","-c","pD $SS @ $S",self.fp],capture_output=True,text=True,timeout=60).stdout
            for m in re.finditer(r'mov\s+(?:qword\s+)?\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+)\]\s*,\s*(0x[0-9a-fA-F]+)',o,re.I):
                try: off=int(m.group(2),16);h=int(m.group(3),16);idx=off//8
                if 0<=idx<=27: d[idx]=h
                except: continue
        except: pass
        return d

DANG=["MmMapIoSpace","MmCopyMemory","__readmsr","__writemsr","ZwMapViewOfSection","IoAllocateMdl"]
def _cd(c,fp):
    f=[]
    try:
        d=subprocess.run(["r2","-q","-c",f"pD @ {c.ha}",fp],capture_output=True,text=True,timeout=30).stdout
        for a in DANG:
            if a.lower()in d.lower(): f.append(f"IOCTL {hex(c.code)} {a}")
    except: pass
    if c.ac=="NEI": f.append(f"IOCTL {hex(c.code)} NEITHER")
    return f

class CC:
    def __init__(self,d): self._d=d
    def cr(self):
        c=[]; t=self._d.decode("ascii",errors="ignore")
        for cap,kw in{DC.RP:["MmMapIoSpace"],DC.MIO:["IoAllocateMdl"],DC.MSR:["__readmsr"],DC.PIO:["READ_PORT"]}.items():
            if any(k in t for k in kw): c.append(cap)
        return c
    def cw(self):
        c=[]; t=self._d.decode("ascii",errors="ignore")
        for cap,kw in{DC.WP:["MmMapIoSpace"],DC.MSR:["__writemsr"],DC.PIO:["WRITE_PORT"]}.items():
            if any(k in t for k in kw): c.append(cap)
        return c
    def cx(self):
        c=[]; t=self._d.decode("ascii",errors="ignore")
        if any(x in t for x in["MmAllocateNonCachedMemory","ZwAllocateVirtualMemory"]): c.append(DC.KEX)
        if any(x in t for x in["HalGetBusData","HalSetBusData"]): c.append(DC.DMA)
        return c

def _pt(d):
    ts=set()
    for m in re.compile(rb'(?<![a-zA-Z0-9])([A-Za-z0-9]{4})(?![a-zA-Z0-9])').finditer(d):
        t=m.group(1).decode("ascii",errors="ignore")
        if t.isalnum()and not t.isdigit(): ts.add(t)
    return sorted(ts)[:50]
def _fw(d):
    t=d.decode("ascii",errors="ignore")
    if"WdfDriverCreate"in t: return"WDF"
    if"UMDF"in t: return"UMDF"
    return"unknown"

def akd(fp,dr=False):
    if not os.path.exists(fp): raise FileNotFoundError(fp)
    if dr: return DR(os.path.basename(fp),_plat(fp))
    pl=_plat(fp); dn=os.path.basename(fp)
    with open(fp,"rb")as f: rd=f.read()
    a=IA(fp); io=a.ex(); irp=a.rirp(); ch=CC(rd); caps=list(set(ch.cr()+ch.cw()+ch.cx())); dg=[]
    for i in io: dg.extend(_cd(i,fp))
    if"MmMapIoSpace"in rd.decode("ascii",errors="ignore"): dg.append("MmMapIoSpace")
    pt=_pt(rd); fw=_fw(rd); mi=_mod(rd)if pl.startswith("linux")else{}; eb=_ebr(rd)if'ebpf'in pl else 0.0; wd=_wdf(rd)if pl.startswith("win")else[]; sg=False
    try: po=struct.unpack_from("<I",rd,0x3C)[0]; mg=struct.unpack_from("<H",rd,po+24)[0]; sg=struct.unpack_from("<I",rd,po+24+(112 if mg==0x20b else 96)+32)[0]!=0
    except: pass
    _inc('kdr.a',1); return DR(dn,pl,io,caps,dg,{"sz":len(rd)},irp,pt,sg,fw,mi,eb,wd)

def sdd(dp):
    rs=[]
    for r,_,fs in os.walk(dp):
        for fn in fs:
            if os.path.splitext(fn)[1].lower()in{".sys",".ko",".kext",".dll",".efi"}:
                try: rs.append(akd(os.path.join(r,fn)))
                except: pass
    return rs
