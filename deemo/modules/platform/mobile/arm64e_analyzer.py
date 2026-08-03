#!/usr/bin/env python3
"""
ARM64e增强安全分析。Apple Silicon PAC/BTI深度审计、微架构侧信道、ARM MTE内存标签检测。

维度：
  1. PAC指令检测——指针认证指令全量识别
  2. PAC签名gadget——签名神谕与绕过路径扫描
  3. PAC绕过路径——指针替换/重放攻击可行性
  4. BTI着陆点——间接跳转目标BTI覆盖率与违规
  5. JOP/COP gadget——PAC约束下的抗JOP评估，含支配图剪枝
  6. 密钥多样性——IA/IB/DA/DB密钥域统计与隔离
  7. 签名剥离——JIT代码页签名剥离识别
  8. 跨库PAC绕过链——dyld共享缓存跨边界认证转发
  9. 微架构侧信道——ExfilState式无定时器cache状态泄露
  10. ARM MTE——内存标签扩展使用审计与TikTag旁路扫描

基础：
  - ARMv8.3-A/ARMv8.6-A指令集反汇编模式匹配
  - MTE（ARMv8.5-A）指令编码见ARM架构参考手册
  - TikTag（IEEE S&P 2025）：推测执行泄露MTE标签的gadget
  - NanoTag（IEEE S&P 2026）：Pixel 8字节级溢出检测特征
  - Folded-Tag（C&S 2026）：XOR指针掩码加固

MTE指令编码：
  IRG  Xd, Xn{, Xm}     — 插入随机tag到指针
  ADDG Xd, Xn, #imm{, #uimm4}  — tag感知地址加法
  SUBG Xd, Xn, #imm{, #uimm4}  — tag感知地址减法
  STG  Xt, [Xn{, #simm}] — 存储allocation tag到tag memory
  LDG  Xt, [Xn{, #simm}] — 从tag memory加载tag
  STZG Xt, [Xn{, #simm}] — 零填充并存储tag
  LDGV Xt, [Xn]          — 加载tag并验证（不匹配则trap）
  STGV Xt, [Xn]          — 存储tag并验证
  CMPP Xn, Xm/XZR        — 指针tag比较
"""

import logging, os, re, subprocess, json
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

_logger = logging.getLogger(__name__)


class PACKey(str, Enum): IA="IA"; IB="IB"; DA="DA"; DB="DB"; GA="GA"; UNKNOWN="UNKNOWN"

class PACInstructionType(str, Enum):
    PACIASP="paciasp"; PACIBSP="pacibsp"; AUTIASP="autiasp"; AUTIBSP="autibsp"
    PACIA="pacia"; PACIB="pacib"; PACDA="pacda"; PACDB="pacdb"; PACGA="pacga"
    AUTIA="autia"; AUTIB="autib"; AUTDA="autda"; AUTDB="autdb"
    XPACI="xpaci"; XPACD="xpacd"; RETAB="retab"
    BRAA="braa"; BRAB="brab"; BLRAA="blraa"; BLRAB="blrab"
    ERETAA="eretaa"; ERETAB="eretab"; UNKNOWN="unknown"

    @property
    def key(self)->PACKey:
        _m={"paciasp":PACKey.IA,"paciab":PACKey.IA,"pacia":PACKey.IA,"autiasp":PACKey.IA,"autiab":PACKey.IA,"autia":PACKey.IA,"braa":PACKey.IA,"blraa":PACKey.IA,"eretaa":PACKey.IA,"pacibsp":PACKey.IB,"pacibab":PACKey.IB,"pacib":PACKey.IB,"autibsp":PACKey.IB,"autibab":PACKey.IB,"autib":PACKey.IB,"brab":PACKey.IB,"blrab":PACKey.IB,"eretab":PACKey.IB,"retab":PACKey.IB,"pacda":PACKey.DA,"autda":PACKey.DA,"pacdb":PACKey.DB,"autdb":PACKey.DB,"pacga":PACKey.GA}
        return _m.get(self.value,PACKey.UNKNOWN)
    @property
    def is_sign(self)->bool: return self.value.startswith("pac")
    @property
    def is_auth(self)->bool: return self.value.startswith("aut") or self.value=="retab"
    @property
    def is_branch(self)->bool: return self.value in ("braa","brab","blraa","blrab","eretaa","eretab","retab")
    @property
    def is_strip(self)->bool: return self.value.startswith("xpac")

class BTIInstructionType(str, Enum): BTI_C="bti c"; BTI_J="bti j"; BTI_JC="bti jc"

class Severity(str, Enum):
    CRITICAL="CRITICAL"; HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; INFO="INFO"
    @property
    def weight(self)->int: return {"CRITICAL":32,"HIGH":16,"MEDIUM":8,"LOW":4,"INFO":1}[self.value]

class SideChannelGadgetType(str, Enum):
    CSDB_COND_BRANCH="csdb_cond_branch"; DC_CVAU_EXCEPTION="dc_cvau_exception"
    PSTATE_TIMING="pstate_timing"; LDAR_STLR_PAIR="ldar_stlr_pair"
    DMB_DSB_FENCE="dmb_dsb_fence"; SYSREG_ACCESS="sysreg_access"

# ── MTE标签操作类型 ──
class MTEOperationType(str, Enum):
    IRG="irg"           # 插入随机tag
    ADDG="addg"         # tag感知地址加法
    SUBG="subg"         # tag感知地址减法
    STG="stg"           # 存储allocation tag
    LDG="ldg"           # 加载allocation tag
    STZG="stzg"         # 零填充并存储tag
    LDGV="ldgv"         # 加载tag并验证
    STGV="stgv"         # 存储tag并验证
    CMPP="cmpp"         # 指针tag比对
    GMI="gmi"           # 插入tag，不含随机分量

@dataclass
class PACInstruction:
    address:int; mnemonic:str; insn_type:PACInstructionType; key:PACKey; function_name:str=""
    def to_dict(self)->Dict[str,Any]: return {"addr":f"0x{self.address:X}","mnemonic":self.mnemonic,"type":self.insn_type.value,"key":self.key.value,"func":self.function_name}

@dataclass
class BTIInstruction:
    address:int; insn_type:BTIInstructionType; function_name:str=""; is_function_entry:bool=False; missing_preceding:bool=False
    def to_dict(self)->Dict[str,Any]: return {"addr":f"0x{self.address:X}","type":self.insn_type.value,"func":self.function_name,"entry":self.is_function_entry,"missing":self.missing_preceding}

@dataclass
class SideChannelGadget:
    address:int; gadget_type:SideChannelGadgetType; mnemonic_sequence:List[str]
    registers_involved:Set[str]; leaks_cache_state:bool; leaks_tlb_state:bool
    exploitable_without_timer:bool; severity:Severity; function_name:str=""
    def to_dict(self)->Dict[str,Any]: return {"addr":f"0x{self.address:X}","type":self.gadget_type.value,"seq":self.mnemonic_sequence,"regs":sorted(self.registers_involved),"cache_leak":self.leaks_cache_state,"tlb_leak":self.leaks_tlb_state,"timer_free":self.exploitable_without_timer,"severity":self.severity.value,"func":self.function_name}

@dataclass
class MTEGadget:
    address:int; operation:MTEOperationType; mnemonic:str; tag_reg:str; pointer_reg:str
    function_name:str=""; is_allocation:bool=False; is_deallocation:bool=False; tiktag_vulnerable:bool=False
    def to_dict(self)->Dict[str,Any]: return {"addr":f"0x{self.address:X}","op":self.operation.value,"mnemonic":self.mnemonic,"tag_reg":self.tag_reg,"ptr_reg":self.pointer_reg,"func":self.function_name,"alloc":self.is_allocation,"dealloc":self.is_deallocation,"tiktag":self.tiktag_vulnerable}

@dataclass
class PACSigningGadget:
    address:int; sign_insn:str; source_reg:str; modifier_reg:str; key:PACKey; context:str; is_oracle:bool; controllable_modifier:bool; severity:Severity
    def to_dict(self)->Dict[str,Any]: return {"addr":f"0x{self.address:X}","sign":self.sign_insn,"src":self.source_reg,"mod":self.modifier_reg,"key":self.key.value,"oracle":self.is_oracle,"ctrl":self.controllable_modifier,"severity":self.severity.value}

@dataclass
class PACBypassPath:
    source_addr:int; target_addr:int; auth_insn:str; bypass_type:str; authenticated_ptr:str; replaceable_with:str; key:PACKey; difficulty:str; severity:Severity
    def to_dict(self)->Dict[str,Any]: return {"src":f"0x{self.source_addr:X}","tgt":f"0x{self.target_addr:X}","auth":self.auth_insn,"type":self.bypass_type,"key":self.key.value,"diff":self.difficulty,"severity":self.severity.value}

@dataclass
class JOPGadget:
    address:int; gadget_type:str; sequence:list; dst_reg:str="x16"; pac_protected:bool=False; pac_key:PACKey=PACKey.UNKNOWN; bti_landing:bool=False; usefulness:str="unknown"; severity:Severity=Severity.INFO; post_dominators:Set[int]=field(default_factory=set); pruned:bool=False
    def to_dict(self)->Dict[str,Any]: return {"addr":f"0x{self.address:X}","type":self.gadget_type,"seq":self.sequence,"pac":self.pac_protected,"pkey":self.pac_key.value,"bti":self.bti_landing,"use":self.usefulness,"severity":self.severity.value,"pruned":self.pruned}

@dataclass
class StripSignatureRegion:
    addr_range:tuple; strip_count:int; resign_count:int; likely_jit:bool; jit_calls:int; risk:str
    def to_dict(self)->Dict[str,Any]: return {"range":[f"0x{self.addr_range[0]:X}",f"0x{self.addr_range[1]:X}"],"strips":self.strip_count,"resigns":self.resign_count,"jit":self.likely_jit,"jit_calls":self.jit_calls,"risk":self.risk}

@dataclass
class CrossLibraryPACChain:
    caller_lib:str; caller_func:str; callee_lib:str; callee_func:str; caller_key:PACKey; callee_key:PACKey; key_mismatch:bool; auth_forwarded:bool; ga_used:bool; risk_level:Severity
    def to_dict(self)->Dict[str,Any]: return {"clib":self.caller_lib,"cfunc":self.caller_func,"dlib":self.callee_lib,"dfunc":self.callee_func,"ckey":self.caller_key.value,"dkey":self.callee_key.value,"mismatch":self.key_mismatch,"ga":self.ga_used,"risk":self.risk_level.value}

# MTE指令编码模式，基于ARM架构参考手册32-bit编码空间
_MTE_PATTERNS = [
    (re.compile(rb'\x20\x0c\x9a\xd7'), MTEOperationType.IRG, "IRG——插入随机tag到指针"),
    (re.compile(rb'[\x00-\x1f]\x00\x18\x91'), MTEOperationType.ADDG, "ADDG——tag感知地址加法"),
    (re.compile(rb'[\x00-\x1f]\x00\x18\xd1'), MTEOperationType.SUBG, "SUBG——tag感知地址减法"),
    (re.compile(rb'[\x00-\x1f]\x90\x19\xd9'), MTEOperationType.STG, "STG——存储allocation tag"),
    (re.compile(rb'[\x00-\x1f]\x90\x5d\xd9'), MTEOperationType.LDG, "LDG——加载allocation tag"),
    (re.compile(rb'[\x00-\x1f]\xd0\x19\xd9'), MTEOperationType.STZG, "STZG——零填充+tag存储"),
    (re.compile(rb'[\x00-\x1f]\x60\xdf\xd6'), MTEOperationType.LDGV, "LDGV——加载tag并验证"),
    (re.compile(rb'[\x00-\x1f]\xa0\xdf\xd6'), MTEOperationType.STGV, "STGV——存储tag并验证"),
    (re.compile(rb'\x00\x00\xb4\xba'), MTEOperationType.CMPP, "CMPP——比较指针tag"),
    (re.compile(rb'\x20\x0c\x9b\xd7'), MTEOperationType.GMI, "GMI——插入tag(不含随机性)"),
]

# ── TikTag（IEEE S&P 2025）推测执行MTE标签泄露gadget ──
# LDG/LDGV后的条件分支暗示标签验证结果可通过推测执行泄露
_TIKTAG_PATTERNS = [
    (re.compile(rb'(?:ldg|ldgv)\s.{0,32}(?:cbz|cbnz|tbz|tbnz)',re.DOTALL),
     "LDG/LDGV+条件分支——MTE标签验证结果可被推测执行泄露", Severity.HIGH),
    (re.compile(rb'stg.{0,64}(?:stg|ldg)',re.DOTALL),
     "密集tag内存操作——标签碰撞可通过时序暴露", Severity.MEDIUM),
]

_EXFIL_PATTERNS = [
    (re.compile(rb'\x9f\x3f\x03\xd5.{0,16}[\x40-\x5f]\x00\x00\x54',re.DOTALL),SideChannelGadgetType.CSDB_COND_BRANCH,"CSDB+条件分支——cache命中性通过分支方向泄露",True),
    (re.compile(rb'[\x20-\x2f]\x0c\x0b\xd5.{0,32}(?:eret|d65f03c0)',re.DOTALL),SideChannelGadgetType.DC_CVAU_EXCEPTION,"DC CVAU+异常返回",True),
    (re.compile(rb'[\x00-\x1f]\x41\x0b\xd5.{0,24}(?:cbz|cbnz|tbz|tbnz)',re.DOTALL),SideChannelGadgetType.PSTATE_TIMING,"PSTATE操作+条件分支",False),
    (re.compile(rb'(?:ldar|ldarb|ldarh)\s.{0,64}(?:stlr|stlrb|stlrh)',re.DOTALL),SideChannelGadgetType.LDAR_STLR_PAIR,"LDAR+STLR获取释放对",False),
    (re.compile(rb'(?:dmb|dsb)\s+(?:sy|ish|ld).{0,32}(?:dmb|dsb)\s+(?:sy|ish|ld)',re.DOTALL),SideChannelGadgetType.DMB_DSB_FENCE,"DMB/DSB密集区",False),
    (re.compile(rb'mrs\s+x\d+,\s*(?:s3_\d+_c\d+_c\d+_\d+|ctr_el0|dcache).{0,32}(?:cbz|cbnz)',re.DOTALL),SideChannelGadgetType.SYSREG_ACCESS,"系统寄存器读+条件分支",True),
]


def _compute_post_dominators(gs:Dict[int,JOPGadget],bts:Set[int])->Dict[int,Set[int]]:
    pd=defaultdict(set); sa=sorted(gs.keys()); n=len(sa)
    if n==0: return pd
    ea=sa[-1]
    for a in sa:
        if a!=ea: pd[a]={ea}
    for i,a in enumerate(sa):
        for j in range(i+1,min(i+5,n)):
            if sa[j] in bts: pd[a].add(sa[j])
    return dict(pd)


class Arm64eEnhancedAnalyzer:
    ALL_PAC=set(t.value for t in PACInstructionType if t!=PACInstructionType.UNKNOWN)
    BRANCH_RE=re.compile(r"\b(br|blr|ret)\b\s+x\d+",re.IGNORECASE)
    SIGN_RE=re.compile(r"0x([0-9a-fA-F]+)\s+(pac[ia][a-z0-9]*)\s+(\w+),\s*(\w+)",re.IGNORECASE)
    JIT_SYMS={"pthread_jit_write_protect_np","sys_icache_invalidate","vm_protect","mach_vm_remap","mmap"}
    LIB_PFX={"dyld_":"dyld","objc_":"libobjc","_objc":"libobjc","dispatch_":"libdispatch","pthread_":"libsystem_pthread","mach_":"libsystem_kernel","xpc_":"libxpc","os_":"libsystem"}
    _DISPATCHER_RE=re.compile(r"ldp.*ldr",re.IGNORECASE)

    def __init__(s,bp:str):
        s.binary_path=os.path.abspath(bp); s._funcs:List[Dict]=[]; s._imports:List[Dict]=[]
        s._arch="arm64e"; s._dc:Dict[int,str]={}

    def _r2(s,c:str,t:int=60)->str:
        try:
            r=subprocess.run(["r2","-q","-c",f"{c}; q",s.binary_path],capture_output=True,text=True,timeout=t,encoding="utf-8",errors="replace")
            return r.stdout if r.returncode==0 else ""
        except (subprocess.SubprocessError, FileNotFoundError): return ""  # bare except已收敛为SubprocessError

    def _load(s)->bool:
        try:
            s._arch=s._r2("e asm.arch",15).strip() or "arm64e"
            raw=s._r2("aaaa; aflj",120)
            if raw:
                j=json.loads(raw); s._funcs=j if isinstance(j,list) else []
            raw2=s._r2("aaa; iij",60)
            if raw2:
                j2=json.loads(raw2); s._imports=j2 if isinstance(j2,list) else []
            s._func_by_addr=sorted(s._funcs,key=lambda f:f.get("offset",0))
            return True
        except Exception as e: _logger.warning("Load failed: %s",e); return False

    def _disasm(s,addr:int)->str:
        if addr not in s._dc: s._dc[addr]=s._r2(f"s 0x{addr:X}; pdb",30)
        return s._dc[addr]

    def _func_for(s,addr:int)->str:
        funcs=getattr(s,'_func_by_addr',None) or s._funcs; lo,hi=0,len(funcs)-1
        while lo<=hi:
            mid=(lo+hi)//2; f=funcs[mid]; off=f.get("offset",0); sz=f.get("size",0)
            if off<=addr<off+sz: return f.get("name","")
            if addr<off: hi=mid-1
            else: lo=mid+1
        return ""

    def _func_addr(s,name:str)->Optional[int]: return next((f.get("offset") for f in s._funcs if f.get("name")==name),None)
    def _exported(s,name:str)->bool: return any(f.get("name")==name and f.get("type","") in ("sym","FUNC") for f in s._funcs)
    def _key_from(s,m:str)->PACKey:
        ml=m.lower()
        if "ga" in ml: return PACKey.GA
        if "ia" in ml: return PACKey.IA
        if "ib" in ml: return PACKey.IB
        if "da" in ml: return PACKey.DA
        if "db" in ml: return PACKey.DB
        return PACKey.UNKNOWN

    def _detect_pac(s)->List[PACInstruction]:
        res=[]; seen=set()
        for mn in sorted(s.ALL_PAC):
            for line in s._r2(f"aaaa; /ad/ {mn}",60).split("\n"):
                m=re.match(r"\s*(0x[0-9a-fA-F]+)\s+(\S+)",line)
                if not m: continue
                a,ins=int(m.group(1),16),m.group(2).lower()
                if a in seen: continue
                seen.add(a)
                it=next((t for t in PACInstructionType if t.value==ins),PACInstructionType.UNKNOWN)
                res.append(PACInstruction(a,ins,it,it.key,s._func_for(a)))
        return sorted(res,key=lambda x:x.address)

    def _signing_gadgets(s,pac:List[PACInstruction])->List[PACSigningGadget]:
        gs=[]; seen=set()
        for i in pac:
            if not i.insn_type.is_sign or not i.function_name or i.function_name in seen: continue
            seen.add(i.function_name); fa=s._func_addr(i.function_name)
            if not fa: continue
            for mm in s.SIGN_RE.finditer(s._disasm(fa)):
                a=int(mm.group(1),16); si=mm.group(2).lower(); src=mm.group(3); modr=mm.group(4)
                ctrl=modr.lower() not in ("sp","x31","wsp","wzr"); oracle=ctrl and s._exported(i.function_name)
                gs.append(PACSigningGadget(a,si,src,modr,s._key_from(si),i.function_name,oracle,ctrl,Severity.CRITICAL if oracle else (Severity.HIGH if ctrl else Severity.MEDIUM)))
        return gs

    def _bypass_paths(s,pac,_g)->List[PACBypassPath]:
        paths=[]; auths=[i for i in pac if i.insn_type.is_auth and not i.insn_type.is_strip]
        for auth in auths[:30]:
            fa=s._func_addr(auth.function_name) if auth.function_name else None
            if not fa: continue
            lines=s._disasm(fa).split("\n"); dr=None; ai=-1
            for idx,line in enumerate(lines):
                am=re.match(rf"\s*0x{auth.address:X}\s+(aut\w+)\s+(\w+)",line,re.IGNORECASE)
                if am: dr=am.group(2); ai=idx; break
            if not dr or ai<0: continue
            for j in range(ai+1,min(ai+15,len(lines))):
                if re.search(r"\b(br|blr)\s+"+re.escape(dr)+r"\s*$",lines[j],re.IGNORECASE):
                    ta=auth.address+(j-ai)*4; seg="\n".join(lines[ai:j+1])
                    if re.search(r"xpac[di]",seg,re.IGNORECASE): bt="strip_resign"
                    elif re.search(r"(str|stp)\s",seg,re.IGNORECASE): bt="replay"
                    else: bt="substitution"
                    df="trivial" if bt=="strip_resign" else ("moderate" if bt=="substitution" else "hard")
                    paths.append(PACBypassPath(auth.address,ta,auth.mnemonic,bt,dr,f"attacker_{dr}",auth.key,df,Severity.HIGH if bt in ("substitution","strip_resign") else Severity.MEDIUM)); break
        for i in pac:
            if i.insn_type not in (PACInstructionType.BLRAA,PACInstructionType.BLRAB): continue
            if not i.function_name: continue
            fa=s._func_addr(i.function_name)
            if not fa: continue
            if re.search(rf"0x{i.address:X}\s+blra[a-z].*@plt",s._disasm(fa),re.IGNORECASE):
                paths.append(PACBypassPath(i.address,0,i.mnemonic,"cross_library","lr","plt_stub_redirect",i.key,"moderate",Severity.HIGH))
        return paths

    def _verify_bti(s)->Tuple[List[BTIInstruction],float]:
        bis=[]; ba={}
        for line in s._r2("aaaa; /ad/ bti",60).split("\n"):
            m=re.match(r"\s*(0x[0-9a-fA-F]+)\s+(bti\s*\S*)",line)
            if m: a=int(m.group(1),16); ba[a]=m.group(2).strip().lower()
        for a,bs in ba.items():
            if "bti j" in bs and "jc" not in bs: bt=BTIInstructionType.BTI_J
            elif "bti c" in bs: bt=BTIInstructionType.BTI_C
            else: bt=BTIInstructionType.BTI_JC
            ie=any(f.get("offset")==a for f in s._funcs)
            bis.append(BTIInstruction(a,bt,s._func_for(a),ie,ie))
        ind=sum(len(s.BRANCH_RE.findall(s._disasm(f.get("offset",0)))) for f in s._funcs[:50])
        return bis,round(min(1.0,len(bis)/max(1,ind)),3)

    def _detect_jop(s,pac)->List[JOPGadget]:
        gs=[]; pl={i.address for i in pac}; bp_=re.compile(r"0x([0-9a-fA-F]+)\s+(br|blr|ret)\s+x?(\w+)",re.IGNORECASE)
        bts:Set[int]=set(); gm:Dict[int,JOPGadget]={}
        for f in s._funcs[:80]:
            fa=f.get("offset",0)
            if not fa: continue
            for ix,line in enumerate(s._disasm(fa).split("\n")):
                bm=bp_.search(line)
                if not bm: continue
                ba,bi,br=int(bm.group(1),16),bm.group(2).lower(),bm.group(3); bts.add(ba)
                seq=[]
                for j in range(max(0,ix-4),ix+1):
                    im=re.match(r".*0x[0-9a-fA-F]+\s+(\w+)",line)
                    if im: seq.append(im.group(1))
                gt="jop_dispatch" if bi in ("br","ret") else "cop_dispatch"; prot=ba in pl; pk=PACKey.UNKNOWN
                if prot:
                    for pi in pac:
                        if pi.address==ba: pk=pi.key; break
                bti=bool(re.search(r"bti\s",s._disasm(ba)[:200],re.IGNORECASE))
                ss=" ".join(seq).lower()
                if s._DISPATCHER_RE.search(ss): use="dispatcher"
                elif re.search(r"add.*(?:br|blr|ret)",ss): use="loader"
                elif len(seq)<=2: use="terminator"
                else: use="unknown"
                sev=Severity.LOW if prot else (Severity.HIGH if use=="dispatcher" else Severity.MEDIUM)
                g=JOPGadget(ba,gt,seq,br,prot,pk,bti,use,sev)
                gm[ba]=g; gs.append(g)
                if len(gs)>=25: break
            if len(gs)>=25: break
        if len(gm)>=3:
            pd=_compute_post_dominators(gm,bts)
            for addr,gadget in gm.items():
                if len(pd.get(addr,set()))<2 and gadget.usefulness=="unknown": gadget.pruned=True
        return gs

    def _key_dist(s,pac)->Dict[str,int]:
        d={"IA":0,"IB":0,"DA":0,"DB":0,"GA":0,"UNKNOWN":0,"_total":len(pac)}
        for i in pac: d[i.key.value]=d.get(i.key.value,0)+1
        d["_ia_ib"]=round(d["IA"]/max(1,d["IB"]),2); d["_da_db"]=round(d["DA"]/max(1,d["DB"]),2)
        d["_diversity"]=sum(1 for k in ("IA","IB","DA","DB","GA") if d[k]>0)
        nz=sorted(v for k,v in d.items() if k in ("IA","IB","DA","DB","GA") and v>0)
        if len(nz)>=2:
            n=len(nz); mean=sum(nz)/n; gs_=sum(abs(vi-nz[j]) for ii,vi in enumerate(nz) for j in range(ii+1,n))
            d["_gini"]=round(gs_/(n*n*mean) if mean>0 else 0,3)
        else: d["_gini"]=0.0
        d["_cross_domain_risk"]="HIGH" if (d["DA"]>0 and d["IA"]==0) or (d["DB"]>0 and d["IB"]==0) else ("MEDIUM" if d["GA"]>0 and d["IA"]==0 else "LOW")
        return d

    def _strip_regions(s,pac)->List[StripSignatureRegion]:
        strips=sorted([i for i in pac if i.insn_type.is_strip],key=lambda x:x.address)
        if not strips: return []
        grps=[]; cur=[strips[0]]
        for st in strips[1:]:
            if st.address-cur[-1].address<0x10000: cur.append(st)
            else: grps.append(cur); cur=[st]
        grps.append(cur)
        jc=sum(1 for imp in s._imports if any(sym in imp.get("name","") for sym in s.JIT_SYMS))
        rs=[]
        for g in grps:
            rg=(min(x.address for x in g),max(x.address for x in g))
            rc=sum(1 for i in pac if rg[0]<=i.address<=rg[1] and i.insn_type.is_sign)
            lj=jc>0 and len(g)>=2 and rc>=1
            risk="HIGH" if not lj and rc==0 else ("MEDIUM" if lj else "LOW")
            rs.append(StripSignatureRegion(rg,len(g),rc,lj,jc,risk))
        return rs

    def _cross_lib(s,pac)->List[CrossLibraryPACChain]:
        cs=[]
        for i in pac:
            if i.insn_type not in (PACInstructionType.BLRAA,PACInstructionType.BLRAB): continue
            if not i.function_name: continue
            fa=s._func_addr(i.function_name)
            if not fa: continue
            if not re.search(rf"0x{i.address:X}\s+blra[a-z].*@plt",s._disasm(fa),re.IGNORECASE): continue
            cl=next((v for k,v in s.LIB_PFX.items() if i.function_name.startswith(k)),"main_binary"); dl="unknown_lib"
            for imp in s._imports:
                if imp.get("plt")==i.address: dl=imp.get("uname","unknown_lib").split(".")[0]; break
            mism=i.key!=PACKey.IA
            ga=any(x.insn_type==PACInstructionType.PACGA for x in pac if 0<abs(x.address-i.address)<0x200)
            risk=Severity.HIGH if mism and not ga else (Severity.MEDIUM if mism else Severity.LOW)
            cs.append(CrossLibraryPACChain(cl,i.function_name,dl,"",i.key,PACKey.IA,mism,ga,ga,risk))
        return cs

    def _detect_side_channels(s)->List[SideChannelGadget]:
        gadgets=[]; raw=s._r2("aaaa; pD 10000",120)
        if not raw: return gadgets
        for pat,gtype,desc,tf in _EXFIL_PATTERNS:
            for m in pat.finditer(raw):
                seq_bytes=m.group(0); mnems=[]
                for line in seq_bytes.decode('utf-8',errors='replace').split('\n'):
                    lp=line.strip().split()
                    if lp: mnems.append(lp[0])
                regs_found=set()
                for rn in [b'x0',b'x1',b'x2',b'x3',b'x4',b'x5',b'x6',b'x7',b'x8',b'x9',b'x10',b'x11',b'x12',b'x13',b'x14',b'x15',b'x16',b'x17']:
                    if rn in seq_bytes: regs_found.add(rn.decode())
                sev=Severity.HIGH if tf and gtype in (SideChannelGadgetType.CSDB_COND_BRANCH,SideChannelGadgetType.DC_CVAU_EXCEPTION,SideChannelGadgetType.SYSREG_ACCESS) else (Severity.MEDIUM if tf else Severity.LOW)
                gadgets.append(SideChannelGadget(m.start(),gtype,mnems[:8],regs_found,gtype in (SideChannelGadgetType.CSDB_COND_BRANCH,SideChannelGadgetType.DC_CVAU_EXCEPTION,SideChannelGadgetType.SYSREG_ACCESS),gtype==SideChannelGadgetType.DC_CVAU_EXCEPTION,tf,sev,s._func_for(m.start())))
        return gadgets

    # ── ARM MTE指令检测与TikTag旁路gadget扫描 ──
    def _detect_mte_operations(s)->List[MTEGadget]:
        """检测ARM MTE标签操作指令，审计内存标签使用模式。

        依据NanoTag（IEEE S&P 2026）Pixel 8上MTE实现特征：
        - IRG数量反映标签随机化覆盖范围
        - STG/LDG配对密度反映内存分配释放的标签管理
        - STZG出现标志清零并删除标签，内存复用安全关键操作
        """
        gadgets=[]; raw=s._r2("aaaa; pD 20000",120)
        if not raw: return gadgets
        for pat,optype,desc in _MTE_PATTERNS:
            for m in pat.finditer(raw):
                # 提取寄存器上下文
                ctx=m.group(0).decode('utf-8',errors='replace')
                regs=re.findall(r'x\d+',ctx)
                tr=regs[0] if regs else "?"
                pr=regs[1] if len(regs)>1 else tr
                is_alloc=optype in (MTEOperationType.IRG,MTEOperationType.STG,MTEOperationType.STZG)
                is_dealloc=optype in (MTEOperationType.STZG,)
                gadgets.append(MTEGadget(m.start(),optype,desc,tr,pr,s._func_for(m.start()),is_alloc,is_dealloc,False))
        return gadgets

    def _detect_tiktag_gadgets(s,mte_gadgets:List[MTEGadget])->List[Dict[str,Any]]:
        """扫描TikTag推测执行MTE标签泄露gadget。

        TikTag（IEEE S&P 2025）展示了推测执行泄露4-bit MTE标签的攻击。
        关键模式：LDG/LDGV后紧跟条件分支，标签验证结果经由分支预测器
        的推测执行通道泄露至架构状态。
        """
        findings=[]; raw=s._r2("aaaa; pD 20000",120)
        if not raw: return findings
        for pat,desc,sev in _TIKTAG_PATTERNS:
            for m in pat.finditer(raw):
                findings.append({"type":"tiktag_gadget","severity":sev.value,
                    "description":desc,"offset":f"0x{m.start():x}",
                    "function":s._func_for(m.start())})
        # 交叉检查：存在IRG/STG配对但无LDG验证时，标记标签使用不完整
        has_irg=any(g.operation==MTEOperationType.IRG for g in mte_gadgets)
        has_ldgv=any(g.operation==MTEOperationType.LDGV for g in mte_gadgets)
        if has_irg and not has_ldgv:
            findings.append({"type":"mte_incomplete_protection","severity":"MEDIUM",
                "description":"检测到IRG标签插入但无LDGV标签验证——MTE保护不完整，标签检查可能被绕过",
                "recommendation":"确保关键指针解引用前使用LDGV进行标签验证"})
        return findings

    @staticmethod
    def _pac_str(pac)->str:
        t=len(pac); s_=sum(1 for i in pac if i.insn_type.is_sign); a=sum(1 for i in pac if i.insn_type.is_auth)
        if t==0: return "UNPROTECTED"
        if s_>30 and a>20: return "STRONG"
        if s_>10 and a>5: return "MODERATE"
        return "WEAK"

    @staticmethod
    def _risk(sg,byp,jg,bc)->Severity:
        sc_=sum(1 for g in sg if g.is_oracle)*32; sc_+=sum(p.severity.weight for p in byp)
        sc_+=sum(j.severity.weight for j in jg if not j.pruned)
        if bc<0.5: sc_+=32
        elif bc<0.8: sc_+=8
        if sc_>=100: return Severity.CRITICAL
        if sc_>=50: return Severity.HIGH
        if sc_>=20: return Severity.MEDIUM
        if sc_>=5: return Severity.LOW
        return Severity.INFO

    def analyze(s)->Dict[str,Any]:
        if not s._load(): return {"success":False,"error":"Binary load failed","binary":s.binary_path}
        pac=s._detect_pac(); sig=s._signing_gadgets(pac); byp=s._bypass_paths(pac,sig)
        bti,bc=s._verify_bti(); jop=s._detect_jop(pac); kd=s._key_dist(pac)
        reg=s._strip_regions(pac); chn=s._cross_lib(pac); ps=s._pac_str(pac)
        sc=s._detect_side_channels(); mte=s._detect_mte_operations()
        tiktag=s._detect_tiktag_gadgets(mte)
        overall=s._risk(sig,byp,jop,bc)
        cnt=lambda items,cond:sum(1 for i in items if cond(i))
        return {"success":True,"binary":s.binary_path,"arch":s._arch,
            "pac":{"total":len(pac),"sign":cnt(pac,lambda i:i.insn_type.is_sign),"auth":cnt(pac,lambda i:i.insn_type.is_auth),"strip":cnt(pac,lambda i:i.insn_type.is_strip),"branch":cnt(pac,lambda i:i.insn_type.is_branch),"items":[i.to_dict() for i in pac[:50]]},
            "bti":{"total":len(bti),"c":cnt(bti,lambda b:b.insn_type==BTIInstructionType.BTI_C),"j":cnt(bti,lambda b:b.insn_type==BTIInstructionType.BTI_J),"jc":cnt(bti,lambda b:b.insn_type==BTIInstructionType.BTI_JC),"items":[b.to_dict() for b in bti[:30]]},
            "signing":{"total":len(sig),"oracles":cnt(sig,lambda g:g.is_oracle),"items":[g.to_dict() for g in sig[:20]]},
            "bypass":{"total":len(byp),"substitution":cnt(byp,lambda p:p.bypass_type=="substitution"),"replay":cnt(byp,lambda p:p.bypass_type=="replay"),"strip_resign":cnt(byp,lambda p:p.bypass_type=="strip_resign"),"cross_lib":cnt(byp,lambda p:p.bypass_type=="cross_library"),"items":[p.to_dict() for p in byp[:20]]},
            "jop":{"total":len(jop),"dispatchers":cnt(jop,lambda j:j.usefulness=="dispatcher"),"pac_protected":cnt(jop,lambda j:j.pac_protected),"pruned":cnt(jop,lambda j:j.pruned),"items":[j.to_dict() for j in jop[:15]]},
            "side_channels":{"total":len(sc),"timer_free":cnt(sc,lambda g:g.exploitable_without_timer),"items":[g.to_dict() for g in sc[:15]]},
            "mte":{"total":len(mte),"alloc_ops":cnt(mte,lambda g:g.is_allocation),"dealloc_ops":cnt(mte,lambda g:g.is_deallocation),"items":[g.to_dict() for g in mte[:15]],"tiktag_findings":tiktag},
            "strip_regions":{"total":len(reg),"jit":cnt(reg,lambda r:r.likely_jit),"items":[r.to_dict() for r in reg]},
            "cross_lib_chains":{"total":len(chn),"key_mismatch":cnt(chn,lambda c:c.key_mismatch),"items":[c.to_dict() for c in chn[:15]]},
            "key_distribution":kd,"pac_strength":ps,"bti_coverage":bc,"overall_risk":overall.value,
            "metadata":{"version":"2.3.0","funcs":len(s._funcs),"imports":len(s._imports)}}

def analyze_arm64e_enhanced(binary_path:str)->Dict[str,Any]: return Arm64eEnhancedAnalyzer(binary_path).analyze()
