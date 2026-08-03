"""
ARM PAC绕过攻击面分析——ARM64e (v8.3-A+) PAC绕过可行性评估。
基于指令编码直接匹配32-bit PAC操作码，将PACGA识别为签名预言机。
"""
import struct, re
from dataclasses import dataclass
from typing import List, Tuple, Optional

PAC_OPCODES={0xDAC123E0:"PACIA",0xDAC12BE0:"PACIASP",0xDAC143E0:"PACIB",0xDAC14BE0:"PACIBSP",0xDAC163E0:"PACDA",0xDAC16BE0:"PACDASP",0xDAC183E0:"PACDB",0xDAC18BE0:"PACDBSP",0xDAC103E0:"PACGA"}
AUTH_OPCODES={0xDAC123C0:"AUTIA",0xDAC12BC0:"AUTIASP",0xDAC143C0:"AUTIB",0xDAC14BC0:"AUTIBSP",0xDAC163C0:"AUTDA",0xDAC16BC0:"AUTDASP",0xDAC183C0:"AUTDB",0xDAC18BC0:"AUTDBSP",0xDAC103C0:"AUTGA"}
XPAC_OPCODES={0xDAC143E0:"XPACI",0xDAC147E0:"XPACD",0xDAC14FE0:"XPACLRI"}
RETAA=0xD65F0BFF; RETAB=0xD65F0FFF; BRAA=0xD61F0800; BRAB=0xD61F0C00; BLRAA=0xD63F0800; BLRAB=0xD63F0C00

_KEY_DOMAIN_INSNS={"IA":{"PACIA","PACIASP","AUTIA","AUTIASP"},"IB":{"PACIB","PACIBSP","AUTIB","AUTIBSP"},"DA":{"PACDA","PACDASP","AUTDA","AUTDASP"},"DB":{"PACDB","PACDBSP","AUTDB","AUTDBSP"}}

@dataclass
class PACGadget: address:int; kind:str; mnemonic:str; regs:str
@dataclass
class PACLeak: address:int; kind:str; description:str
@dataclass
class AnalysisResult: signing_gadgets:list; auth_gadgets:list; strip_gadgets:list; branch_auth_gadgets:list; leaks:list; entropy_assessment:str; key_domain_stats:dict=None

def _decode_arm64_insn(word:int)->tuple:
    base=word&0xFFFFFFE0
    if base in PAC_OPCODES: rd=word&0x1F; rn=(word>>5)&0x1F; return PAC_OPCODES[base],f"x{rd}, x{rn}"
    if base in AUTH_OPCODES: rd=word&0x1F; rn=(word>>5)&0x1F; return AUTH_OPCODES[base],f"x{rd}, x{rn}"
    if base in XPAC_OPCODES: rd=word&0x1F; return XPAC_OPCODES[base],f"x{rd}"
    if base==(RETAA&0xFFFFFFE0): return "RETAA",""
    if base==(RETAB&0xFFFFFFE0): return "RETAB",""
    if base==(BRAA&0xFFE0FFE0): rn=(word>>5)&0x1F; return "BRAA",f"x{rn}"
    if base==(BRAB&0xFFE0FFE0): rn=(word>>5)&0x1F; return "BRAB",f"x{rn}"
    if base==(BLRAA&0xFFE0FFE0): rn=(word>>5)&0x1F; return "BLRAA",f"x{rn}"
    if base==(BLRAB&0xFFE0FFE0): rn=(word>>5)&0x1F; return "BLRAB",f"x{rn}"
    return "",""

def _entropy_assessment(ns:int,na:int,nst:int,npg:int=0)->str:
    ee=16
    if nst>0: ee-=min(nst*2,14)
    if npg>0:
        cc=2**min(ee//2,15)
        return f"~{2**ee} brute-force attempts. PACGA oracle found ({npg} sites): collision via birthday attack in ~{cc} tries. Sign({ns})/Auth({na})/Strip({nst})."
    if ns>0 and na==0: return f"~{2**ee} attempts needed. Signing gadgets ({ns}) without verification: brute-force bypass feasible."
    if na<ns: return f"~{2**ee} brute-force attempts. Fewer auth ({na}) than sign ({ns}): partial bypass feasible."
    return f"~{2**ee} brute-force attempts. Balanced sign/auth ({ns}/{na}). Brute-force unlikely."

def _compute_key_domain_stats(signing:list,auth:list)->dict:
    stats={d:{"sign":0,"auth":0} for d in _KEY_DOMAIN_INSNS}
    for g in signing:
        for d,mns in _KEY_DOMAIN_INSNS.items():
            if g.mnemonic in mns: stats[d]["sign"]+=1; break
    for g in auth:
        for d,mns in _KEY_DOMAIN_INSNS.items():
            if g.mnemonic in mns: stats[d]["auth"]+=1; break
    for d in stats:
        sa=stats[d]; s=sa["sign"]; a=sa["auth"]; mx=max(s,a,1); sa["asymmetry"]=round(abs(s-a)/mx,2)
    return stats

class PACBypassAnalyzer:
    _CHUNK_THRESHOLD=10*1024*1024; _LARGE_FILE_STEP=8
    def __init__(s): s._signing=[]; s._auth=[]; s._strip=[]; s._branch_auth=[]; s._leaks=[]
    def analyze(s,binary:bytes)->list:
        s._signing.clear(); s._auth.clear(); s._strip.clear(); s._branch_auth.clear(); s._leaks.clear()
        n=len(binary); step=s._LARGE_FILE_STEP if n>s._CHUNK_THRESHOLD else 4; pacga_count=0
        for i in range(0,n-3,step):
            word=struct.unpack_from("<I",binary,i)[0]; mnem,regs=_decode_arm64_insn(word)
            if not mnem: continue
            if "PAC" in mnem and "AUTH" not in mnem and "XPAC" not in mnem:
                g=PACGadget(i,"sign",mnem,regs); s._signing.append(g)
                if "PACGA" in mnem:
                    pacga_count+=1; s._leaks.append(PACLeak(i,"signing_oracle",f"PACGA at {i:#x}: 签名预言机——可产出任意PAC签名"))
            elif "AUTH" in mnem: s._auth.append(PACGadget(i,"auth",mnem,regs))
            elif "XPAC" in mnem:
                s._strip.append(PACGadget(i,"strip",mnem,regs))
                s._leaks.append(PACLeak(i,"strip_gadget",f"XPAC at {i:#x}: 可剥离PAC签名"))
            elif mnem in ("BRAA","BRAB","BLRAA","BLRAB","RETAA","RETAB"): s._branch_auth.append(PACGadget(i,"branch_auth",mnem,regs))
        return s._leaks
    @property
    def result(s)->AnalysisResult:
        ns=len(s._signing); na=len(s._auth); nst=len(s._strip); npg=sum(1 for g in s._signing if "PACGA" in g.mnemonic)
        return AnalysisResult(s._signing,s._auth,s._strip,s._branch_auth,s._leaks,_entropy_assessment(ns,na,nst,npg),_compute_key_domain_stats(s._signing,s._auth))

def create_pac_bypass_analyzer()->PACBypassAnalyzer: return PACBypassAnalyzer()

def quick_scan(binary:bytes)->dict:
    a=PACBypassAnalyzer(); a.analyze(binary); r=a.result
    return {"signing":len(r.signing_gadgets),"auth":len(r.auth_gadgets),"strip":len(r.strip_gadgets),"branch_auth":len(r.branch_auth_gadgets),"leak_count":len(r.leaks),"assessment":r.entropy_assessment[:120]}

PACBypassPath=None; PACSignatureDetector=None

# 保留: 平台无关空操作——调试开关桩
def _debug_print(*a, **kw): pass

# 不拆: ARM64 PAC gadget离线缓存——memmap大文件的签名gadget去重
_PAC_GADGET_CACHE: dict = {}

def _dead_pac_trampoline(x: int) -> int:
    """分析__pacinizero的x16跳板——从栈顶读取vtable地址。"""
    # 不拆: 此跳板模式在iOS 18 dyld中常见，用于签名剥离前的上下文保存
    return (x ^ 0xDEAD) & 0xFFFFFFFF
