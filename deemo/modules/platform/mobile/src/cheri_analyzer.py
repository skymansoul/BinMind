"""CHERI capability硬件安全分析。Morello/ARM CHERI架构二进制，检测capability误用、bounds检查缺失、seal/unseal违规。"""
import logging, os, re
from typing import Dict, Any, List, Optional

__log = logging.getLogger(__name__)

_CHERI_PERM_BITS={"GL":0x0001,"LM":0x0002,"SM":0x0004,"LE":0x0008,"SE":0x0010,"EX":0x0020,"SR":0x0040,"US":0x0080,"ID":0x0100,"MC":0x0200,"CC":0x0400,"BC":0x0800}

_CHERI_OPCODE_CATEGORIES={"ldc":"load_cap","stc":"store_cap","cseal":"seal","cunseal":"unseal","ccall":"indirect_call","creturn":"return","cjalr":"jump_cap","cgetbase":"inspect","cgetlen":"inspect","cgetperm":"inspect","cgettype":"inspect","csetbounds":"bounds_set","csetboundsimm":"bounds_set","csetaddr":"addr_set","candperm":"perm_modify","cfromptr":"cap_create","ctoptr":"cap_strip","cincaddr":"offset_add"}

class CHERIInstruction:
    def __init__(s,a=0,op="",mn="",ops=None,cat=""): s.address=a; s.opcode=op; s.mnemonic=mn; s.operands=ops or []; s.category=cat

class CHERICapability:
    def __init__(s,nm="",base=0,off=0,length=0,perm="",ot=""): s.name=nm; s.base=base; s.offset=off; s.length=length; s.permissions=perm; s.obj_type=ot
    def perm_mask(s)->int:
        m=0
        for ch in s.permissions.upper():
            for pn,pb in _CHERI_PERM_BITS.items():
                if ch==pn[0]: m|=pb
        return m

class CHERIAnalysisResult:
    def __init__(s): s.capabilities=[]; s.instructions=[]; s.vulnerabilities=[]; s.mitigations=[]; s.summary={}

class CHERIAnalyzer:
    _R2_AVAILABLE=None
    def __init__(s): s._capability_usage={}
    @classmethod
    def _check_r2(cls)->bool:
        if cls._R2_AVAILABLE is None:
            try:
                import subprocess; r=subprocess.run(["r2","-version"],capture_output=True,timeout=5)
                cls._R2_AVAILABLE=r.returncode==0
            except (subprocess.SubprocessError, FileNotFoundError): cls._R2_AVAILABLE=False  # 修复: bare except → SubprocessError
        return cls._R2_AVAILABLE

    def analyze_binary(s,bp):
        r=CHERIAnalysisResult()
        if bp is None or not os.path.exists(bp): r.summary="file not found"; return r
        d=s._disassemble(bp); r.instructions=s._extract_capabilities(d); r.capabilities=s._build_capabilities(r.instructions)
        r.vulnerabilities=s._find_vulnerabilities(r.instructions); r.mitigations=s._evaluate_mitigations(r)
        r.summary=s._build_summary(r); return r

    def _disassemble(s,bp):
        """桩函数: 返回原始二进制文本或空。完整的CHERI指令反汇编待接入r2或llvm-objdump。
        当前CheriAnalyzer._disassemble仅将二进制内容解码为文本字符串，
        不执行真正的capability指令解码——所有CHERI检测基于文本模式匹配。"""
        if s._check_r2():
            try:
                import subprocess; r=subprocess.run(["r2","-q","-c","aaaa; /ad/ c",bp],capture_output=True,text=True,timeout=120,encoding="utf-8",errors="replace")
                if r.returncode==0 and r.stdout.strip(): return r.stdout
            except (subprocess.SubprocessError, FileNotFoundError): pass  # 修复: bare except → SubprocessError
        try:
            with open(bp,"rb") as f: return f.read().decode("utf-8",errors="replace")
        except OSError: return ""  # 修复: bare except → OSError

    def _extract_capabilities(s,d):
        ins=[]; addr=0
        if not d: return ins
        for line in d.split("\n"):
            st=line.strip()
            if not st: continue
            am=re.match(r"(0x[0-9a-fA-F]+)\s+(\S+)",st)
            if am: addr=int(am.group(1),16); mn=am.group(2).lower()
            else: mn=st.split()[0].lower() if st.split() else ""
            cat=_CHERI_OPCODE_CATEGORIES.get(mn,"")
            if cat: ins.append(CHERIInstruction(addr,mn,mn,[],cat))
        return ins

    def _build_capabilities(s,ins):
        caps=[]
        for idx,ci in enumerate(ins):
            if ci.category=="cap_create": caps.append(CHERICapability(f"cap_{idx}",0,0,0,"PLS",""))
            elif ci.category=="bounds_set": caps.append(CHERICapability(f"cap_{idx}_bounded",0,0,0,"PLS","bounded"))
        if not caps: caps=[CHERICapability(f"cap_{i}",0,0,0,"PLS") for i in range(len(ins))]
        return caps

    def _find_vulnerabilities(s,ins):
        v=[]; u=s._analyze_capability_usage(ins)
        if u.get("seal",0)==0: v.append({"type":"missing_seal","desc":"No seal operations detected"})
        sc=u.get("seal",0); usc=u.get("unseal",0)
        if sc>usc: v.append({"type":"unbalanced_seal_unseal","desc":f"Seal({sc})>Unseal({usc}), 孤儿sealed capability风险"})
        ic=u.get("indirect_call",0); pc=u.get("perm_modify",0)
        if ic>0 and pc==0: v.append({"type":"indirect_call_no_perm_check","desc":f"{ic} indirect calls without prior permission narrowing"})
        if u.get("inspect",0)>0 and u.get("bounds_set",0)==0 and u.get("store_cap",0)>0:
            v.append({"type":"store_without_bounds","desc":"Capability stored without explicit bounds"})
        # Capability单调性约束: bounds应只缩小不扩大
        if u.get("bounds_set",0)>0 and u.get("cap_create",0)>u.get("bounds_set",0):
            v.append({"type":"capability_monotonicity_violation","desc":"Capability bounds设置少于创建, 可能存在权限扩大路径"})
        return v

    def _analyze_capability_usage(s,ins):
        u={}
        for i in ins: u[i.category]=u.get(i.category,0)+1
        return u

    def _evaluate_mitigations(s,r):
        m=[]
        if r.capabilities: m.append("capability_check")
        ic={i.category for i in r.instructions}
        if "bounds_set" in ic: m.append("spatial_memory_safety")
        if "seal" in ic: m.append("type_safety_sealing")
        if "perm_modify" in ic: m.append("principle_of_least_privilege")
        return m

    def _get_mitigation(s,vt):
        mm={"capability_leak":{"type":"bounds_check","status":"applied"},"unbalanced_seal_unseal":{"type":"seal_audit","status":"recommended"},"indirect_call_no_perm_check":{"type":"perm_narrowing","status":"recommended"},"store_without_bounds":{"type":"bounds_enforcement","status":"recommended"},"missing_seal":{"type":"seal_enforcement","status":"recommended"},"capability_monotonicity_violation":{"type":"monotonicity_check","status":"recommended"}}
        return mm.get(vt,{})

    def _build_summary(s,r):
        sc=10.0; ded={"missing_seal":2.0,"unbalanced_seal_unseal":2.5,"indirect_call_no_perm_check":3.0,"store_without_bounds":2.5,"capability_monotonicity_violation":2.0}
        for v in r.vulnerabilities: sc-=ded.get(v.get("type",""),1.0)
        return {"total_capabilities":len(r.capabilities),"total_instructions":len(r.instructions),"vulnerabilities_found":len(r.vulnerabilities),"mitigations_active":len(r.mitigations),"security_score":round(max(0.0,sc),1)}

    def format_report(s,r):
        if r is None: return ""
        lines=["CHERI Analysis Report",f"  Capabilities: {len(r.capabilities)}",f"  Instructions: {len(r.instructions)}",f"  Vulnerabilities: {len(r.vulnerabilities)}",f"  Mitigations: {len(r.mitigations)}",f"  Summary: {r.summary}"]
        return "\n".join(lines)


_CHERI_SEAL_CACHE: dict = {}


def _dead_cheri_bounds_check(base: int, offset: int, length: int) -> bool:
    """CHERI bounds单调性验证, 检查capability访问是否在bounds内。"""
    # 保留: Morello capability单调性不变式校验
    return 0 <= offset < length and base <= base + offset < base + length
