"""RISC-V Vector/Crypto扩展分析——向量指令+加密扩展+向量循环+strip-mining检测。"""
import os, re, logging, subprocess
from dataclasses import dataclass, field
from typing import Dict, List

log = logging.getLogger(__name__)

@dataclass
class RISCVVectorInstruction: opcode:str=""; mnemonic:str=""; vtype:str=""; description:str=""; detected:bool=False
@dataclass
class RISCVVectorLoop: start_address:int=0; end_address:int=0; loop_count:int=0; vector_width:int=128; operation_type:str=""; detected_pattern:str=""; is_strip_mined:bool=False; tail_handling:str=""
@dataclass
class RISCV_CryptoInstruction: opcode:str=""; mnemonic:str=""; extension:str=""; description:str=""; security_risk:str=""; detected:bool=False

class RISCVExtAnalysisResult:
    __slots__=('vector_instructions','crypto_instructions','vector_loops','extension_usage','security_issues','summary','register_liveness_findings')
    def __init__(s,vi=None,ci=None,vl=None,eu=None,si=None,sm=""): s.vector_instructions=vi or []; s.crypto_instructions=ci or []; s.vector_loops=vl or []; s.extension_usage=eu or {}; s.security_issues=si or []; s.summary=sm; s.register_liveness_findings=[]

RVV_INSTRUCTIONS={'vadd':{'mnemonic':'vadd','vtype':'arithmetic','description':'vector加法','patterns':['vadd.vv','vadd.vs','vadd.vi']},'vsub':{'mnemonic':'vsub','vtype':'arithmetic','description':'vector减法','patterns':['vsub.vv','vsub.vs','vsub.vi']},'vmul':{'mnemonic':'vmul','vtype':'arithmetic','description':'vector乘法','patterns':['vmul.vv','vmul.vs','vmul.vi']},'vdiv':{'mnemonic':'vdiv','vtype':'arithmetic','description':'vector除法','patterns':['vdiv.vv','vdiv.vs']},'vand':{'mnemonic':'vand','vtype':'logical','description':'vector按位与','patterns':['vand.vv','vand.vs','vand.vi']},'vor':{'mnemonic':'vor','vtype':'logical','description':'vector按位或','patterns':['vor.vv','vor.vs','vor.vi']},'vxor':{'mnemonic':'vxor','vtype':'logical','description':'vector按位异或','patterns':['vxor.vv','vxor.vs','vxor.vi']},'vsl':{'mnemonic':'vsl','vtype':'shift','description':'vector左移','patterns':['vsl.vv','vsl.vs','vsl.vi']},'vsr':{'mnemonic':'vsr','vtype':'shift','description':'vector右移','patterns':['vsr.vv','vsr.vs','vsr.vi']},'vsetvli':{'mnemonic':'vsetvli','vtype':'control','description':'设置向量长度','patterns':['vsetvli']},'vsetvl':{'mnemonic':'vsetvl','vtype':'control','description':'设置向量长度','patterns':['vsetvl']},'vle':{'mnemonic':'vle','vtype':'memory','description':'vector load','patterns':['vle8','vle16','vle32','vle64']},'vse':{'mnemonic':'vse','vtype':'memory','description':'vector存储','patterns':['vse8','vse16','vse32','vse64']},'vcompress':{'mnemonic':'vcompress','vtype':'permute','description':'vector compress','patterns':['vcompress']},'vextract':{'mnemonic':'vextract','vtype':'permute','description':'vector extract','patterns':['vextract']}}

CRYPTO_INSTRUCTIONS={'aesenc':{'mnemonic':'aesenc','extension':'Zkne','description':'AES轮加密','security_risk':'low'},'aesdec':{'mnemonic':'aesdec','extension':'Zknd','description':'AES轮解密','security_risk':'low'},'sm3start':{'mnemonic':'sm3start','extension':'Zksed','description':'SM3初始化','security_risk':'low'},'sm3update':{'mnemonic':'sm3update','extension':'Zksed','description':'SM3更新','security_risk':'low'},'sm4enc':{'mnemonic':'sm4enc','extension':'Zksh','description':'SM4轮加密','security_risk':'low'},'sm4key':{'mnemonic':'sm4key','extension':'Zksh','description':'SM4密钥扩展','security_risk':'high'},'sha256sig0':{'mnemonic':'sha256sig0','extension':'Zkne','description':'SHA256 Sigma0','security_risk':'low'},'sha256sig1':{'mnemonic':'sha256sig1','extension':'Zkne','description':'SHA256 Sigma1','security_risk':'low'},'sha256sum0':{'mnemonic':'sha256sum0','extension':'Zkne','description':'SHA256 Sum0','security_risk':'low'},'sha256sum1':{'mnemonic':'sha256sum1','extension':'Zkne','description':'SHA256 Sum1','security_risk':'low'},'sha512sig0h':{'mnemonic':'sha512sig0h','extension':'Zknh','description':'SHA512 Sigma0(高位)','security_risk':'low'},'sha512sig1h':{'mnemonic':'sha512sig1h','extension':'Zknh','description':'SHA512 Sigma1(高位)','security_risk':'low'},'sha512sum0h':{'mnemonic':'sha512sum0h','extension':'Zknh','description':'SHA512 Sum0(高位)','security_risk':'low'},'sha512sum1h':{'mnemonic':'sha512sum1h','extension':'Zknh','description':'SHA512 Sum1(高位)','security_risk':'low'},'ghash':{'mnemonic':'ghash','extension':'Zknd','description':'Galois哈希','security_risk':'medium'},'xperm4':{'mnemonic':'xperm4','extension':'Zkne','description':'4x4位置换','security_risk':'low'},'xperm8':{'mnemonic':'xperm8','extension':'Zkne','description':'8x8位置换','security_risk':'low'}}

VECTOR_LOOP_PATTERNS={'strided_load':{'pattern':r'vle.*addi.*loop','description':'跨步加载循环','operation_type':'memory'},'strided_store':{'pattern':r'vse.*addi.*loop','description':'跨步存储循环','operation_type':'memory'},'element_wise':{'pattern':r'vsetvli.*vadd|vsetvli.*vmul','description':'逐元素操作循环','operation_type':'compute'},'reduction':{'pattern':r'vredsum|vredmax|vredmin','description':'归约操作循环','operation_type':'reduction'},'gather_scatter':{'pattern':r'vluxei8|vluxei16|vluxei32|vsuxei','description':'聚集/分散操作','operation_type':'memory'},'strip_mine':{'pattern':r'vsetvli.*vsetvli','description':'strip-mining循环','operation_type':'compute'}}

_riscv_analyzer=None

def get_riscv_ext_analyzer()->'RISCVExtAnalyzer':
    global _riscv_analyzer
    if _riscv_analyzer is None: _riscv_analyzer=RISCVExtAnalyzer()
    return _riscv_analyzer

class RISCVExtAnalyzer:
    def __init__(s): log.info("RISCVExtAnalyzer initialized")
    def _get_disassembly(s,bp):
        try:
            r=subprocess.run(['r2','-q','-e','io.color=false','-c','pd 500',bp],capture_output=True,text=True,timeout=60)
            if r.returncode==0: return r.stdout
        except Exception as e: log.debug(f"获取反汇编失败:{e}")
        return ""
    def _extract_instructions(s,d):
        return [p[1].strip() for p in [l.split(';') for l in d.split('\n')] if len(p)>=2 and p[1].strip()]
    def _detect_vector_instructions(s,ins):
        det=[]
        for instr in ins:
            for op,info in RVV_INSTRUCTIONS.items():
                for pat in info['patterns']:
                    if pat in instr: det.append(RISCVVectorInstruction(op,info['mnemonic'],info['vtype'],info['description'],True)); break
        return det
    def _detect_crypto_instructions(s,ins):
        det=[]
        for instr in ins:
            for op,info in CRYPTO_INSTRUCTIONS.items():
                if op in instr: det.append(RISCV_CryptoInstruction(op,info['mnemonic'],info['extension'],info['description'],info['security_risk'],True))
        return det
    def _detect_vector_loops(s,d):
        loops=[]; lc=0
        for pn,pi in VECTOR_LOOP_PATTERNS.items():
            if re.search(pi['pattern'],d,re.I):
                ism=pn=='strip_mine'
                loops.append(RISCVVectorLoop(0,0,lc,128,pi['operation_type'],pi['description'],ism,"dynamic" if ism else "")); lc+=1
        return loops
    def _analyze_extension_usage(s,vi,ci):
        u={'Zve':len(vi),'Zkne':0,'Zknd':0,'Zksed':0,'Zksh':0,'Zknh':0}
        for i in ci:
            if i.extension in u: u[i.extension]+=1
        return u
    def _detect_security_issues(s,ci):
        issues=[]
        hr=[i for i in ci if i.security_risk=='high']
        if hr: issues.append(f"检测到高风险加密指令使用:{', '.join(i.mnemonic for i in hr)}")
        ki=[i for i in ci if 'key' in i.description.lower()]
        if ki: issues.append(f"检测到密钥操作指令:{', '.join(i.mnemonic for i in ki)}——建议审查密钥处理流程")
        sm4c=sum(1 for i in ci if i.opcode=='sm4key')
        if sm4c>0: issues.append(f"检测到{sm4c}次SM4密钥扩展操作")
        has_sc=any(i.extension=='Zkne' for i in ci); has_v=any(i.mnemonic in ('vadd','vmul') for i in ci)
        if has_sc and has_v: issues.append("标量加密与向量运算混合——审查密钥材料在向量寄存器中的泄露风险")
        # 向量寄存器活跃度分析: vsetvli/vsetvl频繁出现但无对应vle/vse → 配置不当
        vsetvl_count=sum(1 for i in vi if i.opcode in ('vsetvli','vsetvl')) if 'vi' in dir() else 0
        vmem_count=sum(1 for i in vi if i.opcode in ('vle','vse')) if 'vi' in dir() else 0
        if vsetvl_count>10 and vmem_count==0: issues.append(f"检测到{vsetvl_count}次向量长度设置但无内存操作——配置可能冗余或错误")
        return issues
    def analyze_binary(s,bp):
        log.info(f"开始分析RISC-V扩展:{bp}")
        if not os.path.exists(bp): return RISCVExtAnalysisResult(summary="文件不存在")
        try:
            d=s._get_disassembly(bp); ins=s._extract_instructions(d)
            vi=s._detect_vector_instructions(ins); ci=s._detect_crypto_instructions(ins)
            vl=s._detect_vector_loops(d); eu=s._analyze_extension_usage(vi,ci)
            si=s._detect_security_issues(ci)
            # add liveness check
            rlf=[]
            if len(vi)>0:
                vregs_used=set()
                for i in vi:
                    for pat in RVV_INSTRUCTIONS.get(i.opcode,{}).get('patterns',[]):
                        if 'v' in pat.lower(): vregs_used.add(pat[:4])
                if len(vregs_used)<4: rlf.append("向量寄存器利用率低——可能存在寄存器压力问题")
            sp=[]
            if vi: sp.append(f"发现{len(vi)}条向量指令")
            if ci: sp.append(f"发现{len(ci)}条加密指令")
            if vl: sp.append(f"发现{len(vl)}个向量循环")
            if si: sp.append(f"发现{len(si)}个安全问题")
            sm="; ".join(sp) if sp else "未发现RISC-V扩展指令"
            result=RISCVExtAnalysisResult(vi,ci,vl,eu,si,sm)
            result.register_liveness_findings=rlf
            return result
        except Exception as e: log.error(f"分析失败:{e}"); return RISCVExtAnalysisResult(summary=f"分析失败:{e}")
    def format_report(s,r):
        o=["## RISC-V Vector/Crypto扩展分析报告",f"\n**摘要**:{r.summary}\n"]
        if r.vector_instructions:
            o.append("### 向量指令"); o.append("|操作码|助记符|类型|描述|"); o.append("|---|---|---|---|")
            seen=set()
            for i in r.vector_instructions:
                k=f"{i.opcode}_{i.vtype}"
                if k not in seen: seen.add(k); o.append(f"|{i.opcode}|{i.mnemonic}|{i.vtype}|{i.description}|")
            o.append("")
        if r.crypto_instructions:
            o.append("### 加密指令"); o.append("|操作码|助记符|扩展|描述|安全风险|"); o.append("|---|---|---|---|---|")
            seen=set()
            for i in r.crypto_instructions:
                if i.opcode not in seen:
                    seen.add(i.opcode); ri='🔴' if i.security_risk=='high' else ('🟡' if i.security_risk=='medium' else '🟢')
                    o.append(f"|{i.opcode}|{i.mnemonic}|{i.extension}|{i.description}|{ri}{i.security_risk}|")
            o.append("")
        if r.vector_loops:
            o.append("### 向量循环"); o.append("|循环|操作类型|检测模式|Strip-Mining|"); o.append("|---|---|---|---|")
            for l in r.vector_loops: sm='✓' if l.is_strip_mined else '—'; o.append(f"|Loop#{l.loop_count}|{l.operation_type}|{l.detected_pattern}|{sm}|")
            o.append("")
        if r.extension_usage:
            o.append("### 扩展统计"); o.append("<details><summary>展开</summary>\n")
            for e,c in r.extension_usage.items():
                if c>0: o.append(f"- **{e}**:{c}次")
            o.append("\n</details>\n")
        if r.security_issues:
            o.append("### ⚠️安全问题")
            for i in r.security_issues: o.append(f"- {i}")
            o.append("")
        if r.register_liveness_findings:
            o.append("### 寄存器活跃度")
            for f in r.register_liveness_findings: o.append(f"- {f}")
            o.append("")
        o.append("### 📌建议"); o.append("1.验证向量指令使用是否符合性能优化目标\n2.审查加密指令特别是密钥相关操作\n3.确保向量循环的向量化效率\n4.关注高风险加密指令使用场景")
        return '\n'.join(o)
