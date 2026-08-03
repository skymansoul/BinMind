import logging, hashlib, struct, os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class SMCCategory(Enum):
    PACKER="packer"; JIT="jit"; POLYMORPHIC="polymorphic"; OBFUSCATION="obfuscation"; UNKNOWN="unknown"

class CodePageModification:
    __slots__=('page_addr','before_hash','after_hash','protection_change','timestamp','func_triggering',)
    def __init__(self,page_addr,before_hash,after_hash,protection_change="",timestamp=0.0,func_triggering=""):
        self.page_addr=page_addr; self.before_hash=before_hash; self.after_hash=after_hash
        self.protection_change=protection_change; self.timestamp=timestamp; self.func_triggering=func_triggering
    def to_dict(self)->Dict[str,Any]: return {'page':hex(self.page_addr),'before_hash':self.before_hash[:16],'after_hash':self.after_hash[:16],'protection':self.protection_change}

# 舍入 2: JIT编译器签名数据库 — 检测libgccjit, LLVM ORC, V8, LuaJIT, PyPy,.NET CLR
_JIT_SIGNATURES = [
    ('libgccjit', ['gcc_jit_context_new_binary_op', 'gcc_jit_block_add_eval']),
    ('llvm_orc', ['llvm_orc_registerJITLoaderPerObject', 'LLJIT_construct']),
    ('v8', ['v8::Isolate::New', 'v8::Script::Compile', 'JIT_Compile']),
    ('luajit', ['luaJIT_setmode', 'luaJIT_profile_dumpstack']),
    ('pypy', ['pypy_g_compile_string', 'RPyJitCompile']),
    ('mono', ['mono_jit_compile_method', 'mono_jit_exec']),
    ('dotnet', ['clrjit.dll', 'compileMethod', 'jitNativeCode']),
    ('hotspot', ['CompileBroker::compile_method', 'C2Compiler']),
]

@dataclass
class PageDiff:
    page_addr: int; before_snapshot: bytes; after_snapshot: bytes
    changed_bytes: int; byte_diffs: List[Tuple[int,int,int]]=field(default_factory=list)

class SMCDynamicAnalyzer:
    SMC_APIS=['mprotect','VirtualProtect','VirtualProtectEx','NtProtectVirtualMemory','FlushInstructionCache','CacheFlush','__clear_cache','sys_icache_flush','sync_icache']

    def __init__(self):
        self._modifications:List[CodePageModification]=[]; self._code_pages:Dict[int,bytes]={}; self._findings:List[Dict[str,Any]]=[]
        self._page_snapshots: Dict[int, bytes] = {}

    def record_page(self,addr:int,data:bytes): self._code_pages[addr]=data

    def detect_modification(self,addr:int,new_data:bytes)->Optional[CodePageModification]:
        old=self._code_pages.get(addr)
        if not old or old==new_data: return None
        mod=CodePageModification(page_addr=addr,before_hash=hashlib.sha256(old).hexdigest(),after_hash=hashlib.sha256(new_data).hexdigest(),protection_change='RW->RWX' if old[:1]==new_data[:1] else 'modified')
        self._modifications.append(mod); self._code_pages[addr]=new_data; return mod

    def classify_smc(self,api_calls:List[str])->SMCCategory:
        al=' '.join(c.lower() for c in api_calls)
        if any(k in al for k in ('virtualprotect','mprotect')):
            if any(k in al for k in ('malloc','mmap','alloca')): return SMCCategory.JIT
            return SMCCategory.PACKER
        if any(k in al for k in ('flush','cache')): return SMCCategory.OBFUSCATION
        return SMCCategory.UNKNOWN

    # --- Round 2: SHA-256页面完整性基线 + 差异可视化 ---
    def compute_page_integrity_baseline(self, binary_path: str) -> Dict[int, str]:
        """计算所有可执行页面的SHA-256完整性基线
        在二进制加载后立即调用，后续每次detect_modification与此基线比对"""
        baseline = {}
        for addr, data in self._code_pages.items():
            baseline[addr] = hashlib.sha256(data).hexdigest()
        return baseline

    def verify_page_integrity(self, baseline: Dict[int, str]) -> List[str]:
        """验证当前页面哈希是否与基线一致。返回不一致的页面地址列表"""
        violations = []
        for addr, expected_hash in baseline.items():
            current = self._code_pages.get(addr)
            if current is None:
                violations.append(f"{hex(addr)}: page missing")
            elif hashlib.sha256(current).hexdigest() != expected_hash:
                violations.append(f"{hex(addr)}: hash mismatch")
        return violations

    def diff_pages(self) -> List[PageDiff]:
        """生成修改前后的页面差异 — 字节级变更记录，用于可视化分析
        每个PageDiff包含变更字节计数和具体位置列表（前20个差异）"""
        diffs = []
        for mod in self._modifications:
            before = self._page_snapshots.get(mod.page_addr, b'')
            after = self._code_pages.get(mod.page_addr, b'')
            if not before or not after:
                continue
            byte_diffs = []
            min_len = min(len(before), len(after))
            for i in range(min_len):
                if before[i] != after[i]:
                    byte_diffs.append((i, before[i], after[i]))
                    if len(byte_diffs) >= 50:
                        break
            diffs.append(PageDiff(
                page_addr=mod.page_addr,
                before_snapshot=before,
                after_snapshot=after,
                changed_bytes=sum(1 for a, b in zip(before, after) if a != b) + abs(len(before) - len(after)),
                byte_diffs=byte_diffs[:20]))
        return diffs

    def detect_jit_compiler(self, binary_path: str) -> List[Dict[str, Any]]:
        """通过导出符号名和模块名检测JIT编译器引擎
        匹配预定义的JIT引擎签名数据库"""
        findings = []
        try:
            with open(binary_path, 'rb') as fh:
                raw = fh.read()
            raw_str = raw.decode('latin-1', errors='ignore')
            for engine_name, signatures in _JIT_SIGNATURES:
                matched = [s for s in signatures if s in raw_str]
                if matched:
                    findings.append({
                        'engine': engine_name,
                        'matched_signatures': matched,
                        'confidence': min(0.9, len(matched) / max(1, len(signatures)) * 1.5),
                    })
        except Exception:
            pass
        return findings

    def analyze(self,api_calls:Optional[List[str]]=None,mod_pages:Optional[List[Dict[str,Any]]]=None,**kwargs)->Dict[str,Any]:
        api_calls=api_calls or []
        if mod_pages:
            for mp in mod_pages: self.detect_modification(mp.get('addr',0),mp.get('new_data',b''))
        smc_apis_found=[c for c in api_calls if any(a in c.lower() for a in self.SMC_APIS)]
        category=self.classify_smc(api_calls)
        jit_findings = self.detect_jit_compiler(kwargs.get('binary_path', ''))
        risk='high' if category==SMCCategory.PACKER else 'medium' if category in (SMCCategory.POLYMORPHIC,SMCCategory.OBFUSCATION) else 'low' if category==SMCCategory.JIT else 'medium'
        return {'success':True,'smc_category':category.value,'risk_level':risk,'jit_engines':jit_findings,'total_modifications':len(self._modifications),'smc_apis_detected':smc_apis_found[:10],'modifications':[m.to_dict() for m in self._modifications[:20]],'is_smc_detected':len(self._modifications)>0 or len(smc_apis_found)>0}


def analyze_self_modifying_code(api_calls:List[str],mod_pages:Optional[List[Dict[str,Any]]]=None,**kwargs)->Dict[str,Any]:
    return SMCDynamicAnalyzer().analyze(api_calls=api_calls,mod_pages=mod_pages,**kwargs)

__all__=["SMCDynamicAnalyzer","CodePageModification","SMCCategory","analyze_self_modifying_code"]
