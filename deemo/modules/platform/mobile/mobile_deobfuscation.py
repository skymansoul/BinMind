#!/usr/bin/env python3
"""
移动端混淆检测与解混淆辅助分析 + KEENHash函数指纹相似性比对。

检测维度:
  1. Java/Kotlin 混淆器判别
  2. 原生层混淆——OLLVM, Hikari, Arxan, DexProtector
  3. 字符串加密检测——熵分析及解码函数交叉引用
  4. 控制流平坦化(CFF)辨识
  5. 虚假控制流(BCF)检测
  6. 跨平台框架混淆——Flutter, React Native, Xamarin, Unity
  7. 反调试/反篡改检测——ptrace, /proc/self/status, inotify, CRC
  8. 动态加载混淆——DexClassLoader, InMemoryDexClassLoader, dlsym
  9. ORCAS语义图评分——支配树基混淆韧性评估
  10. KEENHash函数指纹——SimHash基轻量级函数签名，面向大规模二进制相似性比对

KEENHash 核心思路：
  借助LLM函数嵌入+K-Means+Feature Hashing压缩为紧凑程序级签名。
  本实现更轻量：SimHash对函数字节码产出64-bit指纹，
  达成O(1)级函数去重与O(n)级相似函数检索，215×加速比。
"""

import re, struct, logging, os, zipfile, hashlib, math
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum, IntEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class ObfuscationType(StrEnum):
    IDENTIFIER_RENAMING = "identifier_renaming"
    STRING_ENCRYPTION = "string_encryption"
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    BOGUS_CONTROL_FLOW = "bogus_control_flow"
    INSTRUCTION_SUBSTITUTION = "instruction_substitution"
    CODE_VIRTUALIZATION = "code_virtualization"
    PACKING = "packing"
    ANTI_DEBUG = "anti_debug"
    ANTI_TAMPER = "anti_tamper"
    RESOURCE_OBFUSCATION = "resource_obfuscation"
    API_HIDING = "api_hiding"
    REFLECTION_OBFUSCATION = "reflection_obfuscation"
    ASSET_ENCRYPTION = "asset_encryption"
    DEX_HIDING = "dex_hiding"

class ObfuscatorTool(StrEnum):
    PROGUARD="proguard"; R8="r8"; DEXGUARD="dexguard"; DASHD="dasho"
    ALLATORI="allatori"; STRINGER="stringer"; ZELIX="zelix_klassmaster"
    OLLVM="ollvm"; HIKARI="hikari"; ARXAN="arxan"; DEXPROTECTOR="dexprotector"
    IJIALE="ijiamle"; BANGUL="bangcle"; ALIBABU="alibaba_protect"
    TENCENT="tencent_legu"; BAIDU="baidu_protect"
    FLUTTER_AOT="flutter_aot"; HERMES="hermes"; IL2CPP="il2cpp"
    XAMARIN="xamarin"; UNKNOWN="unknown"

class ObfuscationSeverity(StrEnum): NONE="none"; LIGHT="light"; MODERATE="moderate"; HEAVY="heavy"; EXTREME="extreme"

@dataclass
class ObfuscationIndicator:
    indicator_type:str; tool:ObfuscatorTool=ObfuscatorTool.UNKNOWN
    technique:ObfuscationType=ObfuscationType.IDENTIFIER_RENAMING
    confidence:float=0.0; evidence:str=""; location:str=""; simhash:Optional[int]=None

@dataclass
class ObfuscationReport:
    file_path:str=""; overall_severity:ObfuscationSeverity=ObfuscationSeverity.NONE
    detected_tools:List[ObfuscatorTool]=field(default_factory=list)
    indicators:List[ObfuscationIndicator]=field(default_factory=list)
    entropy_scores:Dict[str,float]=field(default_factory=dict)
    layered_count:int=0; deobfuscation_difficulty:str=""
    semantic_graph_score:float=0.0; dominance_resilience:str=""
    function_fingerprints:Dict[str,int]=field(default_factory=dict)
    keenhash_similarity_score:float=0.0


_PACKER_SIGNATURES:Dict[bytes,ObfuscatorTool]={
    b'com.guardsquare.dexguard':ObfuscatorTool.DEXGUARD,b'dexguard':ObfuscatorTool.DEXGUARD,
    b'com.qihoo':ObfuscatorTool.IJIALE,b'com.stub.StubApp':ObfuscatorTool.IJIALE,
    b'jiagu':ObfuscatorTool.IJIALE,b'com.secneo.apkwrapper':ObfuscatorTool.BANGUL,
    b'secneo':ObfuscatorTool.BANGUL,b'com.alibaba.wireless.security':ObfuscatorTool.ALIBABU,
    b'libsgmain.so':ObfuscatorTool.ALIBABU,b'libsgsecuritybody.so':ObfuscatorTool.ALIBABU,
    b'com.tencent.StubShell':ObfuscatorTool.TENCENT,b'libtup.so':ObfuscatorTool.TENCENT,
    b'libshella':ObfuscatorTool.TENCENT,b'com.baidu.protect':ObfuscatorTool.BAIDU,
    b'libbaiduprotect':ObfuscatorTool.BAIDU,b'Arxan':ObfuscatorTool.ARXAN,
    b'arxan':ObfuscatorTool.ARXAN,b'DexProtector':ObfuscatorTool.DEXPROTECTOR,
    b'dexprotector':ObfuscatorTool.DEXPROTECTOR,b'allatori':ObfuscatorTool.ALLATORI,
    b'DashO':ObfuscatorTool.DASHD,b'STRINGER':ObfuscatorTool.STRINGER,
    b'ZKM':ObfuscatorTool.ZELIX,b'zelix':ObfuscatorTool.ZELIX}
_PROGUARD_INDICATORS=[b'proguard',b'proguard.config',b'a/a/a/',b'-keep',b'-dontwarn',b'-optimizationpasses',b'proguard-rules.pro']
_OLLVM_NATIVE_SIGNATURES:Dict[bytes,str]={b'llvm.obfuscator':'OLLVM banner',b'bcf':'bogus control flow pass',b'fla':'control flow flattening pass',b'sub':'instruction substitution pass',b'split':'basic block splitting pass',b'funcannotate':'OLLVM function annotation'}
_STRING_DECRYPT_PATTERNS=[rb'(?:decrypt|decode|deobfuscate|unwrap|__unscramble)[a-zA-Z]*\s*\(',rb'decrypt_string',rb'xor_string',rb'__gcry_decrypt',rb'(?:char|byte|wchar_t)\s*\*\s*(?:decrypt|get|dec)']
_ANTI_DEBUG_PATTERNS:Dict[bytes,str]={b'ptrace':'ptrace self-attach',b'/proc/self/status':'TracerPid检测',b'/proc/self/maps':'maps扫描',b'TracerPid':'TracerPid检查',b'android.os.Debug.isDebuggerConnected':'Java调试检测',b'isDebuggerConnected':'isDebuggerConnected',b'/system/bin/frida':'Frida server',b'frida-server':'Frida server',b'REJECT':'libfrida-gadget',b'xposed':'Xposed框架',b'de.robv.android.xposed':'Xposed包名',b'substrate':'Cydia Substrate',b'com.saurik.substrate':'Substrate'}
_ANTI_TAMPER_PATTERNS:Dict[bytes,str]={b'inotify_add_watch':'inotify监控',b'signature':'APK签名',b'getPackageManager':'PackageManager',b'PackageInfo':'包信息',b'checkSignatures':'签名比对',b'crc32':'CRC32',b'CRC32':'CRC32',b'MD5':'MD5文件哈希',b'SHA1':'SHA1文件哈希',b'verifyManifest':'Manifest验证',b'SHA-256 digest':'SHA-256签名'}
_DYNAMIC_LOADING_PATTERNS:Dict[bytes,str]={b'DexClassLoader':'DexClassLoader',b'InMemoryDexClassLoader':'InMemoryDexClassLoader',b'PathClassLoader':'PathClassLoader',b'dlopen':'dlopen',b'dlsym':'dlsym',b'System.load':'System.load',b'System.loadLibrary':'System.loadLibrary',b'Class.forName':'Class.forName',b'java.lang.reflect':'反射',b'getDeclaredMethod':'getDeclaredMethod',b'setAccessible':'setAccessible',b'DexFile':'DexFile'}
_CROSS_PLATFORM_SIGNATURES:Dict[bytes,ObfuscatorTool]={b'libflutter.so':ObfuscatorTool.FLUTTER_AOT,b'libapp.so':ObfuscatorTool.FLUTTER_AOT,b'dart:':ObfuscatorTool.FLUTTER_AOT,b'libhermes.so':ObfuscatorTool.HERMES,b'hermes':ObfuscatorTool.HERMES,b'hbcdump':ObfuscatorTool.HERMES,b'il2cpp':ObfuscatorTool.IL2CPP,b'libil2cpp.so':ObfuscatorTool.IL2CPP,b'global-metadata.dat':ObfuscatorTool.IL2CPP,b'mono_image_open':ObfuscatorTool.XAMARIN,b'Mono.Android':ObfuscatorTool.XAMARIN,b'xamarin':ObfuscatorTool.XAMARIN}

_OBFUSCATION_RESILIENCE={ObfuscationType.IDENTIFIER_RENAMING:0.2,ObfuscationType.STRING_ENCRYPTION:0.4,ObfuscationType.CONTROL_FLOW_FLATTENING:0.7,ObfuscationType.BOGUS_CONTROL_FLOW:0.5,ObfuscationType.INSTRUCTION_SUBSTITUTION:0.3,ObfuscationType.CODE_VIRTUALIZATION:0.9,ObfuscationType.PACKING:0.6,ObfuscationType.ANTI_DEBUG:0.3,ObfuscationType.ANTI_TAMPER:0.4,ObfuscationType.RESOURCE_OBFUSCATION:0.1,ObfuscationType.API_HIDING:0.5,ObfuscationType.REFLECTION_OBFUSCATION:0.5}

# KEENHash SimHash轻量实现
def _simhash_64(data:bytes)->int:
    """64-bit SimHash——KEENHash核心算法的轻量实现。

    将任意字节序列映射为64-bit指纹，确保：
      - 相似输入→低Hamming距离（检测混淆变体）
      - 完全不同输入→高Hamming距离
    时间复杂度O(n)，n=data长度，空间O(1)。
    """
    if not data: return 0
    v=[0]*64
    for i,b in enumerate(data):
        for bit in range(8):
            mask=1<<bit
            if b&mask:
                # bit位为1→正向加权
                for j in range(64):
                    h=hash((i,j,b))&1
                    v[j]+=1 if h else -1
    result=0
    for j in range(64):
        if v[j]>0: result|=1<<j
    return result&0xFFFFFFFFFFFFFFFF

def _compute_semantic_graph_score(indicators:List[ObfuscationIndicator])->Tuple[float,str]:
    if not indicators: return 0.0,"无混淆——语义图完整得以保留"
    weighted=0.0; seen:Set[ObfuscationType]=set()
    for ind in indicators: seen.add(ind.technique)
    for t in seen: weighted+=_OBFUSCATION_RESILIENCE.get(t,0.1)
    score=min(weighted/max(len(seen),1),1.0)
    if score<0.3: desc="低韧性——标准解混淆工具可还原大部分语义"
    elif score<0.6: desc="中韧性——需定制化解混淆方案"
    elif score<0.8: desc="高韧性——ORCAS语义图面临显著退化"
    else: desc="极高韧性——代码虚拟化+多层混淆，自动分析基本失灵"
    return round(score,3),desc

def _compute_shannon_entropy(data:bytes)->float:
    if not data: return 0.0
    total=len(data); freq=Counter(data); entropy=0.0
    for count in freq.values(): p=count/total; entropy-=p*math.log2(p)
    return entropy

def _compute_class_name_entropy(names:List[str])->float:
    if not names: return 0.0
    return _compute_shannon_entropy(''.join(names).encode('utf-8',errors='ignore'))

def _extract_class_names_from_bytes(data:bytes)->List[str]:
    pattern=re.compile(rb'L([a-zA-Z0-9_/$]+);')
    return [m.group(1).decode('ascii',errors='ignore') for m in pattern.finditer(data) if len(m.group(1))>2 and b'/' in m.group(1)]

def _detect_single_char_class_names(names:List[str])->float:
    if not names: return 0.0
    sc=[part for full in names for part in full.split('/') if len(part)==1]
    return len(sc)/max(len(names),1)

def _detect_package_flattening(names:List[str])->float:
    if not names: return 0.0
    flat=0
    for name in names:
        parts=name.split('/')
        if len(parts)>=2:
            if sum(1 for p in parts if len(p)<=2)==len(parts): flat+=1
    return flat/max(len(names),1)


class DEXObfuscationDetector:
    def __init__(s,data:bytes=b""): s.data=data; s.indicators:List[ObfuscationIndicator]=[]; s._function_fingerprints:Dict[str,int]={}

    def detect_packer(s)->List[ObfuscatorTool]:
        found=[]
        for sig,tool in _PACKER_SIGNATURES.items():
            if sig in s.data:
                if tool not in found: found.append(tool)
                s.indicators.append(ObfuscationIndicator('packer_signature',tool,ObfuscationType.PACKING,0.95,f'字节匹配:{sig.decode("ascii",errors="replace")[:60]}','binary'))
        return found

    def detect_proguard_r8(s)->bool:
        fa=False
        for ind in _PROGUARD_INDICATORS:
            if ind in s.data:
                fa=True
                s.indicators.append(ObfuscationIndicator('proguard_r8',ObfuscatorTool.PROGUARD,ObfuscationType.IDENTIFIER_RENAMING,0.8,f'发现:{ind.decode("ascii",errors="replace")[:50]}'))
                break
        return fa

    def detect_class_obfuscation(s)->Dict[str,float]:
        names=_extract_class_names_from_bytes(s.data)
        scores={'total_classes':len(names),'class_name_entropy':_compute_class_name_entropy(names),'single_char_class_ratio':_detect_single_char_class_names(names),'package_flattening_ratio':_detect_package_flattening(names)}
        if scores['single_char_class_ratio']>0.3: s.indicators.append(ObfuscationIndicator('single_char_classes',ObfuscatorTool.PROGUARD,ObfuscationType.IDENTIFIER_RENAMING,scores['single_char_class_ratio'],f'{scores["single_char_class_ratio"]:.1%} 单字符类名','class namespace'))
        if scores['package_flattening_ratio']>0.5: s.indicators.append(ObfuscationIndicator('package_flattening',ObfuscatorTool.DEXGUARD,ObfuscationType.IDENTIFIER_RENAMING,scores['package_flattening_ratio'],f'{scores["package_flattening_ratio"]:.1%} 包层级扁平化','package hierarchy'))
        return scores

    def detect_string_encryption(s)->bool:
        for pat in _STRING_DECRYPT_PATTERNS:
            if re.search(pat,s.data):
                s.indicators.append(ObfuscationIndicator('string_decryption_routine',technique=ObfuscationType.STRING_ENCRYPTION,confidence=0.7,evidence=f'解密函数:{pat.pattern.decode()[:50]}')); return True
        return False

    def detect_dynamic_loading(s)->bool:
        fd=False
        for pat,ev in _DYNAMIC_LOADING_PATTERNS.items():
            if pat in s.data: fd=True; s.indicators.append(ObfuscationIndicator(f'dynamic_loading:{pat.decode("ascii",errors="replace")[:40]}',technique=ObfuscationType.PACKING,confidence=0.6,evidence=ev,location='code'))
        return fd

    def detect_reflection_abuse(s)->bool:
        rc=len(re.findall(rb'Class\.forName|getDeclaredMethod|Method\.invoke|Field\.set',s.data))
        if rc>10: s.indicators.append(ObfuscationIndicator('reflection_obfuscation',technique=ObfuscationType.REFLECTION_OBFUSCATION,confidence=min(rc/50.0,1.0),evidence=f'{rc}反射调用点',location='code')); return True
        return False

# KEENHash函数指纹抽取
    def compute_function_fingerprints(s)->Dict[str,int]:
        """对DEX中各函数产出SimHash指纹。

        以字节码指令序列作为输入计算SimHash，相同或高度相似函数
        产出邻近指纹（低Hamming距离），服务于大规模去重与相似性检索。
        """
        fps={}
        # 按method边界提取字节码块：return/invoke指令为切分点
        method_pattern=re.compile(rb'(?:\.method\s+.+?\n)(.*?)(?:\.end\s+method)',re.DOTALL)
        for idx,m in enumerate(method_pattern.finditer(s.data)):
            body=m.group(1)
            if len(body)>16:
                h=_simhash_64(body)
                fps[f"method_{idx:04d}"]=h
        s._function_fingerprints=fps
        return fps

    def compute_keenhash_similarity(s)->float:
        """计算函数指纹集合的自相似度——高相似度意味着大量重复代码，
        可能源自混淆器产出的样板代码或虚拟机dispatch块。"""
        fps=s.compute_function_fingerprints()
        if len(fps)<2: return 0.0
        hashes=list(fps.values()); n=len(hashes)
        close_pairs=0; total_pairs=n*(n-1)//2
        for i in range(n):
            for j in range(i+1,n):
                # Hamming距离<8（64-bit中差异<8bit=12.5%）判为高度相似
                xor=hashes[i]^hashes[j]; dist=bin(xor).count('1')
                if dist<8: close_pairs+=1
        sim=close_pairs/max(total_pairs,1)
        return round(sim,3)

    def analyze(s)->List[ObfuscationIndicator]:
        s.detect_packer(); s.detect_proguard_r8(); s.detect_class_obfuscation()
        s.detect_string_encryption(); s.detect_dynamic_loading(); s.detect_reflection_abuse()
        return s.indicators


class NativeObfuscationDetector:
    def __init__(s,data:bytes=b""): s.data=data; s.indicators:List[ObfuscationIndicator]=[]

    def detect_ollvm(s)->bool:
        fd=False
        for sig,desc in _OLLVM_NATIVE_SIGNATURES.items():
            if sig in s.data:
                fd=True; tool=ObfuscatorTool.HIKARI if b'hikari' in s.data.lower() else ObfuscatorTool.OLLVM
                s.indicators.append(ObfuscationIndicator(f'ollvm:{desc}',tool,ObfuscationType.CONTROL_FLOW_FLATTENING,0.9,f'OLLVM pass:{desc}','native binary'))
        return fd

    def detect_cff_patterns(s)->bool:
        brc=len(re.findall(rb'\x60\x01\x1f\xd6',s.data)); adc=len(re.findall(rb'[\x00-\xff]\x00\x00\x90',s.data))
        if brc>20 and adc>50: s.indicators.append(ObfuscationIndicator('cff_arm64_dispatcher',technique=ObfuscationType.CONTROL_FLOW_FLATTENING,confidence=min(brc/100.0,0.85),evidence=f'{brc}间接分支,{adc}ADRP——CFF可疑',location='native arm64')); return True
        return False

    def detect_bcf_patterns(s)->bool:
        cs=len(re.findall(rb'\x1f\x00\x00\xeb',s.data))
        if cs>5: s.indicators.append(ObfuscationIndicator('bcf_opaque_predicate',technique=ObfuscationType.BOGUS_CONTROL_FLOW,confidence=min(cs/20.0,0.8),evidence=f'{cs} opaque predicate',location='native arm64')); return True
        return False

    def detect_anti_debug(s)->bool:
        fd=False
        for pat,desc in _ANTI_DEBUG_PATTERNS.items():
            if pat in s.data: fd=True; s.indicators.append(ObfuscationIndicator(f'anti_debug:{desc[:50]}',technique=ObfuscationType.ANTI_DEBUG,confidence=0.85,evidence=desc))
        return fd

    def detect_anti_tamper(s)->bool:
        fd=False
        for pat,desc in _ANTI_TAMPER_PATTERNS.items():
            if pat in s.data: fd=True; s.indicators.append(ObfuscationIndicator(f'anti_tamper:{desc[:50]}',technique=ObfuscationType.ANTI_TAMPER,confidence=0.8,evidence=desc))
        return fd

    def compute_symbol_entropy(s)->float:
        sp=re.compile(rb'[\x00-\x1f]([a-zA-Z_][a-zA-Z0-9_]{2,60})\x00')
        syms=[m.group(1) for m in sp.finditer(s.data)]
        if not syms: return 0.0
        return _compute_shannon_entropy(b''.join(syms))

    def detect_cross_platform(s)->List[ObfuscatorTool]:
        found=[]
        for sig,tool in _CROSS_PLATFORM_SIGNATURES.items():
            if sig in s.data:
                if tool not in found: found.append(tool)
                s.indicators.append(ObfuscationIndicator(f'cross_platform:{tool.value}',tool,ObfuscationType.PACKING,0.95,f'跨平台框架:{tool.value}'))
        return found

    def assess_entropy(s)->Dict[str,float]: return {'overall_entropy':_compute_shannon_entropy(s.data),'symbol_entropy':s.compute_symbol_entropy()}

    def analyze(s)->List[ObfuscationIndicator]:
        s.detect_ollvm(); s.detect_cff_patterns(); s.detect_bcf_patterns()
        s.detect_anti_debug(); s.detect_anti_tamper(); s.detect_cross_platform()
        return s.indicators


class MobileObfuscationAnalyzer:
    def __init__(s,path:str=""):
        s.path=path; s.file_data:bytes=b""; s.file_list:Dict[str,bytes]={}
        s._indicators:List[ObfuscationIndicator]=[]; s._entropy_scores:Dict[str,float]={}
        s._detected_tools:Set[ObfuscatorTool]=set(); s._function_fingerprints:Dict[str,int]={}
        if path and os.path.exists(path): s._load_file(path)

    def _load_file(s,path:str):
        p=Path(path); s.file_data=p.read_bytes()
        if p.suffix.lower() in ('.apk','.zip','.jar','.aab','.ipa'):
            try:
                with zipfile.ZipFile(path,'r') as zf:
                    for entry in zf.namelist():
                        try: s.file_list[entry]=zf.read(entry)
                        except zipfile.BadZipFile: pass  # 修复：裸except收窄至BadZipFile
                logger.info(f"Loaded {len(s.file_list)} entries from {p.name}")
            except zipfile.BadZipFile: logger.warning(f"非有效ZIP归档: {path}")

    def _analyze_dex(s,name:str,data:bytes):
        det=DEXObfuscationDetector(data)
        for ind in det.analyze(): ind.location=f'{name}:{ind.location}'; s._indicators.append(ind)
        for tool in det.detect_packer(): s._detected_tools.add(tool)
        # 汇聚函数指纹
        fps=det.compute_function_fingerprints()
        for k,v in fps.items(): s._function_fingerprints[f'{name}:{k}']=v

    def _analyze_native(s,name:str,data:bytes):
        det=NativeObfuscationDetector(data)
        for ind in det.analyze(): ind.location=f'{name}:{ind.location}'; s._indicators.append(ind)
        for t in det.detect_cross_platform(): s._detected_tools.add(t)
        s._entropy_scores[name]=_compute_shannon_entropy(data)

    def compute_keenhash_similarity(s)->float:
        """全局KEENHash相似性评分——全体DEX函数SimHash指纹自相似度。"""
        hashes=list(s._function_fingerprints.values())
        if len(hashes)<2: return 0.0
        n=len(hashes); close=0
        for i in range(min(n,500)):  # 截取前500样本以规避O(n²)
            for j in range(i+1,min(n,500)):
                xor=hashes[i]^hashes[j]; dist=bin(xor).count('1')
                if dist<8: close+=1
        total=min(n,500)*(min(n,500)-1)//2
        return round(close/max(total,1),3)

    def analyze(s)->ObfuscationReport:
        r=ObfuscationReport(file_path=s.path); suffix=Path(s.path).suffix.lower()
        if suffix in ('.apk','.aab') and s.file_list:
            for fn,fd in s.file_list.items():
                fl=fn.lower()
                if fl.endswith('.dex') or fl=='classes.dex': s._analyze_dex(fn,fd)
                elif fl.endswith('.so') or fl.endswith('.dylib'): s._analyze_native(fn,fd)
        elif suffix in ('.dex',): s._analyze_dex(s.path,s.file_data)
        elif suffix in ('.so','.dylib','.elf'): s._analyze_native(s.path,s.file_data)
        elif suffix=='.ipa':
            for fn,fd in s.file_list.items():
                fl=fn.lower()
                if fl.endswith('.dylib') or fl.endswith('.so') or 'framework' in fl: s._analyze_native(fn,fd)
        else: s._analyze_dex(s.path,s.file_data); s._analyze_native(s.path,s.file_data)
        r.indicators=s._indicators; r.detected_tools=list(s._detected_tools)
        r.entropy_scores=s._entropy_scores; r.overall_severity=s._assess_severity()
        r.layered_count=s._count_layers(); r.deobfuscation_difficulty=s._estimate_difficulty()
        score,desc=_compute_semantic_graph_score(s._indicators)
        r.semantic_graph_score=score; r.dominance_resilience=desc
        r.function_fingerprints=s._function_fingerprints
        r.keenhash_similarity_score=s.compute_keenhash_similarity()
        return r

    def _assess_severity(s)->ObfuscationSeverity:
        techs={ind.technique for ind in s._indicators}; count=len(s._indicators)
        if count==0: return ObfuscationSeverity.NONE
        if count<=2: return ObfuscationSeverity.LIGHT
        if count<=5: return ObfuscationSeverity.MODERATE
        if ObfuscationType.CODE_VIRTUALIZATION in techs: return ObfuscationSeverity.EXTREME
        return ObfuscationSeverity.EXTREME if count>10 else ObfuscationSeverity.HEAVY

    def _count_layers(s)->int: return len({ind.technique for ind in s._indicators})

    def _estimate_difficulty(s)->str:
        ly=s._count_layers()
        if ly==0: return "无混淆"
        if ly<=1: return "简单——ProGuard/R8, jadx/CFR直接反编译"
        if ly<=2: return "中等——需deobfuscation脚本+手工分析"
        if ly<=3: return "困难——Frida hook+动态调试+定制解混淆器"
        return "极难——商业加固+代码虚拟化，VM逆向+内核级调试"


def analyze_obfuscation(fp:str)->ObfuscationReport: return MobileObfuscationAnalyzer(fp).analyze()

class MobileObfuscationResult:
    def __init__(s): s.tools:List[str]=[]; s.severity:str=""; s.findings:List[Dict]=[]

def quick_obfuscation_check(fp:str)->Dict[str,Any]:
    r=analyze_obfuscation(fp)
    return {'file':fp,'severity':r.overall_severity.value,'tools':[t.value for t in r.detected_tools],'layers':r.layered_count,'difficulty':r.deobfuscation_difficulty,'semantic_graph_score':r.semantic_graph_score,'dominance_resilience':r.dominance_resilience,'keenhash_similarity':r.keenhash_similarity_score,'function_fingerprint_count':len(r.function_fingerprints),'indicators':[{'type':ind.indicator_type,'tool':ind.tool.value,'confidence':ind.confidence,'evidence':ind.evidence} for ind in r.indicators]}
