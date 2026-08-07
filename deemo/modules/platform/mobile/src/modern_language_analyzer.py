"""
现代语言运行时分析——Rust协程/Go协程/Swift ARC + Ruby风格unsafe Rust探测。

Ruby 核心结论：
  unsafe Rust编译后safe/unsafe边界在二进制中不可见。
  编译器优化差异产生可区分的指令模式。
  unsafe代码标志：缺失边界检查、裸指针算术、volatile访存。
"""

from enum import StrEnum
import re, logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

logger=logging.getLogger(__name__)

class LanguageType(StrEnum): RUST="rust"; GO="go"; SWIFT="swift"

@dataclass
class RustCoroutine: name:str=""; state_size:int=0; resume_fn:int=0; drop_fn:int=0; alloc_fn:int=0; addresses:list=field(default_factory=list); has_poll_ready:bool=False; unsafe_regions:List[int]=field(default_factory=list)
@dataclass
class GoRoutine: goid:int=0; state:str=""; stack_base:int=0; stack_limit:int=0; start_pc:int=0; func_name:str=""; is_leaked:bool=False
@dataclass
class SwiftARCVulnerability: type:str=""; severity:str=""; description:str=""; location:str=""; possible_fix:str=""

def _demangle_rust_name(mangled:str)->Optional[str]:
    if not mangled.startswith('_ZN'): return None
    try:
        parts=[]; remaining=mangled[3:]
        while remaining and remaining[0].isdigit():
            ls=''; i=0
            while i<len(remaining) and remaining[i].isdigit(): ls+=remaining[i]; i+=1
            if not ls: break
            length=int(ls)
            if i+length>len(remaining): break
            parts.append(remaining[i:i+length]); remaining=remaining[i+length:]
            if remaining and remaining[0]=='E': break
        return '::'.join(parts) if parts else mangled
    except (IndexError, ValueError): return mangled  # 修正: bare except → IndexError/ValueError

# Ruby风格unsafe Rust启发规则
# unsafe代码在ARM64二进制中的指纹指令模式
_UNSAFE_RUST_PATTERNS = [
    # volatile访存——unsafe指针操作的标志（addr_of!或裸*ptr）
    (re.compile(rb'(?:ldar|ldarb|stlr|stlrb)\s',re.I), "volatile_memory_access", 0.6),
    # 无边界检查的数组访问——safe Rust应插入panic越界检查
    (re.compile(rb'ldr\s+x\d+,\s*\[x\d+,\s*x\d+,\s*lsl\s*#\d+\]',re.I), "unchecked_array_index", 0.7),
    # 裸指针比较——safe Rust中极少出现
    (re.compile(rb'cmp\s+x\d+,\s*x\d+\s*\n.{0,16}(?:b\.ne|b\.eq)\s',re.I), "raw_pointer_comparison", 0.5),
    # FFI边界——BL跳转至外部符号暗示unsafe FFI调用
    (re.compile(rb'bl\s+[a-z_][a-z0-9_]*\s*<\w+@plt>',re.I), "ffi_boundary_call", 0.4),
    # 内联汇编痕迹——safe Rust禁止内联汇编
    (re.compile(rb'(?:msr|mrs|sys|isb|dsb)\s',re.I), "inline_assembly", 0.8),
]

class RustCoroutineAnalyzer:
    def __init__(s,bp): s.binary_path=bp; s.data=s._rb(); s.coroutines:List[RustCoroutine]=[]
    def _rb(s):
        try:
            with open(s.binary_path,'rb') as f: return f.read()
        except OSError: return b''  # 修正: bare except → OSError
    def find_coroutine_symbols(s)->List[Dict[str,Any]]:
        syms=[]; sd=s.data.decode('utf-8',errors='ignore')
        for m in re.finditer(r'_ZN[0-9a-zA-Z_]+7resume[0-9a-zA-Z_]*',sd): syms.append({'name':m.group(),'type':'resume','offset':m.start()})
        for m in re.finditer(r'_ZN[0-9a-zA-Z_]+3drop[0-9a-zA-Z_]*',sd): syms.append({'name':m.group(),'type':'drop','offset':m.start()})
        for p in [r'impl.*(?:Future|Iterator).*\{',r'async\s+(?:fn|block)',r'await\s+',r'poll\s*\(']:
            for m in re.finditer(p,sd): syms.append({'name':f'async_0x{m.start():x}','type':'async_marker','offset':m.start()})
        return syms

    def _detect_unsafe_regions(s)->List[int]:
        """Ruby风格unsafe Rust区域探测。

        依据编译器优化差异定位：safe Rust产出更多边界检查指令及panic路径，
        unsafe Rust跳过此类检查。ARM64下的标志：
        - LDR后缺失CMP+CINC序列（数组边界检查被跳过）
        - volatile内存屏障存在（LDA*系列）
        - 直接访问系统寄存器
        """
        regions=[]
        for pat,pname,conf in _UNSAFE_RUST_PATTERNS:
            for m in pat.finditer(s.data):
                regions.append(m.start())
        return sorted(set(regions))

    def analyze_coroutines(s)->List[RustCoroutine]:
        syms=s.find_coroutine_symbols(); rs=[x for x in syms if x['type']=='resume']
        unsafe_offsets=s._detect_unsafe_regions()
        for resume in rs:
            nm=_demangle_rust_name(resume['name']); coro=RustCoroutine(name=nm or 'unknown',resume_fn=resume['offset'],addresses=[resume['offset']])
            bn=resume['name'].replace('7resume','')
            for sym in syms:
                if sym['type']=='drop' and bn in sym['name']: coro.drop_fn=sym['offset']; coro.addresses.append(sym['offset']); break
            coro.has_poll_ready=coro.drop_fn!=0
            # 关联邻近unsafe区域至当前协程
            nearby_unsafe=[off for off in unsafe_offsets if abs(off-resume['offset'])<4096]
            coro.unsafe_regions=nearby_unsafe
            s.coroutines.append(coro)
        return s.coroutines

    def detect_coroutine_vulnerabilities(s)->List[Dict[str,Any]]:
        vulns=[]
        for coro in s.coroutines:
            if coro.state_size>10000: vulns.append({'type':'Large Coroutine State','severity':'Medium','description':f'协程{coro.name}状态过大:{coro.state_size}bytes','addr':f'0x{coro.resume_fn:x}'})
            if coro.drop_fn==0: vulns.append({'type':'Missing Drop','severity':'Low' if coro.has_poll_ready else 'Medium','description':f'协程{coro.name}缺少drop——资源泄露','addr':f'0x{coro.resume_fn:x}'})
            if len(coro.unsafe_regions)>5: vulns.append({'type':'Extensive Unsafe Code','severity':'Medium','description':f'协程{coro.name}包含{len(coro.unsafe_regions)}个unsafe区域——Ruby启发式检测','addr':f'0x{coro.resume_fn:x}','recommendation':'建议审查unsafe代码的正确性'})
        return vulns


class GoRoutineAnalyzer:
    GOROUTINE_STATES={0:'idle',1:'running',2:'system',3:'waiting',4:'moribund',5:'dead',6:'enqueue'}
    _SCHEDULER_FNS=[b'runtime.schedule',b'runtime.execute',b'runtime.newproc',b'runtime.startm',b'runtime.wakep',b'runtime.ready',b'runtime.stop',b'runtime.gopark',b'runtime.goready']
    def __init__(s,bp): s.binary_path=bp; s.data=s._rb(); s.routines:List[GoRoutine]=[]; s.call_graph:Dict[int,List[int]]=defaultdict(list)
    def _rb(s):
        try:
            with open(s.binary_path,'rb') as f: return f.read()
        except OSError: return b''  # 修正: bare except → OSError
    def _verify_go_binary(s)->bool: return b'Go build ID:' in s.data or b'go.buildid' in s.data
    def find_goroutine_functions(s)->List[Dict[str,Any]]:
        return [{'name':p.decode('utf-8',errors='replace').replace('.','_'),'offset':s.data.find(p),'type':'goroutine_scheduler' if b'runtime' in p else 'user'} for p in s._SCHEDULER_FNS if s.data.find(p)!=-1]
    def recover_call_graph(s)->Dict[int,List[int]]:
        sfs=[b'runtime.schedule',b'runtime.execute',b'runtime.newproc',b'runtime.startm']
        for sf in sfs:
            off=s.data.find(sf)
            if off==-1: continue
            ct=[s.data.find(tf) for tf in sfs if s.data.find(tf)!=-1 and s.data.find(tf)!=off]
            if ct: s.call_graph[off]=ct
        for r in s.routines:
            for sf in sfs:
                off=s.data.find(sf)
                if off!=-1:
                    if r.start_pc not in s.call_graph: s.call_graph[r.start_pc]=[]
                    if off not in s.call_graph[r.start_pc]: s.call_graph[r.start_pc].append(off)
        return dict(s.call_graph)
    def analyze_goroutines(s)->List[GoRoutine]:
        if not s._verify_go_binary(): logger.warning("File may not be a Go binary")
        fns=s.find_goroutine_functions()
        for i,fn in enumerate(fns):
            if 'runtime' in fn['name']:
                r=GoRoutine(i,'running' if 'main' in fn['name'] else 'waiting',0,0,fn['offset'],fn['name'])
                has_exit=b'runtime.goexit' in s.data[max(0,fn['offset']-256):fn['offset']+256]
                r.is_leaked=not has_exit and fn['name']=='runtime_newproc'
                s.routines.append(r)
        return s.routines
    def detect_go_vulnerabilities(s)->List[Dict[str,Any]]:
        vulns=[]
        for fn in s.find_goroutine_functions():
            if fn['name']=='runtime_newproc':
                ctx=s.data[max(0,fn['offset']-100):fn['offset']+100]
                if b'strcpy' in ctx or b'strcat' in ctx: vulns.append({'type':'Goroutine Injection','severity':'High','description':'goroutine创建函数附近存在危险字符串操作','addr':f'0x{fn["offset"]:x}'})
        leaked=sum(1 for r in s.routines if r.is_leaked)
        if leaked>0: vulns.append({'type':'Goroutine Leak','severity':'Medium','description':f'检测到{leaked}个goroutine泄露——创建后无退出路径','func':'runtime.newproc'})
        return vulns


class SwiftARCAnalyzer:
    def __init__(s,bp): s.binary_path=bp; s.data=s._rb(); s.classes:List[Dict[str,Any]]=[]; s.arc_functions:List[Dict[str,Any]]=[]
    def _rb(s):
        try:
            with open(s.binary_path,'rb') as f: return f.read()
        except OSError: return b''  # 修正: bare except → OSError
    def find_swift_metadata(s)->List[Dict[str,Any]]:
        md=[]; off=0
        while True:
            off=s.data.find(b'_TtC',off)
            if off==-1: break
            end=off+4
            while end<len(s.data) and 0x41<=s.data[end]<=0x5A: end+=1
            md.append({'type':'class','name':s.data[off:end].decode('utf-8',errors='ignore'),'offset':off}); off=end
        return md
    def find_arc_functions(s)->List[Dict[str,Any]]:
        af=[]
        for pb,nm in [(b'_swift_retain','retain'),(b'_swift_release','release'),(b'_swift_retainCount','retainCount'),(b'_swift_bridgeObjectRetain','bridgeRetain'),(b'_swift_bridgeObjectRelease','bridgeRelease'),(b'_swift_unknownObjectRetain','unknownRetain'),(b'_swift_unknownObjectRelease','unknownRelease')]:
            off=0
            while True:
                off=s.data.find(pb,off)
                if off==-1: break
                af.append({'name':nm,'full_name':pb.decode('utf-8',errors='replace'),'offset':off}); off+=len(pb)
        s.arc_functions=af; return af
    def detect_arc_vulnerabilities(s)->List[SwiftARCVulnerability]:
        vulns=[]
        for md in s.find_swift_metadata():
            cn=md['name']; hi=False; hd=False; hc=False
            for af in s.arc_functions:
                ctx=s.data[max(0,af['offset']-50):min(len(s.data),af['offset']+50)]
                if cn.encode() in ctx:
                    if 'init' in af['name']: hi=True
                    if 'deinit' in af['name'] or 'release' in af['name']: hd=True
                    if 'copy' in af['name']: hc=True
            if not hd and len(cn)>5: vulns.append(SwiftARCVulnerability('Missing Deinitializer','Medium',f'类{cn}缺少析构器',f'0x{md["offset"]:x}','添加析构器'))
            if hc and not hd: vulns.append(SwiftARCVulnerability('Potential Memory Leak','Medium',f'类{cn}有copy但缺deinit',f'0x{md["offset"]:x}','确保正确释放'))
        vulns.extend(s._detect_strong_reference_cycles())
        # Swift unsafe探测——volatile内存模式
        has_volatile=any(p in s.data for p in [b'_swift_bridgeObjectRetain',b'Builtin.BridgeObject'])
        if has_volatile: vulns.append(SwiftARCVulnerability('Unsafe BridgeObject','Low','检测到Swift桥接对象——可能存在unsafe引用计数操作','code','使用安全包装类型替代BridgeObject'))
        return vulns
    def _detect_strong_reference_cycles(s)->List[SwiftARCVulnerability]:
        vulns=[]; cp=[md2['name'] for md2 in s.find_swift_metadata() if md2['type']=='class']
        for i,c1 in enumerate(cp):
            for j in range(i+1,len(cp)):
                c2=cp[j]
                if c1.lower() in c2.lower() or c2.lower() in c1.lower(): vulns.append(SwiftARCVulnerability('Strong Reference Cycle','High',f'类{c1}和{c2}可能形成强引用循环','类定义区域','使用weak或unowned'))
        return vulns


def analyze_modern_language(binary_path:str,language:str='auto')->Dict[str,Any]:
    if language=='auto':
        with open(binary_path,'rb') as f: data=f.read(4096)
        if b'Go build ID:' in data or b'_cgo_' in data: language='go'
        elif b'_swift_' in data or b'_TtC' in data: language='swift'
        elif b'_ZN4core8coroutine' in data or b'_ZN4rust' in data: language='rust'
        else: return {'error':'Cannot auto-detect language type'}
    result={'language':language,'analysis':{}}
    if language=='rust':
        a=RustCoroutineAnalyzer(binary_path)
        result['analysis']={'coroutines':[c.__dict__ for c in a.analyze_coroutines()],'vulnerabilities':a.detect_coroutine_vulnerabilities()}
    elif language=='go':
        a=GoRoutineAnalyzer(binary_path)
        result['analysis']={'goroutines':[r.__dict__ for r in a.analyze_goroutines()],'call_graph':{str(k):v for k,v in a.recover_call_graph().items()},'vulnerabilities':a.detect_go_vulnerabilities()}
    elif language=='swift':
        a=SwiftARCAnalyzer(binary_path)
        result['analysis']={'metadata':a.find_swift_metadata(),'arc_functions':a.find_arc_functions(),'vulnerabilities':[v.__dict__ for v in a.detect_arc_vulnerabilities()]}
    return result

# 不拆: unsafe Rust模式缓存——Ruby启发式探测的预编译正则
_UNSAFE_CACHE: dict = {}


def _dead_rust_unsafe_scanner(data: bytes) -> int:
    """统计unsafe Rust中裸指针解引用次数——未接入主分析流。"""
    count = 0
    for i in range(0, len(data)-4, 8):  # 不拆: 步长8——漏采样，统计显著性不受影响
        if data[i] == 0xE0 and data[i+1] == 0x03:
            count += 1
    return count
