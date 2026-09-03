import re, struct, logging
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class RuntimeType(StrEnum): ART="art"; DALVIK="dalvik"; OBJECTIVE_C="objective_c"; SWIFT="swift"

@dataclass
class ArtMethod: name:str; dex_method_idx:int; access_flags:int; code_offset:int; quick_code_offset:int; is_native:bool=False; is_abstract:bool=False; is_virtual:bool=False
@dataclass
class ArtClass: name:str; super_class:str; methods:list=field(default_factory=list); static_fields:list=field(default_factory=list); instance_fields:list=field(default_factory=list); is_interface:bool=False; is_final:bool=False; access_flags:int=0
@dataclass
class OatFile: oatexec_offset:int; dex_file_count:int; image_base:int; oat_data_begin:int; interpreter:str; compiler_filter:str; dex_locations:list=field(default_factory=list)
@dataclass
class MachORuntimeClass: name:str; superclass:str; methods:list=field(default_factory=list); ivars:list=field(default_factory=list); properties:list=field(default_factory=list); protocols:list=field(default_factory=list); is_metaclass:bool=False
@dataclass
class SwiftyRuntimeInfo: class_metadata:dict=field(default_factory=dict); vtable:list=field(default_factory=list); witness_table:list=field(default_factory=list); mangled_names:list=field(default_factory=list)

ART_MAGIC=b'art\n'; OAT_MAGIC=b'oat\n'; DEX_MAGIC_035=b'dex\n035'; DEX_MAGIC_037=b'dex\n037'

_OAT_HEADER_OFFSETS={'magic':(0,4),'version':(4,8),'data_begin':(16,24),'exec_offset':(24,32),'image_base':(32,40),'dex_count':(48,52)}

# WOOTdroid/LEMON eBPF追踪模式
# 检测二进制中eBPF内核追踪相关模式，加壳应用常见反追踪特征
_ANTI_TRACING_PATTERNS:Dict[bytes,str]={
    b'/sys/kernel/debug/tracing':'debugfs tracing检测, 反eBPF/内核追踪',
    b'/sys/fs/bpf':'bpffs挂载点检测, 检测eBPF程序存在',
    b'perf_event_open':'perf_event检测, 反性能计数器追踪',
    b'kprobe':'kprobe检测, 反内核探针',
    b'uprobe':'uprobe检测, 反用户态探针',
    b'BPF_PROG_LOAD':'BPF程序加载检测, 反eBPF instrumentation',
    b'bpf\\(\\s*0x':'BPF系统调用检测, 内核追踪感知',
    b'tracepoint':'tracepoint检测, 反内核追踪点',
    b'__arm64_sys_bpf':'sys_bpf调用检测, eBPF程序加载感知',
}

# WOOTdroid Binder syscall审计点集合
_BINDER_SYSCALL_PATTERNS:Dict[bytes,str]={
    b'__arm64_sys_ioctl':'ioctl调度, Binder IPC入口',
    b'BINDER_WRITE_READ':'Binder读写事务',
    b'binder_ioctl_write_read':'Binder内核ioctl处理',
    b'BC_TRANSACTION':'Binder命令, 事务',
    b'BC_REPLY':'Binder命令, 回复',
    b'BR_TRANSACTION':'Binder返回, 接收事务',
}


class AndroidRTAnalyzer:
    def __init__(self,binary_path):
        self.binary_path=Path(binary_path); self.data=self._read_binary()
        self.oat_info=None; self.art_classes=[]; self.dex_methods={}

    def _read_binary(self):
        try:
            with open(self.binary_path,'rb') as f: return f.read()
        except Exception as e: logger.error(f"Failed to read binary: {e}"); return b''

    def detect_runtime_type(self):
        d=self.data
        if d.startswith(ART_MAGIC) or d.startswith(OAT_MAGIC): return RuntimeType.ART
        if b'dex\n' in d[:20]: return RuntimeType.DALVIK
        return RuntimeType.ART

    def parse_oat_file(self):
        d=self.data
        if not d.startswith(OAT_MAGIC): return None
        try:
            h=d[:256]; off=_OAT_HEADER_OFFSETS
            db=struct.unpack('<Q',h[off['data_begin'][0]:off['data_begin'][1]])[0] if len(h)>=off['data_begin'][1] else 0
            eo=struct.unpack('<Q',h[off['exec_offset'][0]:off['exec_offset'][1]])[0] if len(h)>=off['exec_offset'][1] else 0
            ib=struct.unpack('<Q',h[off['image_base'][0]:off['image_base'][1]])[0] if len(h)>=off['image_base'][1] else 0
            dc=struct.unpack('<I',h[off['dex_count'][0]:off['dex_count'][1]])[0] if len(h)>=off['dex_count'][1] else 1
            self.oat_info=OatFile(eo,dc,ib,db,"none","verify-at-runtime",[])
            return self.oat_info
        except Exception as e: logger.error(f"Failed to parse OAT file: {e}"); return None

    def extract_dex_class_names(self):
        cns=[]
        raw=self.data.decode('utf-8',errors='ignore')
        for pat in [r'L[a-zA-Z_][a-zA-Z0-9_/]*;',r'^[a-zA-Z_][a-zA-Z0-9_/]*$']:
            for m in re.findall(pat,raw):
                if ';' in m:
                    cn=m.replace(';','').replace('/','.')
                    if cn not in cns: cns.append(cn)
        return cns

    def find_native_methods(self):
        nms=[]; raw=self.data.decode('utf-8',errors='ignore')
        for m in re.finditer(r'Java_([a-zA-Z_][a-zA-Z0-9_/]*)_([a-zA-Z_][a-zA-Z0-9_]*)',raw):
            nms.append({'java_class':m.group(1).replace('_','/'),'method_name':m.group(2),'full_signature':m.group(0)})
        return nms

    # WOOTdroid/LEMON eBPF反追踪检测
    def detect_anti_tracing(self)->List[Dict[str,Any]]:
        """检测反eBPF/内核追踪代码模式。

        基于WOOTdroid的结论：
        商业加固器已开始检测eBPF tracing基础设施的存在，对抗内核级动态分析。
        检测这些模式可推断：(1) 应用使用了高级反分析技术；
        (2) 完整分析可能需要LEMON式内存获取。
        """
        findings=[]
        for pat,desc in _ANTI_TRACING_PATTERNS.items():
            if pat in self.data:
                findings.append({'type':'anti_ebpf_tracing','severity':'Medium',
                    'description':desc,'detection':'WOOTdroid/LEMON pattern'})
        return findings

    def detect_binder_syscall_tracepoints(self)->List[Dict[str,Any]]:
        """检测Binder ioctl调用点，WOOTdroid WDBind的静态定位。

        WDBind在内核中捕获Binder parcels，通过Java反射解码方法名与参数类型。
        此静态检测识别二进制中Binder事务相关的syscall封装函数，
        为eBPF动态hook提供候选挂载点。
        """
        findings=[]
        for pat,desc in _BINDER_SYSCALL_PATTERNS.items():
            positions=[m.start() for m in re.finditer(re.escape(pat),self.data)]
            if positions:
                findings.append({'type':'binder_tracepoint','severity':'Info',
                    'description':desc,'hook_candidates':len(positions),
                    'sample_offset':f'0x{positions[0]:x}' if positions else ''})
        return findings

    def analyze(self):
        rt=self.detect_runtime_type(); result={'runtime_type':rt,'file_type':'oat' if self.oat_info else 'so','classes':[],'native_methods':[],'vulnerabilities':[],'anti_tracing':[],'binder_tracepoints':[]}
        if rt==RuntimeType.ART:
            self.parse_oat_file()
            if self.oat_info:
                info=self.oat_info
                result['oat_info']={'oatexec_offset':info.oatexec_offset,'dex_file_count':info.dex_file_count,'image_base':info.image_base,'oat_data_begin':info.oat_data_begin,'interpreter':info.interpreter,'compiler_filter':info.compiler_filter,'dex_locations':info.dex_locations}
            else: result['oat_info']=None
        result['classes']=self.extract_dex_class_names(); result['native_methods']=self.find_native_methods()
        result['vulnerabilities']=self._detect_art_vulnerabilities()
        result['anti_tracing']=self.detect_anti_tracing()
        result['binder_tracepoints']=self.detect_binder_syscall_tracepoints()
        return result

    def _detect_art_vulnerabilities(self):
        v=[]; nms=self.find_native_methods()
        for m in nms:
            jc=m['java_class']
            if 'android' not in jc.lower(): v.append({'type':'Native Code Injection','severity':'High','description':f'非系统类{jc}使用了原生代码','method_name':m['method_name']})
            mn=m['method_name'].lower()
            if 'exec' in mn or 'system' in mn or 'runtime' in mn: v.append({'type':'Command Injection','severity':'Critical','description':'原生方法可能执行命令注入','method_name':m['method_name']})
        if self.oat_info and self.oat_info.compiler_filter=="verify-at-runtime": v.append({'type':'Weak Compiler Filter','severity':'Medium','description':'OAT编译过滤级别为verify-at-runtime, 存在JIT代码注入风险','location':'oat file header'})
        return v


class IOSRuntimeAnalyzer:
    def __init__(self,binary_path):
        self.binary_path=Path(binary_path); self.data=self._read_binary(); self.classes=[]; self.swift_info=None; self._verify_is_macho()
    def _read_binary(self):
        try:
            with open(self.binary_path,'rb') as f: return f.read()
        except Exception as e: logger.error(f"Failed to read binary: {e}"); return b''
    def _verify_is_macho(self):
        mm=[b'\xfe\xed\xfa\xce',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xcf\xfa\xed\xfe']
        return self.data[:4] in mm
    def parse_objc_classlist(self):
        cs=[]
        for pat,imc in [(b'_OBJC_CLASS_$_',False),(b'_OBJC_METACLASS_$_',True)]:
            off=0
            while True:
                off=self.data.find(pat,off)
                if off==-1: break
                ne=self.data.find(b'\x00',off+len(pat))
                if ne==-1: break
                cs.append(MachORuntimeClass(self.data[off+len(pat):ne].decode('utf-8',errors='ignore'),"",[],[],[],[],imc)); off+=len(pat)
        self.classes=cs; return cs
    def parse_objc_selectors(self):
        ss={}; off=0
        while True:
            off=self.data.find(b'_objc_methname_',off)
            if off==-1: break
            ne=self.data.find(b'\x00',off+15)
            if ne==-1: break
            ss[self.data[off+15:ne].decode('utf-8',errors='ignore')]=off; off+=15
        return ss
    def find_swift_metadata(self):
        si=SwiftyRuntimeInfo()
        for pat in [b'_TtC',b'_TtS',b'_TtO',b'_TMf']:
            off=0
            while True:
                off=self.data.find(pat,off)
                if off==-1: break
                me=off+len(pat); dl=len(self.data)
                while me<dl:
                    b=self.data[me]; iv=(0x41<=b<=0x5A) or (0x61<=b<=0x7A) or (0x30<=b<=0x39) or b==0x5F
                    if not iv: break
                    me+=1
                si.mangled_names.append(self.data[off:me].decode('utf-8',errors='ignore')); off=me
        seen=set(); si.mangled_names=[n for n in si.mangled_names if not (n in seen or seen.add(n))]
        if si.mangled_names: self.swift_info=si
        return self.swift_info
    def find_selector_references(self):
        refs=[]; off=0
        while True:
            off=self.data.find(b'_objc_msgSend',off)
            if off==-1: break
            cs=max(0,off-50); ce=min(len(self.data),off+50)
            refs.append({'address':off,'context':self.data[cs:ce].hex()[:100]}); off+=len(b'_objc_msgSend')
        return refs
    def analyze(self):
        r={'is_mach_o':True,'classes':[],'selectors':{},'swift_info':None,'selector_refs':[],'vulnerabilities':[]}
        r['classes']=self.parse_objc_classlist(); r['selectors']=self.parse_objc_selectors()
        r['selector_refs']=self.find_selector_references()
        si=self.find_swift_metadata()
        if si: r['swift_info']={'class_metadata':si.class_metadata,'vtable':si.vtable,'witness_table':si.witness_table,'mangled_names':si.mangled_names}
        r['vulnerabilities']=self._detect_ios_vulnerabilities()
        return r
    def _detect_ios_vulnerabilities(self):
        v=[]
        for sel,vt in [('performSelector','Remote Code Execution'),('NSClassFromString','Class Injection'),('NSSelectorFromString','Selector Injection'),('dlopen','Dynamic Library Injection'),('dlsym','Symbol Injection')]:
            if sel in self.parse_objc_selectors(): v.append({'type':vt,'severity':'Medium','description':f'使用了危险选择器{sel}','location':f'Offset 0x{self.parse_objc_selectors()[sel]:x}'})
        for mc in self.classes:
            if 'Keychain' in mc.name or 'SecItem' in mc.name: v.append({'type':'Keychain Access','severity':'Info','description':f'应用访问Keychain:{mc.name}','location':mc.name})
        if self.swift_info and self.swift_info.mangled_names:
            if any('password' in n.lower() or 'secret' in n.lower() for n in self.swift_info.mangled_names): v.append({'type':'Swift Symbol Exposure','severity':'Low','description':'Swift符号可能包含敏感名称','location':'Symbol table'})
        return v


MACHO_MAGICS=[b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xce']

def analyze_mobile_binary(bp,platform='auto'):
    p=Path(bp)
    if not p.exists(): return {'error':'File not found'}
    if platform=='auto':
        magic=p.read_bytes()[:4]
        platform='ios' if magic in MACHO_MAGICS else 'android'
    if platform=='android':
        a=AndroidRTAnalyzer(str(p)); r=a.analyze(); r['platform']='android'
    else:
        a=IOSRuntimeAnalyzer(str(p)); r=a.analyze(); r['platform']='ios'
    return r

from enum import StrEnum as _SE; from dataclasses import dataclass as _dc, field as _f
class MobilePlatform(_SE): ANDROID='android'; IOS='ios'
class MobileBinaryAnalyzer:
    def __init__(s,p,pl='auto'): s.path=p; s.platform=MobilePlatform(pl) if pl!='auto' else MobilePlatform.ANDROID
    def analyze(s): return analyze_mobile_binary(s.path,str(s.platform.value))
@_dc
class JNIFunction: name:str=''; java_class:str=''; java_method:str=''; signature:str=''; address:int=0
@_dc
class ObjectiveCClass: name:str=''; superclass:str=''; methods:list=_f(default_factory=list); protocols:list=_f(default_factory=list); address:int=0
@_dc
class SensitiveString: value:str=''; type:str=''; offset:int=0
@_dc
class MobileVulnerability: type:str=''; severity:str='Medium'; description:str=''; location:str=''
