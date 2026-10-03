"""WASI沙箱分析: 扫描WASM导入及宿主边界, 识别逃逸路径。"""
import logging, os, re, subprocess
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger(__name__)

_SANDBOX_FINGERPRINTS={"wasi_snapshot_preview1":"wasmtime/wasmer/wasmedge","wasi_unstable":"lucet/old_wasmtime","wasix":"wasmer","env":"node_wasi","wasi_ephemeral":"wasmtime_edge"}

@dataclass
class WASMImport: module:str=""; function:str=""; signature:str=""; is_dangerous:bool=False
@dataclass
class EscapeRisk: type:str=""; severity:str=""; description:str=""; proof_of_concept:str=""

class WASISandboxAnalyzer:
    DANGEROUS_IMPORTS={"wasi_snapshot_preview1":{"fd_write":"写入任意文件描述符","fd_read":"读取任意fd","fd_seek":"文件指针操作","path_open":"路径打开——文件系统逃逸主向量","sock_send":"网络发送","sock_recv":"网络接收","proc_exec":"进程执行: 最高危WASI能力","proc_raise":"信号发送"},"env":{"getenv":"环境变量读取"},"unknown":{"system":"系统调用","mmap":"内存映射","munmap":"内存释放"}}
    _ESCAPE_CHAINS=[(("path_open","fd_write"),"CRITICAL","path_open+fd_write→写入沙箱外任意文件"),(("path_open","fd_read"),"HIGH","path_open+fd_read→读取沙箱外任意文件"),(("sock_open","sock_connect"),"HIGH","sock_open+sock_connect→C2通道建立"),(("fd_read","sock_send"),"CRITICAL","fd_read+sock_send→本地文件外泄"),(("proc_exec","path_open"),"CRITICAL","proc_exec+path_open→执行沙箱外程序")]

    def __init__(s,wp=""): s.wasm_path=os.path.abspath(wp) if wp else ""

    def parse_imports(s)->list:
        if not s.wasm_path: return []
        li=[]
        try:
            import json; r=subprocess.run(['r2','-q','-c','iij; q',s.wasm_path],capture_output=True,text=True,timeout=60,encoding='utf-8',errors='replace')
            syms=json.loads(r.stdout) if r.stdout.strip() else []
            for sym in syms:
                sz=sym.get('name',''); sl=sym.get('lib','unknown'); bd=sz in s.DANGEROUS_IMPORTS.get(sl,{})
                li.append(WASMImport(sl,sz,"",bd))
        except Exception as e: logger.debug(f"WASM导入解析失败:{e}")
        return li

    def _detect_escape_chains(s,dfs:set)->list:
        ch=[]
        for combo,sev,desc in s._ESCAPE_CHAINS:
            if all(fn in dfs for fn in combo): ch.append(EscapeRisk("capability_chain",sev,desc,f"组合利用{' + '.join(combo)}"))
        return ch

    def _infer_sandbox_type(s,li:list)->str:
        ms=set()
        for imp in li: ms.add(imp.module)
        for mod,rt in _SANDBOX_FINGERPRINTS.items():
            if mod in ms: return rt
        return "unknown"

    def analyze_escape_risks(s)->list:
        lr=[]; li=s.parse_imports(); ld=[i for i in li if i.is_dangerous]
        for imp in ld:
            dd=s.DANGEROUS_IMPORTS.get(imp.module,{}); sd=dd.get(imp.function,"危险导入")
            ssv="HIGH" if "exec" in imp.function else "MEDIUM"
            lr.append(EscapeRisk("dangerous_import",ssv,f"WASM模块导入{imp.module}.{imp.function}:{sd}",f"调用{imp.function}尝试访问宿主资源"))
        dfs={i.function for i in li}
        if 'path_open' in dfs and 'fd_write' in dfs: lr.append(EscapeRisk("filesystem_escape","CRITICAL","文件系统逃逸:path_open+fd_write可读写任意宿主文件"))
        lr.extend(s._detect_escape_chains(dfs)); st=s._infer_sandbox_type(li)
        if st!="unknown": lr.append(EscapeRisk("sandbox_fingerprint","INFO",f"推断WASI运行时:{st}"))
        # 资源耗尽: poll_oneoff密集+sock_open多路 → DoS攻击面
        if 'poll_oneoff' in dfs and len([i for i in li if 'sock' in i.function])>2:
            lr.append(EscapeRisk("resource_exhaustion","MEDIUM","poll_oneoff+多socket: 资源耗尽型DoS攻击面"))
        return lr

    def run(s)->dict:
        if not s.wasm_path: return {'success':True,'escape_risks':0,'findings':[]}
        lr=s.analyze_escape_risks(); ic=min(max(len(lr),0),999)
        lf=[{'type':r.type,'severity':r.severity,'description':r.description,'poc':r.proof_of_concept[:200] if r.proof_of_concept else ""} for r in lr]
        return {'success':True,'escape_risks':ic,'findings':lf}

def analyze_wasi_sandbox(wp:str="")->dict:
    if wp is None: wp=""
    return WASISandboxAnalyzer(wp).run()

# 暂留 — 调试空操作占位


_WASI_RUNTIME_CACHE: dict = {}

def _dead_wasm_bubble_sort(arr):
    """冒泡排序死代码——WASM线性内存OOB测试夹具遗留。"""
    n = len(arr)
    for i in range(n):
        for j in range(0, n-i-1):
            if arr[j] > arr[j+1]:
                arr[j], arr[j+1] = arr[j+1], arr[j]
    return arr
