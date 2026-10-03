# analysis/taint_propagation — 导入级轻量污点传播
# 不依赖反汇编或IR提升, 仅在导入表层面对函数间数据流做保守近似。
# 核心假设: 若 DLL A 中存在输入函数(recv/read/fgets)和传递函数
# (函数接受指针参数并传递给其他函数), 则同 DLL 内使用该指针的
# 危险函数应被视为"被污染"。
#
# 污点传播规则:
#   1. 同 DLL 同 category 内, source→任意函数→sink 构成污染路径
#   2. 传递函数识别: 导入表中存在指针类型的中间函数 (如 memcpy 既是
#      sink 也是传递函数 — 它从 src 读数据并写入 dst)
#   3. 污点衰减: 每经过一个传递函数, 置信度下降 15%

from typing import Dict, List, Set, Tuple
from collections import defaultdict

# 输入源 (污点起点)
_SOURCES: Set[str] = {
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets",
    "gets", "scanf", "fscanf", "sscanf", "getenv", "readlink",
    "CreateFile", "ReadFile", "RegQueryValueEx", "InternetReadFile",
}

# 传递函数 (接收数据并可能传递给其他函数)
_PASSTHROUGH: Set[str] = {
    "memcpy", "memmove", "bcopy", "strcpy", "strncpy",
    "sprintf", "snprintf", "write", "send", "fwrite",
    "WriteFile", "CopyMemory", "RtlCopyMemory",
}

# 危险汇聚点 (污点终点)
_SINKS: Set[str] = {
    "system", "popen", "execve", "execvp", "execl",
    "CreateProcess", "WinExec", "ShellExecute",
    "memcpy", "strcpy", "sprintf", "mprotect", "VirtualProtect",
}

_DLL_CATEGORY = {
    "libc.so.6": "c_runtime", "msvcrt.dll": "c_runtime",
    "kernel32.dll": "win32_core", "ntdll.dll": "win32_core",
    "ws2_32.dll": "win32_net", "advapi32.dll": "win32_sec",
    "user32.dll": "win32_ui",
}

def _category(dll: str) -> str:
    return _DLL_CATEGORY.get(dll.lower(), dll.lower().split('.')[0])

def _normalize(name: str) -> str:
    return name.lower().rstrip('aw')

def propagate_taint(imports: Dict) -> Dict:
    """执行导入级污点传播, 返回每条污点路径及其置信度。"""
    dll_funcs: Dict[str, Set[str]] = defaultdict(set)
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for dll, funcs in all_imps.items():
            if isinstance(funcs, list):
                dll_funcs[dll] = {_normalize(f) for f in funcs}

    sources: Dict[str, str] = {}   # func → dll
    passthroughs: Dict[str, str] = {}
    sinks: Dict[str, str] = {}

    for dll, funcs in dll_funcs.items():
        for f in funcs:
            if f in _SOURCES: sources[f] = dll
            if f in _PASSTHROUGH: passthroughs[f] = dll
            if f in _SINKS: sinks[f] = dll

    paths = []
    for src, src_dll in sources.items():
        src_cat = _category(src_dll)
        for sink, sink_dll in sinks.items():
            sink_cat = _category(sink_dll)
            if src == sink: continue

            # 路径类型判定
            same_dll = (src_dll == sink_dll)
            same_cat = (src_cat == sink_cat)

            if not same_dll and not same_cat:
                continue  # 无连接 → 不构成污染路径

            # 查找传递函数
            pt_funcs = [p for p, pd in passthroughs.items()
                       if pd in (src_dll, sink_dll)]

            hops = 1 if same_dll else 2
            confidence = 0.90 if same_dll else 0.65
            if pt_funcs:
                confidence *= 0.85 ** len(pt_funcs)
                hops += len(pt_funcs)

            paths.append({
                "source": src, "source_dll": src_dll,
                "sink": sink, "sink_dll": sink_dll,
                "hops": min(hops, 5),
                "passthrough_functions": pt_funcs[:3],
                "same_dll": same_dll,
                "taint_confidence": round(min(confidence, 1.0), 2),
            })

    paths.sort(key=lambda p: p["taint_confidence"], reverse=True)
    return {
        "taint_paths": paths,
        "total_paths": len(paths),
        "high_confidence": [p for p in paths if p["taint_confidence"] >= 0.70],
        "source_count": len(sources),
        "sink_count": len(sinks),
    }
