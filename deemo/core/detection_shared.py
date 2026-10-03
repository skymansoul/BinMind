"""检测引擎共享数据结构: TaintPath, CFGBlock, TaintSource, TaintSink。
供 taint_tracker/cfg_path_filter/asm_detector 使用的公共类型定义, 独立成模块以避免循环导入。"""


from dataclasses import dataclass, field


@dataclass
class TaintSource:
    """污点源: 用户/外部输入的入口点。"""
    kind: str             # 'read' | 'recv' | 'fgets' | 'scanf' | 'gets' | 'argv' | 'env'
    var_name: str         # variable/register receiving input
    func_name: str        # enclosing function
    address: int = 0      # instruction address (assembly) or 0 (decompiled)
    lineno: int = 0


@dataclass
class TaintSink:
    """污点汇: 消费污点数据的危险操作。"""
    kind: str             # 'strcpy' | 'sprintf' | 'printf' | 'system' | 'memcpy' | 'free'
    var_name: str         # tainted variable
    func_name: str
    address: int = 0
    lineno: int = 0


@dataclass
class TaintPath:
    """污点传播路径: 从源到汇。"""
    source: TaintSource
    sink: TaintSink
    hops: list[str]       # intermediate variable/register names in path
    confidence: float     # 0.0-1.0 path confidence
    verified: bool = False


@dataclass
class CFGBlock:
    """控制流图中的基本块节点。"""
    start_addr: int
    end_addr: int
    instructions: list[str] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)  # 后继块地址


@dataclass
class AsmCall:
    """汇编级函数调用记录。"""
    address: int
    mnemonic: str       # call / jmp
    target: str          # 目标函数名或地址
    args: list[str]      # 调用前各寄存器的值（从反汇编推断）


# 统一危险函数元数据表。
# tuple: (vuln_type, severity, cwe, confidence)
DANGEROUS_FUNCTIONS = {
    # 无界/高风险栈与缓冲区写入
    'gets': ('buffer-overflow', 'Critical', 'CWE-242', 0.95),
    '_gets': ('buffer-overflow', 'Critical', 'CWE-242', 0.95),
    'strcpy': ('buffer-overflow', 'High', 'CWE-120', 0.85),
    'stpcpy': ('buffer-overflow', 'High', 'CWE-120', 0.80),
    'strcat': ('buffer-overflow', 'High', 'CWE-120', 0.85),
    'sprintf': ('buffer-overflow', 'High', 'CWE-120', 0.80),
    'vsprintf': ('buffer-overflow', 'High', 'CWE-120', 0.80),
    'scanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.65),
    '__isoc99_scanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.65),
    'sscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.65),
    '__isoc99_sscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.65),
    'fscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.65),
    '__isoc99_fscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.65),
    'vscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.60),
    'vsscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.60),
    'vfscanf': ('buffer-overflow', 'Medium', 'CWE-120', 0.60),
    'memcpy': ('buffer-overflow', 'Medium', 'CWE-119', 0.60),
    'memmove': ('buffer-overflow', 'Medium', 'CWE-119', 0.55),
    'memset': ('buffer-overflow', 'Low', 'CWE-119', 0.40),
    'read': ('buffer-overflow', 'Medium', 'CWE-119', 0.60),
    'recv': ('buffer-overflow', 'Medium', 'CWE-119', 0.60),
    'recvfrom': ('buffer-overflow', 'Medium', 'CWE-119', 0.55),
    'recvmsg': ('buffer-overflow', 'Medium', 'CWE-119', 0.55),
    'fread': ('buffer-overflow', 'Medium', 'CWE-119', 0.55),
    'strncpy': ('buffer-overflow', 'Low', 'CWE-120', 0.40),
    'strncat': ('buffer-overflow', 'Low', 'CWE-120', 0.40),
    'snprintf': ('buffer-overflow', 'Low', 'CWE-120', 0.35),
    'vsnprintf': ('buffer-overflow', 'Low', 'CWE-120', 0.35),

    # 格式化字符串
    'printf': ('format-string', 'Medium', 'CWE-134', 0.55),
    'fprintf': ('format-string', 'Medium', 'CWE-134', 0.55),
    'dprintf': ('format-string', 'Medium', 'CWE-134', 0.55),
    'vprintf': ('format-string', 'Medium', 'CWE-134', 0.55),
    'vfprintf': ('format-string', 'Medium', 'CWE-134', 0.55),
    'vdprintf': ('format-string', 'Medium', 'CWE-134', 0.55),
    'syslog': ('format-string', 'Medium', 'CWE-134', 0.55),
    'err': ('format-string', 'Medium', 'CWE-134', 0.50),
    'errx': ('format-string', 'Medium', 'CWE-134', 0.50),
    'warn': ('format-string', 'Medium', 'CWE-134', 0.50),
    'warnx': ('format-string', 'Medium', 'CWE-134', 0.50),

    # 命令执行/进程执行
    'system': ('command-injection', 'Critical', 'CWE-78', 0.85),
    'popen': ('command-injection', 'Critical', 'CWE-78', 0.85),
    'execve': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'execl': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'execle': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'execlp': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'execv': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'execvp': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'execvpe': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'WinExec': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'ShellExecuteA': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'ShellExecuteW': ('command-injection', 'Critical', 'CWE-78', 0.80),
    'CreateProcessA': ('command-injection', 'High', 'CWE-78', 0.70),
    'CreateProcessW': ('command-injection', 'High', 'CWE-78', 0.70),

    # 动态代码加载/内存权限
    'mprotect': ('memory-manipulation', 'High', 'CWE-119', 0.65),
    'mmap': ('memory-manipulation', 'Medium', 'CWE-119', 0.50),
    'VirtualAlloc': ('memory-manipulation', 'High', 'CWE-119', 0.65),
    'VirtualProtect': ('memory-manipulation', 'High', 'CWE-119', 0.65),
    'dlopen': ('dynamic-load', 'Medium', 'CWE-829', 0.50),
    'dlsym': ('dynamic-load', 'Medium', 'CWE-829', 0.45),
    'LoadLibraryA': ('dynamic-load', 'Medium', 'CWE-829', 0.50),
    'LoadLibraryW': ('dynamic-load', 'Medium', 'CWE-829', 0.50),
    'GetProcAddress': ('dynamic-load', 'Medium', 'CWE-829', 0.45),

    # 堆/生命周期风险
    'malloc': ('heap-corruption', 'Low', 'CWE-190', 0.35),
    'calloc': ('heap-corruption', 'Low', 'CWE-190', 0.35),
    'realloc': ('heap-corruption', 'Low', 'CWE-190', 0.35),
    'free': ('heap-corruption', 'Low', 'CWE-416', 0.35),
    'strdup': ('heap-corruption', 'Low', 'CWE-401', 0.30),

    # 文件破坏/权限/竞态
    'unlink': ('file-operation', 'Medium', 'CWE-73', 0.45),
    'remove': ('file-operation', 'Medium', 'CWE-73', 0.45),
    'rename': ('file-operation', 'Low', 'CWE-73', 0.35),
    'chmod': ('privilege-escalation', 'Medium', 'CWE-732', 0.45),
    'chown': ('privilege-escalation', 'Medium', 'CWE-732', 0.45),
    'setuid': ('privilege-escalation', 'High', 'CWE-250', 0.65),
    'setgid': ('privilege-escalation', 'High', 'CWE-250', 0.65),
    'fork': ('race-condition', 'Low', 'CWE-362', 0.30),

    # 信息泄露/泄露辅助
    'puts': ('info-leak', 'Medium', 'CWE-200', 0.45),
    'write': ('info-leak', 'Medium', 'CWE-200', 0.45),
    'send': ('info-leak', 'Low', 'CWE-200', 0.35),
}

DANGEROUS_IMPORTS = frozenset(DANGEROUS_FUNCTIONS)


def normalize_import_name(func_name: str) -> str:
    """归一化导入符号名: 去掉 PLT 前缀、版本后缀和常见装饰。"""
    if not func_name:
        return ''
    name = str(func_name).strip()
    for prefix in ('sym.imp.', 'imp.', 'sym.'):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.rsplit('.', 1)[-1]
    name = name.split('@', 1)[0]
    if name.startswith('__imp_'):
        name = name[6:]
    return name


def get_dangerous_function_meta(func_name: str):
    """返回危险函数元数据 tuple, 未命中返回 None。"""
    name = normalize_import_name(func_name)
    return DANGEROUS_FUNCTIONS.get(name)


# 参数可能携带用户输入的危险汇函数
_SINK_FUNCTIONS = {
    name for name, meta in DANGEROUS_FUNCTIONS.items()
    if meta[0] in ('buffer-overflow', 'format-string', 'command-injection')
}

# 返回值或输出缓冲区携带外部输入的源函数
_SOURCE_FUNCTIONS = {
    'read', 'recv', 'recvfrom', 'recvmsg', 'fgets', 'gets',
    'scanf', '__isoc99_scanf', 'sscanf', '__isoc99_sscanf',
    'fscanf', '__isoc99_fscanf', 'getline', 'getenv', 'fread',
}


def is_source(func_name: str) -> bool:
    return normalize_import_name(func_name) in _SOURCE_FUNCTIONS


def is_sink(func_name: str) -> bool:
    return normalize_import_name(func_name) in _SINK_FUNCTIONS
