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


# 参数可能携带用户输入的危险汇函数
_SINK_FUNCTIONS = {
    'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'memcpy', 'memmove', 'system', 'popen',
    'printf', 'fprintf', 'dprintf', 'syslog',
    'err', 'errx', 'warn', 'warnx',
}

# 返回值或输出缓冲区携带外部输入的源函数
_SOURCE_FUNCTIONS = {
    'read', 'recv', 'recvfrom', 'fgets', 'gets',
    'scanf', 'fscanf', 'getline', 'getenv',
}


def is_source(func_name: str) -> bool:
    return func_name in _SOURCE_FUNCTIONS


def is_sink(func_name: str) -> bool:
    return func_name in _SINK_FUNCTIONS
