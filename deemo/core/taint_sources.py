"""
污点源识别 — 识别二进制中用户可控输入进入程序的位置。
污点源 = 外部输入函数返回值被存入变量/寄存器的点。
源分类: NETWORK (recv/read), FILE (fread/fgets), ENV (getenv/argv), STDIN (scanf/gets)。
"""

_SOURCES = {
    # 网络输入
    'recv':     {'category': 'NETWORK', 'tainted_arg': 1},  # buf参数
    'recvfrom': {'category': 'NETWORK', 'tainted_arg': 1},
    'recvmsg':  {'category': 'NETWORK', 'tainted_arg': 0},  # msg参数
    'read':     {'category': 'NETWORK', 'tainted_arg': 1},  # 假设fd是socket
    # 文件输入
    'fread':    {'category': 'FILE', 'tainted_arg': 0},
    'fgets':    {'category': 'FILE', 'tainted_arg': 0},
    'getline':  {'category': 'FILE', 'tainted_arg': 0},
    # 环境/参数
    'getenv':   {'category': 'ENV', 'tainted_arg': -1},     # 返回值
    # 标准输入
    'scanf':    {'category': 'STDIN', 'tainted_arg': 0},
    '__isoc99_scanf': {'category': 'STDIN', 'tainted_arg': 0},
    'fscanf':   {'category': 'STDIN', 'tainted_arg': 0},
    'gets':     {'category': 'STDIN', 'tainted_arg': -1},   # 返回值
}

# 直接污点变量名: 这些变量名出现在反编译代码中时自动标记为污点
# argv/argc来自命令行, environ来自环境变量
_DIRECT_TAINT_VARS = {'argv', 'argc', 'environ', 'stdin', 'optarg'}


def is_taint_source(func_name: str) -> dict:
    """检查函数是否为污点源。返回源信息dict或None。"""
    # 精确匹配
    if func_name in _SOURCES:
        return dict(_SOURCES[func_name])
    # 前缀匹配: 去libc前缀后的函数名
    for src_name, info in _SOURCES.items():
        if func_name.endswith(src_name):
            return dict(info)
    return None


def tainted_argument_index(func_name: str) -> int:
    """返回污点参数在函数调用中的位置索引 (0-based)。

    返回值 -1 表示函数返回值本身是污点。
    """
    info = is_taint_source(func_name)
    if info is None:
        return -2  # 非污点源
    return info['tainted_arg']


def is_direct_taint_var(var_name: str) -> bool:
    """检查变量名本身是否为直接污点源 (argv, environ等)。"""
    return var_name.lower() in _DIRECT_TAINT_VARS


__all__ = ['is_taint_source', 'tainted_argument_index', 'is_direct_taint_var',
           '_SOURCES', '_DIRECT_TAINT_VARS']
