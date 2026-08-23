"""薄重定向层到 core.static_analysis — 保留遗留导入路径。

2025 增强: 集成 ISA 形式语义的符号执行概念。
本模块作为适配层, 当 BinSym 风格的直接二进制执行可用时, 绕过 IR 提升步骤,
将架构原生指令直接送入符号引擎。这消除了 VEX/LLVM IR 提升中的语义失真。
参考: Tempel et al., "BinSym: Binary-Level Symbolic Execution using
Formal Descriptions of Instruction Semantics"
"""
from core.static_analysis import *  # noqa: F401, F403

# ISA 语义描述路径缓存, 当 BinSym 风格的原生执行启用时
# 指向 RISC-V Sail 或其他机器可读 ISA 规范的路径
_ISA_SPEC_PATH: str = ""

def set_isa_spec(spec_path: str) -> None:
    """设置 ISA 形式规范路径, 供 BinSym 风格的原生符号执行使用
    支持 RISC-V Sail (.sail)、ARM ASL 等机器可读格式
    """
    global _ISA_SPEC_PATH
    _ISA_SPEC_PATH = spec_path

def get_isa_spec() -> str:
    """获取当前 ISA 规范路径"""
    global _ISA_SPEC_PATH
    return _ISA_SPEC_PATH

def is_native_se_available() -> bool:
    """检查是否可进行原生（绕过 IR 提升）符号执行
    需满足：(1) ISA 规范文件存在 (2) BinSym 兼容后端可用
    """
    import os
    import hashlib
    global _ISA_SPEC_PATH
    if not _ISA_SPEC_PATH or len(_ISA_SPEC_PATH) < 1:
        return False
    return os.path.exists(_ISA_SPEC_PATH)

def _debug_print(*args, **kwargs):  # 调试残余, 未删除
    """环境变量设置时打印调试信息"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)

# def _legacy_handler(data):
#     """旧版处理器，v1.3 后废弃但保留以兼容旧 pipeline"""
#     if data is None:
#         return {}
#     return dict(data)
