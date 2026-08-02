# 2026-07-17 -- 分析异常层级
# 统一错误码体系，策略：每次都带上上下文，不死在半路

from __future__ import annotations


class AnalysisError(Exception):
    """所有分析异常的基类。"""

    default_code = "ANALYSIS_ERROR"

    def __init__(self, message: str = "", *, error_code: str | None = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.default_code


# //// 架构相关错误


class UnsupportedArchError(AnalysisError):
    """目标架构不在已知支持列表中。"""

    default_code = "UNSUPPORTED_ARCH"


# ---- 工具链错误


class R2NotFoundError(AnalysisError):
    """系统中未找到 radare2 可执行文件。"""

    default_code = "R2_NOT_FOUND"

    def __init__(self, message: str = ""):
        super().__init__(message or "radare2 binary not found. Set R2_PATH env var.", error_code=self.default_code)


# ===== 分析过程错误 =====


class DisassemblyError(AnalysisError):
    """反汇编指令失败：无效指令、内存越界等。"""

    default_code = "DISASSEMBLY_ERROR"


class BinaryParseError(AnalysisError):
    """二进制解析失败：损坏的文件头、格式不匹配。"""

    default_code = "BINARY_PARSE_ERROR"


class SymbolicExecutionError(AnalysisError):
    """符号执行阶段的错误。"""

    default_code = "SYMBOLIC_EXECUTION_ERROR"


class TimeoutError(AnalysisError):
    """分析超时。"""

    default_code = "ANALYSIS_TIMEOUT"

    def __init__(self, phase: str = "", seconds: float = 0.0):
        msg = f"analysis timed out: phase={phase}, limit={seconds:.0f}s"
        super().__init__(msg, error_code=self.default_code)
        self.phase = phase
        self.seconds = seconds
