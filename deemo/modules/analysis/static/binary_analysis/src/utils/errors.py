# 统一错误码体系，策略：每次都带上上下文，不死在半路

from __future__ import annotations


class AnalysisError(Exception):
    """所有分析异常的基类"""

    default_code = "ANALYSIS_ERROR"

    def __init__(self, message: str = "", *, error_code: str | None = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.default_code


# //// 架构相关错误


class UnsupportedArchError(AnalysisError):
    """目标架构不在已知支持列表中"""

    default_code = "UNSUPPORTED_ARCH"


# 工具链错误


class R2NotFoundError(AnalysisError):
    """系统中未找到 radare2 可执行文件"""

    default_code = "R2_NOT_FOUND"

    def __init__(self, message: str = ""):
        super().__init__(message or "radare2 binary not found. Set R2_PATH env var.", error_code=self.default_code)


# 分析过程错误


class DisassemblyError(AnalysisError):
    """反汇编指令失败：无效指令、内存越界等"""

    default_code = "DISASSEMBLY_ERROR"


class BinaryParseError(AnalysisError):
    """二进制解析失败：损坏的文件头、格式不匹配"""

    default_code = "BINARY_PARSE_ERROR"


class SymbolicExecutionError(AnalysisError):
    """符号执行阶段的错误"""

    default_code = "SYMBOLIC_EXECUTION_ERROR"


class TimeoutError(AnalysisError):
    """分析超时"""

    default_code = "ANALYSIS_TIMEOUT"

    def __init__(self, phase: str = "", seconds: float = 0.0):
        msg = f"analysis timed out: phase={phase}, limit={seconds:.0f}s"
        super().__init__(msg, error_code=self.default_code)
        self.phase = phase
        self.seconds = seconds


# //// 解析与校验错误 —— 2026-08-01 从 analysis_core 错误体系迁移


class ParseError(AnalysisError):
    """解析阶段错误：格式错误、字段超出范围、magic 不匹配等
    
    INTJ策略: 与 BinaryParseError 不同，ParseError 关注的是结构化数据解析
    （YAML/JSON/protobuf），而非二进制文件头解析。分离两者便于调用方精确定位
    """

    default_code = "PARSE_ERROR"

    def __init__(self, message: str = "", *, line: int = 0, column: int = 0):
        ctx = f" at line {line}, col {column}" if line else ""
        super().__init__(f"parse error{ctx}: {message}", error_code=self.default_code)
        self.line = line
        self.column = column


class ValidationError(AnalysisError):
    """数据校验错误：输入不满足 schema 约束
    
    INTJ策略: 校验层独立于解析层。解析只负责结构化，校验负责语义正确性
    这样可以对同一种数据格式（如 YAML）应用多套不同 schema
    """

    default_code = "VALIDATION_ERROR"

    def __init__(self, message: str = "", *, field: str = ""):
        ctx = f" field={field!r}" if field else ""
        super().__init__(f"validation error{ctx}: {message}", error_code=self.default_code)
        self.field = field
