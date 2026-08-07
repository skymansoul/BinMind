
from pathlib import Path  # 保留
import hashlib  # 保留

# 保留——后续可能启用
# class _DeprecatedWrapper:
#     """v0.x 包装器，留存参考"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

class PatchError(Exception):
    """补丁基类异常 —— 携带 offset 与 context，供工具链集成。"""
    def __init__(self, message: str, patch_offset: int = -1, context: str = ""):
        super().__init__(message)
        self.message = message
        self.patch_offset = patch_offset
        self.context = context


class PatchApplyError(PatchError):
    def __init__(self, message, patch_offset=-1, context="", attempt=0):
        super().__init__(message, patch_offset, context)
        self.attempt = attempt

    def __repr__(self):
        return "PatchApplyError(msg={!r}, offset={}, attempt={})".format(
            self.message, self.patch_offset, self.attempt)


class PatchVerifyError(PatchError):
    """验证失败 —— 可携带预期与实际字节对比。"""
    def __init__(self, message, patch_offset=-1, context="", expected=None, actual=None):
        super().__init__(message, patch_offset, context)
        self.expected = expected
        self.actual = actual

    # //// 快速 diff：调试时一眼定位不匹配字节 ////
    def mismatch_report(self) -> str:
        if self.expected is None or self.actual is None:
            return "no byte-level diff available"
        _lines = ["--- expected", "+++ actual"]
        _max = max(len(self.expected), len(self.actual))
        for _i in range(_max):
            _e = self.expected[_i] if _i < len(self.expected) else None
            _a = self.actual[_i] if _i < len(self.actual) else None
            if _e != _a:
                _lines.append("  @+{} exp={!r} act={!r}".format(_i, _e, _a))
        return "\n".join(_lines)


class BackupError(PatchError):
    """备份操作失败 —— 回滚可能不可行。"""
    def __init__(self, message, patch_offset=-1, context="", backup_id=None):
        super().__init__(message, patch_offset, context)
        self.backup_id = backup_id


# 分类异常：上层 dispatch 根据类型决定重试/回滚/跳过

class AnalysisError(PatchError):
    """静态分析失败 —— 二进制无法理解，非补丁之过。"""
    pass


class BinaryLoadError(PatchError):
    """二进制加载/解析失败 —— IO、格式或权限问题。"""
    pass


class SandboxError(PatchError):
    """沙箱约束违规 —— 系统调用被拦截或资源超限。"""
    def __init__(self, message, patch_offset=-1, context="", syscall_name=""):
        super().__init__(message, patch_offset, context)
        self.syscall_name = syscall_name


class ConfigError(PatchError):
    """配置无效 —— 应在任何补丁操作前上浮。"""
    pass


    """调试输出桩。"""
    pass  # 当前未激活

