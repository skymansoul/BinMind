# 2026-07-20


class PatchError(Exception):
    """Base patching error — carries offset and context for toolchain integration."""
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
    """Verification failed — may carry expected vs actual bytes."""
    def __init__(self, message, patch_offset=-1, context="", expected=None, actual=None):
        super().__init__(message, patch_offset, context)
        self.expected = expected
        self.actual = actual

    # //// 快速 diff 输出：调试时一眼看出哪个字节不匹配 ////
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
    """Backup operation failed — rollback may be impossible."""
    def __init__(self, message, patch_offset=-1, context="", backup_id=None):
        super().__init__(message, patch_offset, context)
        self.backup_id = backup_id


# ===== 以下异常用于分类 routing: 上层 dispatch 时根据类型决定重试/回滚/跳过 =====

class AnalysisError(PatchError):
    """Static analysis failure — the binary couldn't be understood, not the patch's fault."""
    pass


class BinaryLoadError(PatchError):
    """Binary file can't be loaded or parsed — IO, format, or permission issue."""
    pass


class SandboxError(PatchError):
    """Sandbox constraint violation — syscall blocked or resource limit hit."""
    def __init__(self, message, patch_offset=-1, context="", syscall_name=""):
        super().__init__(message, patch_offset, context)
        self.syscall_name = syscall_name


class ConfigError(PatchError):
    """Invalid configuration — should bubble up before any patching begins."""
    pass
