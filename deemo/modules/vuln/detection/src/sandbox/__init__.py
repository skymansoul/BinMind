# sandbox子包——沙箱逃逸检测/seccomp策略构造/漏洞验证

from deemo.modules.vuln.detection.src.sandbox.escape_detector import (
    SandboxEscapeDetector, EscapeAttempt, escape_check,
)
try:
    from deemo.modules.vuln.detection.src.sandbox.policy_gen import (
        SeccompPolicyGenerator, SeccompPolicy, SyscallAction,
        generate_seccomp_policy,
    )
except ImportError:
    # policy_gen 模块已移除; 缺失时降级为 None
    SeccompPolicyGenerator = None
    SeccompPolicy = None
    SyscallAction = None
    generate_seccomp_policy = None
from deemo.modules.vuln_detection.vuln_verification_sandbox import (
    VulnVerificationSandbox, VerificationResult,
)

__all__ = [
    "SandboxEscapeDetector", "EscapeAttempt", "escape_check",
    "SeccompPolicyGenerator", "SeccompPolicy", "SyscallAction",
    "generate_seccomp_policy",
    "VulnVerificationSandbox", "VerificationResult",
]
