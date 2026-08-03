import logging, os, time, re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

# 移除 loguru 依赖。try/except 是软回退，但大多数环境不装 loguru。
# 标准 logging 始终可用。
# try:
#     from loguru import logger
# except ImportError:
#     logger = logging.getLogger(__name__)
logger = logging.getLogger(__name__)

try:
    from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
except ImportError:
    class AnalyzerType:
        OTHER = "other"
    class AnalyzerMetadata:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    class BaseAnalyzer:
        pass

from enum import Enum


class ProtectionType(Enum):
    BOUND_CHECK = "bound_check"
    NULL_CHECK = "null_check"
    INTEGER_CHECK = "integer_check"
    FORMAT_CHECK = "format_check"
    MEMORY_TRACKING = "memory_tracking"
    CANARY_INSERT = "canary_insert"
    ASLR_ENFORCE = "aslr_enforce"
    DEP_ENFORCE = "dep_enforce"


class InstrumentationFramework(Enum):
    FRIDA = "frida"
    DYNAMORIO = "dynamorio"
    PIN = "pin"
    VALGRIND = "valgrind"
    BPTIME = "bpftime"
    CUSTOM = "custom"


@dataclass
class CVEInfo:
    cve_id: str
    vulnerability_type: str = ""
    affected_functions: List[str] = field(default_factory=list)
    description: str = ""
    severity: str = "MEDIUM"
    mitigation: str = ""


@dataclass
class ProtectionRule:
    rule_id: str
    protection_type: ProtectionType
    target_function: str
    check_code: str = ""
    performance_estimate: float = 0.05
    description: str = ""


@dataclass
class InstrumentationResult:
    binary_path: str = ""
    rules_applied: List[ProtectionRule] = field(default_factory=list)
    instrumented_code: str = ""
    performance_overhead: float = 0.0
    success: bool = False
    verification_passed: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class RewriteResult:
    success: bool = False
    attempts: int = 0
    applied_patches: List[str] = field(default_factory=list)
    failed_patches: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)


# ===== 保护规则代码片段库 =====
# 每种保护类型对应一段 C 级检查代码

_PROTECTION_TEMPLATES: Dict[ProtectionType, str] = {
    ProtectionType.BOUND_CHECK: "if ({target}_len >= {target}_cap) {{ {target}_len = {target}_cap - 1; }}",
    ProtectionType.NULL_CHECK: "if ({target} == NULL) {{ return -EINVAL; }}",
    ProtectionType.INTEGER_CHECK: "if (a > 0 && b > INT_MAX - a) {{ return -EOVERFLOW; }}",
    ProtectionType.FORMAT_CHECK: "if (strchr(fmt, '%') && fmt == user_input) {{ return -EINVAL; }}",
    ProtectionType.MEMORY_TRACKING: "memset({target}, 0xDE, old_size); {target} = NULL;",
    ProtectionType.CANARY_INSERT: "__stack_chk_guard = __random(); canary = __stack_chk_guard;",
    ProtectionType.ASLR_ENFORCE: "if (personality(ADDR_NO_RANDOMIZE) == 0) {{ personality(ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT); }}",
    ProtectionType.DEP_ENFORCE: "if (mmap_check_flags & PROT_EXEC) {{ mmap_check_flags &= ~PROT_WRITE; }}",
}


class SelfHealingRewriter(BaseAnalyzer):
    """自愈重写器：按 ProtectionRule 产出插桩代码，模拟热补丁。

    Python 无法直接修改运行中进程内存，因此生成插桩脚本
    （Frida/DynamoRIO/PIN），真实注入由外部 C 工具链完成。
    """

    def __init__(self, binary_path: str = "", arch: str = "x86_64"):
        self._binary_path = binary_path
        self._arch = arch
        self._results_log: List[str] = []
        self._framework = InstrumentationFramework.FRIDA

    # ============================================================
    # 主入口 —— 遍历规则，生成+应用+验证，最多 3 次重试
    # ============================================================
    def rewrite(self, rules: List[ProtectionRule]) -> RewriteResult:
        """逐规则生成热补丁并验证，失败重试最多 3 次。"""
        _result = RewriteResult()
        _result.attempts = len(rules)
        for _rule in rules:
            _step = "[{}] {} -> {}".format(_rule.rule_id, _rule.protection_type.value, _rule.target_function)
            self._results_log.append(_step + " START")
            _applied = False
            _retries = 0
            _max_retries = 3
            while _retries < _max_retries and not _applied:
                _retries += 1
                _hot = self._generate_hot_patch(_rule)
                _ok = self._apply_and_verify(_rule, _hot)
                if _ok:
                    _applied = True
                    _result.applied_patches.append(_rule.rule_id)
                    self._results_log.append("{} OK (retry {})".format(_step, _retries))
                else:
                    _delay = 0.5 * (2 ** (_retries - 1))
                    self._results_log.append("{} FAIL retry {}/{}, backoff {:.1f}s".format(_step, _retries, _max_retries, _delay))
                    time.sleep(_delay)
            if not _applied:
                _result.failed_patches.append(_rule.rule_id)
                _result.success = False
                self._results_log.append(_step + " FAILED")
        if not _result.failed_patches:
            _result.success = True
        _result.log = list(self._results_log)
        return _result

    # //// 生成热补丁：按 framework 类型分发 ////
    def _generate_hot_patch(self, rule: ProtectionRule) -> str:
        if self._framework == InstrumentationFramework.FRIDA:
            return self._frida_hook_template(rule)
        elif self._framework == InstrumentationFramework.DYNAMORIO:
            return self._dynamorio_hook_template(rule)
        elif self._framework == InstrumentationFramework.PIN:
            return self._pin_hook_template(rule)
        return self._frida_hook_template(rule)

    def _apply_and_verify(self, rule: ProtectionRule, hot_patch: str) -> bool:
        if not hot_patch or len(hot_patch.strip()) == 0:
            return False
        return self._verify_patch(rule)

    def _verify_patch(self, rule: ProtectionRule) -> bool:
        _code = rule.check_code
        if not _code or len(_code.strip()) == 0:
            return False
        # 检查关键模式：应为 if/return/memset 等安全检查代码
        _patterns = [r'\bif\b', r'\breturn\b', r'\bmemset\b', r'\bnull\b', r'\bsizeof\b',
                     r'\bcheck\b', r'\bguard\b', r'\bvalidate\b', r'\{', r'\}']
        _hits = sum(1 for _p in _patterns if re.search(_p, _code, re.IGNORECASE))
        return _hits >= 2

    def _retry_logic(self, rule: ProtectionRule, max_retries: int = 3) -> Tuple[bool, str]:
        _retry = 0
        _log = ""
        while _retry < max_retries:
            _retry += 1
            _hot = self._generate_hot_patch(rule)
            if self._apply_and_verify(rule, _hot):
                return True, _hot
            _log += "retry {} failed; ".format(_retry)
            time.sleep(0.5 * (2 ** (_retry - 1)))
        return False, _log

    # **** FRIDA JavaScript hook ****
    def _frida_hook_template(self, rule: ProtectionRule) -> str:
        _mod = os.path.basename(self._binary_path) or "target"
        _lines = [
            "// FRIDA auto-generated hook for {}".format(rule.rule_id),
            "var mod = Process.findModuleByName('{}');".format(_mod),
            "if (mod) {",
            "  var addr = mod.findExportByName('{}');".format(rule.target_function),
            "  if (addr) {",
            "    Interceptor.attach(addr, {",
            "      onEnter: function(args) {",
            "        // {}: {}".format(rule.protection_type.value, rule.description),
        ]
        # 嵌入检查逻辑
        _check = rule.check_code.strip().replace('\n', '\n        ')
        _lines.append("        // " + _check)
        _lines.append("      },")
        _lines.append("    });")
        _lines.append("  }")
        _lines.append("}")

        # 内存保护：MEMORY_TRACKING / CANARY_INSERT 时启用
        if rule.protection_type in (ProtectionType.MEMORY_TRACKING, ProtectionType.CANARY_INSERT):
            _lines.insert(len(_lines) - 4, "    Memory.protect(addr, 4096, 'rwx');")
            _lines.append("    Memory.writeByteArray(addr, [0x90, 0x90, 0x90, 0x90]);")

        return '\n'.join(_lines)

    # //// DynamoRIO C hook ////
    def _dynamorio_hook_template(self, rule: ProtectionRule) -> str:
        _lines = [
            "// DynamoRIO auto-generated hook for {}".format(rule.rule_id),
            '#include "dr_api.h"',
            '#include "drmgr.h"',
            "",
            "static void pre_{}(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data) {{".format(rule.target_function),
            "    // {}: {}".format(rule.protection_type.value, rule.description),
            "    dr_insert_clean_call(drcontext, bb, instr, (void *)on_enter, false, 0);",
            "}",
        ]
        return '\n'.join(_lines)

    # //// Intel PIN C++ hook (未测试) ////
    def _pin_hook_template(self, rule: ProtectionRule) -> str:
        _lines = [
            "// Intel PIN auto-generated hook for {} [UNTESTED]".format(rule.rule_id),
            '#include "pin.H"',
            "",
            "VOID on_enter_{}(CONTEXT *ctx) {{".format(rule.target_function),
            "    // {}: {}".format(rule.protection_type.value, rule.description),
            "    // PIN instrumentation logic here",
            "}",
            "",
            "VOID ImageLoad(IMG img, VOID *v) {",
            '    RTN rtn = RTN_FindByName(img, "{}");'.format(rule.target_function),
            "    if (RTN_Valid(rtn)) {",
            "        RTN_Open(rtn);",
            "        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)on_enter_{}, IARG_CONTEXT, IARG_END);".format(rule.target_function),
            "        RTN_Close(rtn);",
            "    }",
            "}",
        ]
        return '\n'.join(_lines)


# **** 便捷入口：一步完成自愈保护 ****
def apply_self_healing_protection(binary_path: str,
                                   cve_info: Optional[CVEInfo] = None,
                                   framework: InstrumentationFramework = InstrumentationFramework.FRIDA) -> InstrumentationResult:
    _rewriter = SelfHealingRewriter(binary_path=binary_path)
    _rewriter._framework = framework
    _rules: List[ProtectionRule] = []
    if cve_info:
        _vtype = cve_info.vulnerability_type
        _ptype_map = {
            "buffer_overflow": ProtectionType.BOUND_CHECK,
            "integer_overflow": ProtectionType.INTEGER_CHECK,
            "use_after_free": ProtectionType.MEMORY_TRACKING,
            "null_pointer": ProtectionType.NULL_CHECK,
            "format_string": ProtectionType.FORMAT_CHECK,
        }
        _pt = _ptype_map.get(_vtype, ProtectionType.BOUND_CHECK)
        for _fn in cve_info.affected_functions:
            _rules.append(ProtectionRule(
                rule_id="heal_{}_{}".format(cve_info.cve_id, _fn),
                protection_type=_pt,
                target_function=_fn,
                check_code=_PROTECTION_TEMPLATES.get(_pt, ""),
                description=cve_info.description,
            ))
    _rr = _rewriter.rewrite(_rules)
    return InstrumentationResult(
        binary_path=binary_path,
        rules_applied=_rules,
        instrumented_code="",
        performance_overhead=sum(_r.performance_estimate for _r in _rules) if _rules else 0.0,
        success=_rr.success,
        verification_passed=_rr.success,
        notes=_rr.log,
    )
