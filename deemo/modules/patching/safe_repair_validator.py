"""
安全修复验证器

多轮修复闭环中的验证组件，对应 Agentic Program Repair from
Test Failures at Scale [arXiv:2507.18755] 的 test-execution 反馈环节。
以静态测试预言机替代真实执行，绝不运行被测漏洞程序。

安全边界：
  - 仅语法 / 编译(-fsyntax-only) / 静态模式 三种检查；
  - gcc 仅 -fsyntax-only，不链接不运行；产物写入临时文件并在 finally 清理；
  - lang='python' 用内置 compile() 语法检查，同样不执行；
  - 反编译片段缺上下文导致的编译错误降级为 WARNING，避免误杀。

反馈信号：[tag] 标签输出机器可读反馈，同时附可读文本。
负向规则命中（残留危险模式）→ FAIL；
必需正向模式缺失 → WARNING；全部通过 → PASS。
"""
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationStatus(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    SKIPPED = "skipped"


@dataclass
class CheckResult:
    """单项检查结果。"""
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ValidationResult:
    """候选补丁验证聚合结果。safe 恒 True —— 不执行程序。"""
    status: ValidationStatus = ValidationStatus.SKIPPED
    checks: list = field(default_factory=list)
    feedback: str = ""
    error_lines: list = field(default_factory=list)
    compile_status: str = ""
    safe: bool = True

    def to_dict(self):
        return {
            'status': self.status.value,
            'checks': [{'name': c.name, 'passed': c.passed, 'detail': c.detail}
                       for c in self.checks],
            'feedback': self.feedback,
            'error_lines': self.error_lines,
            'compile_status': self.compile_status,
            'safe': self.safe,
        }


# 负向静态规则 —— 命中=残留/引入危险模式（硬失败）
_NEGATIVE_RULES = [
    ('dangerous_copy', r'\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(', '残留危险拷贝/格式化调用'),
    ('dangerous_exec', r'\b(system|popen|execl|execv)\s*\(', '残留命令执行调用'),
    ('unchecked_alloc', r'\bmalloc\s*\([^)]*\)\s*;', 'malloc 返回值未校验'),
    ('free_no_null', r'\bfree\s*\(\s*(\w+)\s*\)\s*;', 'free 后未置空指针'),
]

# 正向静态规则 —— 命中=引入了对应安全模式
_POSITIVE_RULES = {
    'safe_copy': r'\b(strncpy|strlcpy|snprintf|vsnprintf|strcpy_s|sprintf_s)\s*\(',
    'bounds_guard': r'if\s*\([^\n]*[<>]=?',
    'null_guard': r'(==\s*NULL|!=\s*NULL|==\s*0\s*[);])',
    'overflow_guard': r'(__builtin_(add|sub|mul)_overflow|INT_MAX|SIZE_MAX)',
    'format_literal': r'printf\s*\(\s*"[^"]*%s[^"]*"\s*,',
    'resource_release': r'\bfree\s*\(',
}

# 编译"上下文噪音"特征 —— 反编译片段缺头/类型声明的典型错误
_CONTEXT_NOISE = re.compile(
    r'undeclared|unknown type name|implicit declaration|'
    r'return[^\n]*with a value|void value not ignored|'
    r'expected.*before|type specifier missing', re.I
)


class SafeRepairValidator:
    """安全验证器 —— 仅语法/编译/静态检查，不执行被测程序。"""

    def __init__(self, compiler_path="gcc", allow_exec=False, timeout=30):
        self._compiler = compiler_path
        self._allow_exec = allow_exec
        self._timeout = timeout
        self._compiler_ok = False
        self._check_compiler()
        if allow_exec:
            # 安全约束：禁止执行被测漏洞程序，
            # 调用方显式开启也仅记录警告，验证仍走静态预言机
            logger.warning("allow_exec=True requested but target execution is "
                           "forbidden by design; falling back to static oracles")

    # -- public ---------------------------------------------------------

    def validate(self, patch_diff="", code="", lang="c", required_positive=None):
        """验证候选补丁。

        patch_diff: unified diff（提取新增行做静态 delta 检查）
        code: 修复后完整代码（语法/编译检查）
        required_positive: 必须命中的正向安全模式列表（路由族推导）
        """
        checks = []
        feedback_tags = []
        feedback_msgs = []
        hard = False

        if code and code.strip():
            cr, ch = self._syntax_check(code, lang)
            checks.append(cr)
            hard = hard or ch
            cr, ch = self._compile_check(code, lang)
            checks.append(cr)
            hard = hard or ch
            # 编译上下文噪音降级 WARNING
            if (not cr.passed and cr.name == 'compile'
                    and 'context noise' in cr.detail):
                feedback_tags.append('compile_context')
                feedback_msgs.append('反编译片段缺上下文，编译噪音不视为缺陷')
        else:
            checks.append(CheckResult('syntax', True, 'no new_code provided'))

        delta = self._extract_delta(patch_diff) if patch_diff else []
        if delta:
            cr, ch = self._static_checks(delta, code, feedback_tags, feedback_msgs,
                                         required_positive)
            checks.append(cr)
            hard = hard or ch
        else:
            checks.append(CheckResult('static', False, '补丁未引入任何新增行'))
            feedback_tags.append('empty_delta')
            feedback_msgs.append('补丁未引入任何新增行')

        # 聚合：硬失败 → FAIL；有未通过项 → WARNING；否则 PASS
        if hard:
            status = ValidationStatus.FAIL
        elif any(not c.passed for c in checks):
            status = ValidationStatus.WARNING
        else:
            status = ValidationStatus.PASS

        error_lines = [c.detail for c in checks if not c.passed]
        compile_status = ""
        for c in checks:
            if c.name == 'compile':
                compile_status = 'ok' if c.passed else (c.detail[:120] or 'fail')

        tag_str = '; '.join('[%s]' % t for t in feedback_tags)
        msg_str = '; '.join(feedback_msgs)
        feedback = (tag_str + (' :: ' + msg_str if msg_str else '')).strip()

        return ValidationResult(
            status=status, checks=checks, feedback=feedback,
            error_lines=error_lines, compile_status=compile_status, safe=True,
        )

    # -- 检查实现 ------------------------------------------------------

    def _syntax_check(self, code, lang):
        """语法检查：python=compile()；C=括号平衡启发式。"""
        if lang == 'python':
            try:
                compile(code, '<candidate>', 'exec')
                return CheckResult('syntax', True, 'python compile() OK'), False
            except SyntaxError as e:
                return CheckResult('syntax', False, 'SyntaxError: %s' % e), True
        stripped = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
        stripped = re.sub(r'//.*$', '', stripped, flags=re.M)
        depth = 0
        for ch in stripped:
            if ch in '{([':
                depth += 1
            elif ch in '})]':
                depth -= 1
                if depth < 0:
                    return CheckResult('syntax', False, 'unbalanced closing bracket'), True
        if depth != 0:
            return CheckResult('syntax', False, 'unbalanced brackets (depth=%d)' % depth), True
        return CheckResult('syntax', True, 'bracket balance OK'), False

    def _compile_check(self, code, lang):
        """编译检查 —— gcc -fsyntax-only，不链接不运行。

        内联常见头文件 (-include) 缓解反编译片段缺声明噪音；
        输出对象写入临时文件，finally 清理。
        """
        if lang != 'c' or not self._compiler_ok:
            return CheckResult('compile', True,
                               'skipped (lang=%s, compiler_ok=%s)' % (lang, self._compiler_ok)), False
        fd, obj = tempfile.mkstemp(suffix='.o')
        os.close(fd)
        try:
            cmd = [self._compiler, '-fsyntax-only', '-w', '-x', 'c', '-c', '-o', obj,
                   '-include', 'stdio.h', '-include', 'stdlib.h',
                   '-include', 'string.h', '-include', 'limits.h', '-']
            proc = subprocess.run(cmd, input=code, capture_output=True,
                                  text=True, timeout=self._timeout)
        except subprocess.TimeoutExpired:
            return CheckResult('compile', False,
                               'compile timeout after %ss' % self._timeout), False
        except Exception as ex:
            return CheckResult('compile', False,
                               'compile invocation error: %s' % ex), False
        finally:
            try:
                os.remove(obj)
            except OSError:
                pass
        if proc.returncode == 0:
            return CheckResult('compile', True, 'gcc -fsyntax-only OK'), False
        err = proc.stderr.strip()
        if _CONTEXT_NOISE.search(err):
            return CheckResult('compile', False,
                               'context noise: ' + err[:120]), False
        lines = err.splitlines()
        return CheckResult('compile', False,
                           '; '.join(lines[:3]) or 'compile failed'), True

    def _static_checks(self, delta, full_code, feedback_tags, feedback_msgs,
                       required_positive):
        """静态测试预言机 —— 模式检查模拟测试失败信号。

        返回 (CheckResult, hard)：负向命中 hard=True（补丁仍含危险代码）；
        仅缺必需正向模式 hard=False（补丁不完整但安全）。
        """
        blob = '\n'.join(delta)
        negative_hits = []
        for name, pat, msg in _NEGATIVE_RULES:
            m = re.search(pat, blob)
            if m:
                negative_hits.append(name)
                feedback_tags.append(name)
                feedback_msgs.append('%s: %s' % (msg, m.group(0).strip()[:40]))
        if negative_hits:
            return CheckResult('static', False,
                               '残留危险模式: ' + ','.join(negative_hits)), True
        missing = []
        if required_positive:
            full_blob = full_code or blob
            for rule_name in required_positive:
                pat = _POSITIVE_RULES.get(rule_name)
                if pat and not re.search(pat, full_blob):
                    missing.append(rule_name)
                    feedback_tags.append('missing:' + rule_name)
                    feedback_msgs.append('缺少必需安全模式: ' + rule_name)
        if missing:
            return CheckResult('static', False,
                               '缺少必需安全模式: ' + ','.join(missing)), False
        return CheckResult('static', True, '静态检查通过'), False

    # -- 辅助方法 ------------------------------------------------------

    def _check_compiler(self):
        """探测编译器可用性 —— 不可用时编译检查自动跳过。"""
        try:
            proc = subprocess.run([self._compiler, '--version'],
                                  capture_output=True, text=True, timeout=10)
            self._compiler_ok = proc.returncode == 0
        except Exception:
            self._compiler_ok = False
        if not self._compiler_ok:
            logger.warning("compiler '%s' unavailable; compile check will be skipped",
                           self._compiler)

    @staticmethod
    def _extract_delta(patch_diff):
        """从 unified diff 提取新增行（+ 开头且非 +++ 头）。"""
        out = []
        for line in patch_diff.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                out.append(line[1:])
        return out
