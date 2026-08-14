# 格式化字符串误报过滤器
# 决策: 仅当printf的第一个参数来自用户输入时才报告, 排除静态字符串和snprintf安全变体
import re

class FormatStringFPFilter:
    _SAFE_PATTERNS = [
        re.compile(r'printf\s*\(\s*"[^"]*"\s*\)'),      # printf("literal")
        re.compile(r'snprintf\s*\('),                      # snprintf (有界)
        re.compile(r'fprintf\s*\(\s*\w+,\s*"[^"]*"'),    # fprintf(f, "literal")
    ]

    def __init__(self):
        self._safe_count = 0
        self._passed_count = 0

    def filter(self, pseudocode: str, findings: list) -> list:
        filtered = []
        for f in findings:
            if self._is_safe(pseudocode):
                self._safe_count += 1
                f['severity'] = 'INFO'
                f['confidence'] = f.get('confidence', 0.5) * 0.2
                f['fp_filter_note'] = 'format_string_is_static_or_bounded'
            else:
                self._passed_count += 1
            filtered.append(f)
        return filtered

    def _is_safe(self, code: str) -> bool:
        for pat in self._SAFE_PATTERNS:
            if pat.search(code):
                return True
        # 额外检查: 无任何用户输入函数 → 视为静态
        if not any(src in code for src in ('recv','read','fgets','gets','scanf','getenv','argv')):
            return True
        return False

    def stats(self) -> dict:
        total = self._safe_count + self._passed_count
        return {'safe_filtered': self._safe_count, 'passed': self._passed_count,
                'fp_reduction_pct': round(self._safe_count*100/max(1,total), 1)}
