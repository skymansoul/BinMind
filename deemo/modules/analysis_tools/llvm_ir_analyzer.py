import logging, os, re, subprocess
from typing import Dict, Any, Optional, List

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class LLVMIRAnalyzer(BaseAnalyzer):

    UNSAFE_PATTERNS = [
        (r'alloca\s+[\w.]+,\s*(?:i\d+|\[)', 'alloca_no_bounds_check',
         'stack分配无bounds check, stack overflow风险'),
        (r'bitcast\s+[\w*]+\s+\S+\s+to\s+[\w*]+', 'bitcast_type_confusion',
         'bitcast 类型混淆风险'),
        (r'getelementptr\s+(?:inbounds\s+)?([\w*]+)', 'unchecked_gep',
         'GEP 无bounds check, 越界访问风险'),
        (r'@printf|@sprintf|@fprintf', 'format_string_risk',
         'printf族函数调用, 格式字符串漏洞风险'),
        (r'call\s+\w+\s+asm\s+', 'inline_assembly',
         '内联汇编, control flow劫持风险'),
        (r'unreachable\s*$', 'unreachable_code', '不可达代码, 逻辑错误指示'),
    ]
    _UB_PATTERNS = [
        (r'(?:add|sub|mul|shl)\s+(?:nuw\s+)?(?:nsw\s+)?(i\d+)', 'potential_overflow',
         '整数运算缺少 nuw/nsw 标记'),
        (r'load\s+[\w.]+,\s*[\w.]*\s*\*.*align\s+(\d+)', 'under_aligned_load',
         'load 对齐值 < 自然对齐'),
    ]
    # clang static analyzer 风格的检查——未初始化的栈变量使用
    _UNINIT_STACK_PAT = re.compile(
        r'alloca\s+([\w.]+)\s*\n(?:.*\n){0,20}.*load.*\1', re.MULTILINE)

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}; self._ir_content: str = ""
        self._findings: List[Dict[str, Any]] = []

    def _load_ir(self, ir_path=None, binary_path=None) -> str:
        if ir_path and os.path.isfile(ir_path):
            with open(ir_path, 'r', encoding='utf-8', errors='replace') as f:
                self._ir_content = f.read(); return self._ir_content
        if binary_path and os.path.isfile(binary_path):
            try:
                r = subprocess.run(
                    ['llvm-dis', binary_path, '-o', '-'],
                    capture_output=True, text=True, timeout=120,
                    encoding='utf-8', errors='replace')
                if r.returncode == 0 and r.stdout.strip():
                    self._ir_content = r.stdout; return self._ir_content
            except Exception as e: logger.debug(f"llvm-dis failed: {e}")
        return self._ir_content

    def _parse_functions(self) -> Dict[str, Dict]:
        funcs = {}
        pattern = r'define\s+([\w*]+)\s+(@\w+)\s*\(([^)]*)\)'
        for m in re.finditer(pattern, self._ir_content):
            ret_type = m.group(1); func_name = m.group(2); params = m.group(3)
            body_start = m.end(); depth = 0; body_end = body_start
            for i, c in enumerate(self._ir_content[body_start:], body_start):
                if c == '{': depth += 1
                elif c == '}': depth -= 1
                if depth == 0: body_end = i + 1; break
            body = self._ir_content[body_start:body_end]
            funcs[func_name] = {'ret_type': ret_type, 'params': params,
                                'body': body, 'start': m.start(), 'end': body_end}
        return funcs

    def _detect_unsafe_patterns(self) -> List[Dict[str, Any]]:
        findings = []
        all_pats = self.UNSAFE_PATTERNS + self._UB_PATTERNS
        for pat, pid, desc in all_pats:
            for m in re.finditer(pat, self._ir_content, re.MULTILINE):
                line_num = self._ir_content[:m.start()].count('\n') + 1
                cs = max(0, m.start() - 40); ce = min(len(self._ir_content), m.end() + 40)
                findings.append({
                    'type': pid, 'description': desc, 'line': line_num,
                    'match': m.group(0)[:80],
                    'context': self._ir_content[cs:ce].strip()[:120],
                    'severity': 'HIGH' if pid in ('alloca_no_bounds_check',
                        'format_string_risk','bitcast_type_confusion',
                        'potential_overflow') else 'MEDIUM'})
        return findings

    def _detect_uninitialized_vars(self) -> List[Dict[str, Any]]:
        findings = []; funcs = self._parse_functions()
        for func_name, info in funcs.items():
            body = info['body']
            stores = set(re.findall(r'store\s+[\w.]+,\s*[\w.]*\s*(%\w+)', body))
            load_refs = set(re.findall(r'load\s+[\w.]+,\s*[\w.]*\s*(%\w+)', body))
            for var in load_refs:
                if var not in stores:
                    findings.append({
                        'type': 'possibly_uninitialized',
                        'description': f'{var} 在 {func_name} 中load, 无对应store',
                        'function': func_name, 'variable': var, 'severity': 'MEDIUM'})
        return findings

    def _detect_control_flow_issues(self) -> List[Dict[str, Any]]:
        findings = []
        labels = set(re.findall(r'^(\w[\w.]*):', self._ir_content, re.MULTILINE))
        branches = re.findall(r'br\s+(?:label\s+)?%?(\w[\w.]*)', self._ir_content)
        for br_target in branches:
            if br_target not in labels and br_target not in ('label',):
                findings.append({'type': 'undefined_branch_target',
                                 'description': f'br 目标label未定义: {br_target}',
                                 'severity': 'LOW'})
        return findings

    def analyze(self, ir_path=None, binary_path=None, **kwargs) -> Dict[str, Any]:
        logger.info("执行 LLVM IR 安全分析...")
        self._load_ir(ir_path=ir_path, binary_path=binary_path)
        if not self._ir_content:
            return {"success": True, "report": {"findings": [],
                    "note": "缺少 LLVM IR — 设置 ir_path 或提供 .ll/.bc 文件"}}
        unsafe = self._detect_unsafe_patterns()
        uninit = self._detect_uninitialized_vars()
        cfg_issues = self._detect_control_flow_issues()
        all_findings = unsafe + uninit + cfg_issues
        high_count = sum(1 for f in all_findings if f.get('severity') == 'HIGH')
        logger.info(f"LLVM IR 分析完成: {len(all_findings)} 项 ({high_count} 高危)")
        return {"success": True, "report": {"findings": all_findings,
                "total_count": len(all_findings),
                "high_severity_count": high_count,
                "functions_analyzed": len(self._parse_functions())}}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(name="LLVMIRAnalyzer", type=AnalyzerType.ANALYSIS_ENGINE,
                                version="1.0.0", author="BinaryAnalysisPlatform",
                                dependencies=[], supported_platforms=["any"])

__all__ = ["LLVMIRAnalyzer"]
