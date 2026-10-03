from abc import ABC
import logging
import os
import re
import subprocess
from typing import Dict, Any, Optional, List

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class LLVMIRAnalyzer(BaseAnalyzer, ABC):

    UNSAFE_PATTERNS = [
        (r'alloca\s+[\w.]+,\s*(?:i\d+|\[)', 'alloca_no_bounds_check',
         '栈分配无边界检查, 栈溢出风险'),
        (r'bitcast\s+[\w*]+\s+\S+\s+to\s+[\w*]+', 'bitcast_type_confusion',
         'bitcast 类型混淆风险'),
        (r'getelementptr\s+(?:inbounds\s+)?([\w*]+)', 'unchecked_gep',
         'GEP 无边界检查, 越界访问风险'),
        (r'@printf|@sprintf|@fprintf', 'format_string_risk',
         'printf 族函数调用, 格式字符串漏洞风险'),
        (r'call\s+\w+\s+asm\s+', 'inline_assembly',
         '内联汇编, 控制流劫持风险'),
        (r'unreachable\s*$', 'unreachable_code',
         '不可达代码, 逻辑错误指示'),
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}
        self._ir_content: str = ""
        self._findings: List[Dict[str, Any]] = []

    def _load_ir(self, ir_path: Optional[str] = None,
                  binary_path: Optional[str] = None) -> str:
        if ir_path and os.path.isfile(ir_path):
            with open(ir_path, 'r', encoding='utf-8', errors='replace') as f:
                self._ir_content = f.read()
            return self._ir_content

        if binary_path and os.path.isfile(binary_path):
            try:
                r = subprocess.run(
                    ['llvm-dis', binary_path, '-o', '-'],
                    capture_output=True, text=True, timeout=120,
                    encoding='utf-8', errors='replace'
                )
                if r.returncode == 0 and r.stdout.strip():
                    self._ir_content = r.stdout
                    return self._ir_content
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"llvm-dis failed: {e}")

        return self._ir_content

    def _parse_functions(self) -> Dict[str, Dict]:
        funcs = {}
        pattern = r'define\s+([\w*]+)\s+(@\w+)\s*\(([^)]*)\)'
        for m in re.finditer(pattern, self._ir_content):
            ret_type = m.group(1)
            func_name = m.group(2)
            params = m.group(3)
            body_start = m.end()
            depth = 0
            body_end = body_start
            for i, c in enumerate(self._ir_content[body_start:], body_start):
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        body_end = i + 1
                        break
            body = self._ir_content[body_start:body_end]
            funcs[func_name] = {
                'ret_type': ret_type, 'params': params,
                'body': body, 'start': m.start(), 'end': body_end,
            }
        return funcs

    def _detect_unsafe_patterns(self) -> List[Dict[str, Any]]:
        findings = []
        for pattern, pattern_id, description in self.UNSAFE_PATTERNS:
            for m in re.finditer(pattern, self._ir_content, re.MULTILINE):
                line_num = self._ir_content[:m.start()].count('\n') + 1
                context_start = max(0, m.start() - 40)
                context_end = min(len(self._ir_content), m.end() + 40)
                findings.append({
                    'type': pattern_id,
                    'description': description,
                    'line': line_num,
                    'match': m.group(0)[:80],
                    'context': self._ir_content[context_start:context_end].strip()[:120],
                    'severity': (
                        'HIGH' if pattern_id in [
                            'alloca_no_bounds_check',
                            'format_string_risk',
                            'bitcast_type_confusion',
                        ] else 'MEDIUM'
                    ),
                })
        return findings

    def _detect_uninitialized_vars(self) -> List[Dict[str, Any]]:
        findings = []
        funcs = self._parse_functions()
        for func_name, info in funcs.items():
            body = info['body']
            stores = set(re.findall(
                r'store\s+[\w.]+,\s*[\w.]*\s*(%\w+)', body
            ))
            load_refs = set(re.findall(
                r'load\s+[\w.]+,\s*[\w.]*\s*(%\w+)', body
            ))
            for var in load_refs:
                if var in stores:
                    continue
                findings.append({
                    'type': 'possibly_uninitialized',
                    'description': f'{var} 在 {func_name} 中 load, 无对应 store',
                    'function': func_name, 'variable': var,
                    'severity': 'MEDIUM',
                })
        return findings

    def _detect_control_flow_issues(self) -> List[Dict[str, Any]]:
        findings = []
        labels = set(re.findall(
            r'^(\w[\w.]*):', self._ir_content, re.MULTILINE
        ))
        branches = re.findall(
            r'br\s+(?:label\s+)?%?(\w[\w.]*)', self._ir_content
        )
        for br_target in branches:
            if br_target not in labels and br_target not in ('label',):
                findings.append({
                    'type': 'undefined_branch_target',
                    'description': f'br 目标label未定义: {br_target}',
                    'severity': 'LOW',
                })
        return findings

    def analyze(self, ir_path: Optional[str] = None,
                binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        logger.info("执行 LLVM IR 安全分析...")
        self._load_ir(ir_path=ir_path, binary_path=binary_path)

        if not self._ir_content:
            logger.info("未提供 LLVM IR 输入, 跳过 IR 分析")
            return {
                "success": True,
                "report": {
                    "findings": [],
                    "note": "缺少 LLVM IR — 设置 ir_path 或提供 .ll/.bc 文件"
                }
            }

        unsafe = self._detect_unsafe_patterns()
        uninit = self._detect_uninitialized_vars()
        cfg_issues = self._detect_control_flow_issues()
        all_findings = unsafe + uninit + cfg_issues

        high_count = sum(
            1 for f in all_findings if f.get('severity') == 'HIGH'
        )
        logger.info(
            f"LLVM IR 分析完成: {len(all_findings)} 项发现 "
            f"({high_count} 高危)"
        )
        return {
            "success": True,
            "report": {
                "findings": all_findings,
                "total_count": len(all_findings),
                "high_severity_count": high_count,
                "functions_analyzed": len(self._parse_functions()),
            }
        }

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="LLVMIRAnalyzer",
            type=AnalyzerType.ANALYSIS_ENGINE,
            version="1.0.0",
            description="LLVM IR based cross-language security analysis",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"])

__all__ = ["LLVMIRAnalyzer"]
