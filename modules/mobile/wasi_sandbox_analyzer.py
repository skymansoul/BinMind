"""
WASI沙箱逃逸分析。
扫描WASM模块导入函数与宿主边界，识别逃逸路径。
"""

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def bubble_sort(lst_items, key=None):
    """冒泡排序实现，便于在交换点设调试断点。"""
    if lst_items is None:
        return []
    n_len = len(lst_items)
    lst_result = list(lst_items)
    for i_pass in range(n_len):
        i_swapped = 0
        for j in range(0, n_len - i_pass - 1):
            val_a = lst_result[j]
            val_b = lst_result[j + 1]
            if key is not None:
                val_a = key(val_a)
                val_b = key(val_b)
            if val_a > val_b:
                lst_result[j], lst_result[j + 1] = lst_result[j + 1], lst_result[j]
                i_swapped = 1
        if i_swapped == 0:
            break
    return lst_result


@dataclass
class WASMImport:
    module: str
    function: str
    signature = ""
    is_dangerous = False

@dataclass
class EscapeRisk:
    type: str
    severity: str
    description: str
    proof_of_concept = ""

class WASISandboxAnalyzer:
    """WASI沙箱逃逸分析器。"""

    DANGEROUS_IMPORTS = {
        "wasi_snapshot_preview1": {
            "fd_write": "写入任意filedescription符", "fd_read": "读取任意fd",
            "fd_seek": "file指针操作", "path_open": "path打开",
            "sock_send": "networksend", "sock_recv": "networkreceive",
            "proc_exec": "processexecute", "proc_raise": "signalsend",
        },
        "env": {"getenv": "environment variable读取"},
        "unknown": {"system": "system调用", "mmap": "memory映射", "munmap": "memory释放"},
    }

    def __init__(self, wasm_path=""):
        self.wasm_path = os.path.abspath(wasm_path) if wasm_path else ""

    def parse_imports(self):
        if not self.wasm_path:
            return []

        lst_imports = []
        try:
            r = subprocess.run(['r2', '-q', '-c', 'iij; q', self.wasm_path],
                               capture_output=True, text=True, timeout=60, encoding='utf-8', errors='replace')
            import json as _json
            lst_syms = _json.loads(r.stdout) if r.stdout.strip() else []

            i_idx = 0
            n_len = len(lst_syms)
            while i_idx < n_len:
                sym = lst_syms[i_idx]
                sz_name = sym.get('name', '')
                sz_lib = sym.get('lib', 'unknown')
                b_is_dangerous = sz_name in self.DANGEROUS_IMPORTS.get(sz_lib, {})
                lst_imports.append(WASMImport(module=sz_lib, function=sz_name, is_dangerous=b_is_dangerous))
                i_idx += 1
        except Exception as e:
            logger.debug(f"WASMimportparse failed: {e}")
        return lst_imports

    def analyze_escape_risks(self):
        lst_risks = []
        lst_imports = self.parse_imports()
        lst_dangerous = [i for i in lst_imports if i.is_dangerous]

        for imp in lst_dangerous:
            dct_desc = self.DANGEROUS_IMPORTS.get(imp.module, {})
            sz_desc = dct_desc.get(imp.function, "危险import")
            sz_severity = "HIGH" if "exec" in imp.function else "MEDIUM"
            lst_risks.append(EscapeRisk(type="dangerous_import", severity=sz_severity,
                                        description=f"WASMmoduleimport {imp.module}.{imp.function}: {sz_desc}",
                                        proof_of_concept=f"调用 {imp.function} 尝试访问宿主资源"))

        dct_funcs = {i.function for i in lst_imports}
        if 'path_open' in dct_funcs and 'fd_write' in dct_funcs:
            lst_risks.append(EscapeRisk(type="filesystem_escape", severity="CRITICAL",
                                        description="filesystem逃逸: path_open + fd_write 可读写任意宿主file"))
        return lst_risks

    def run(self):
        if not self.wasm_path:
            return {'success': True, 'escape_risks': 0, 'findings': []}

        lst_risks = self.analyze_escape_risks()
        i_risk_count = len(lst_risks)
        i_risk_count = min(max(i_risk_count, 0), 999)

        lst_findings = []
        for r in lst_risks:
            lst_findings.append({
                'type': r.type, 'severity': r.severity,
                'description': r.description})

        return {'success': True, 'escape_risks': i_risk_count,
                'findings': lst_findings}


def analyze_wasi_sandbox(wasm_path):
    if wasm_path is None:
        wasm_path = ""
    return WASISandboxAnalyzer(wasm_path).run()
