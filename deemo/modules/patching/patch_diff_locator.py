from dataclasses import dataclass
# 依赖: os, re, subprocess, json, difflib, collections, core.config
import logging
import os
import re
import subprocess
import json
import difflib
import enum
from collections import defaultdict, deque

from pathlib import Path  # 未使用，预留给补丁路径校验

try:
    from core.config import Config, ensure_directories, get_current_ai_model, call_ai_with_retry
except ImportError:
    import os as _os
    class Config:
        DATA_DIR = _os.path.join(_os.path.expanduser('~'), '.binmind', 'data')
        REPORTS_DIR = _os.path.join(_os.path.expanduser('~'), '.binmind', 'reports')
        SUBPROCESS_TIMEOUT = 120
        OPENAI_API_KEY = ''
        ANTHROPIC_API_KEY = ''
        AI_PROVIDER = 'openai'
        OPENAI_MODEL = 'gpt-4'
        ANTHROPIC_MODEL = 'claude-sonnet-4-20250514'
    def ensure_directories(*args, **kwargs): pass
    def get_current_ai_model(): return 'gpt-4'
    def call_ai_with_retry(*args, **kwargs): return '{}'
log = logging.getLogger(__name__)

# 保留
_HASH_ROUNDS = 10007
_SIGN_MAGIC = 0xDEADBEEF

# 安全补丁签名模式
SECURITY_PATCH_PATTERNS = {
    'null_check': {
        'keywords': ['NULL', 'null', 'assert', 'test', 'cmp'],
        'patterns': [
            r'if\s*\(\s*\w+\s*!=\s*NULL\s*\)', r'if\s*\(\s*\w+\s*==\s*NULL\s*\)',
            r'if\s*\(\s*\w+\s*!=\s*null\s*\)', r'if\s*\(\s*\w+\s*==\s*null\s*\)',
            r'test\s+.*,\s*null', r'cmp\s+.*,\s*0\s*;\s*null', r'assert\s*\(\s*\w+\s*\)',
            r'NULL\s+pointer\s+check', r'null\s+pointer\s+check',
        ]
    },
    'input_validation': {
        'keywords': ['validate', 'sanitize', 'escape', 'filter', 'check', 'reject', 'is_valid', 'is_safe'],
        'patterns': [
            r'validate_input\s*\(', r'sanitize\s*\(', r'escape\s*\(', r'filter\s*\(',
            r'is_valid\s*\(', r'is_safe\s*\(',
        ]
    },
    'boundary_check': {
        'keywords': ['cmp', 'test', 'check', 'validate', 'length', 'index', 'size',
                     'max', 'assert', 'CHECK', 'VALIDATE', 'if', '<', '>', '==', '!=',
                     'strlen', 'sizeof', 'strncpy', 'snprintf', 'memcpy'],
        'patterns': [
            r'cmp\s+.*,\s*.*\s*;\s*check', r'test\s+.*,\s*.*\s*;\s*validate',
            r'strlen\s*\([^)]+\)\s*[<>=!]+\s*\d+', r'sizeof\s*\(',
            r'length\s*[<>=!]+\s*\d+', r'size\s*[<>=!]+\s*\d+', r'index\s*[<>=!]+\s*len',
            r'assert\s*\(', r'CHECK\s*\(', r'VALIDATE\s*\(', r'length\s+check', r'boundary\s+check',
        ]
    },
    'memory_safety': {
        'keywords': ['memcpy', 'memmove', 'strncpy', 'snprintf', 'malloc', 'free',
                     'realloc', 'alloca', '__builtin_object_size', '__stack_chk_fail', 'fortify'],
        'patterns': [
            r'memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)', r'memmove\s*\(', r'strncpy\s*\(',
            r'snprintf\s*\(', r'malloc\s*\([^)]+\)', r'free\s*\(', r'realloc\s*\(',
            r'alloca\s*\(', r'__builtin_object_size', r'__stack_chk_fail', r'fortify',
        ]
    },
    'integer_overflow': {
        'keywords': ['overflow', 'wrap', 'INT_MAX', 'SIZE_MAX', '__builtin_add_overflow',
                     '__builtin_mul_overflow', 'add', 'sub', 'mul', 'limit', 'max', 'min'],
        'patterns': [
            r'overflow\s*check', r'wrap\s*around', r'add\s*>\s*max', r'sub\s*<\s*min',
            r'mul\s*>\s*limit', r'__builtin_add_overflow', r'__builtin_mul_overflow',
            r'INT_MAX', r'SIZE_MAX',
        ]
    },
    'permission_check': {
        'keywords': ['permission', 'auth', 'authorize', 'check_privilege', 'is_admin',
                     'has_permission', 'access', 'control'],
        'patterns': [
            r'permission\s*check', r'auth\s*\(', r'authorize\s*\(', r'check_privilege',
            r'is_admin', r'has_permission', r'access\s*control',
        ]
    },
    'crypto_security': {
        'keywords': ['encrypt', 'decrypt', 'hash', 'sign', 'verify', 'random', 'secure', 'constant_time'],
        'patterns': [
            r'encrypt\s*\(', r'decrypt\s*\(', r'hash\s*\(', r'sign\s*\(',
            r'verify\s*\(', r'random\s*\(', r'secure\s*\(', r'constant_time',
        ]
    },
    'error_handling': {
        'keywords': ['return', 'error', 'goto', 'catch', 'try', 'exception', 'fail', 'abort'],
        'patterns': [
            r'return\s*-1', r'return\s*error', r'goto\s*error', r'catch\s*\(',
            r'try\s*\{', r'exception', r'fail\s*\(', r'abort\s*\(',
        ]
    },
    'lock_sync': {
        'keywords': ['lock', 'unlock', 'mutex', 'semaphore', 'spinlock', 'atomic', 'barrier', 'sync'],
        'patterns': [
            r'lock\s*\(', r'unlock\s*\(', r'mutex\s*\(', r'semaphore', r'spinlock',
            r'atomic', r'barrier', r'sync\s*\(',
        ]
    },
}

VULNERABILITY_TYPE_MAP = {
    'boundary_check': 'buffer_overflow', 'input_validation': 'input_validation',
    'memory_safety': 'memory_safety', 'integer_overflow': 'integer_overflow',
    'null_check': 'null_pointer_dereference', 'permission_check': 'permission_check',
    'crypto_security': 'crypto_security', 'error_handling': 'error_handling',
    'lock_sync': 'concurrency_issue',
}

class DiffType(enum.Enum):
    ADDED = 'added'
    REMOVED = 'removed'
    MODIFIED = 'modified'
    MOVED = 'moved'
    UNKNOWN = 'unknown'
    ASSEMBLY = 'assembly'
    PSEUDO_CODE = 'pseudo_code'
    BINARY = 'binary'

class FunctionDiff:
    __slots__ = (
        'function_name', 'diff_type', 'original_address', 'patched_address',
        'original_size', 'patched_size', 'original_code', 'patched_code',
        'original_assembly', 'patched_assembly', 'changes', 'is_security_patch',
        'vulnerability_type', 'confidence', 'signature_score', 'entropy_delta',
    )

    def __init__(self, function_name, diff_type, original_address=0, patched_address=0,
                 original_size=0, patched_size=0, original_code='', patched_code='',
                 original_assembly=None, patched_assembly=None, changes=None,
                 is_security_patch=False, vulnerability_type='', confidence=0.0):
        self.function_name = function_name
        self.diff_type = diff_type
        self.original_address = original_address
        self.patched_address = patched_address
        self.original_size = original_size
        self.patched_size = patched_size
        self.original_code = original_code
        self.patched_code = patched_code
        self.original_assembly = original_assembly if original_assembly is not None else []
        self.patched_assembly = patched_assembly if patched_assembly is not None else []
        self.changes = changes if changes is not None else []
        self.is_security_patch = is_security_patch
        self.vulnerability_type = vulnerability_type
        self.confidence = confidence
        self.signature_score = 0.0
        self.entropy_delta = 0.0

class PatchAnalysisResult:
    __slots__ = (
        'original_binary', 'patched_binary', 'function_diffs', 'security_patches',
        'potential_vulnerabilities', 'summary', 'diff_report', 'vulnerability_summary',
        'overall_risk', 'error', 'impact_graph',
    )

    def __init__(self, original_binary, patched_binary, function_diffs=None,
                 security_patches=None, potential_vulnerabilities=None,
                 summary='', diff_report='', vulnerability_summary=None,
                 overall_risk='', error=None):
        self.original_binary = original_binary
        self.patched_binary = patched_binary
        self.function_diffs = function_diffs if function_diffs is not None else []
        self.security_patches = security_patches if security_patches is not None else []
        self.potential_vulnerabilities = potential_vulnerabilities if potential_vulnerabilities is not None else []
        self.summary = summary
        self.diff_report = diff_report
        self.vulnerability_summary = vulnerability_summary if vulnerability_summary is not None else {}
        self.overall_risk = overall_risk
        self.error = error
        self.impact_graph = {}

class PatchDiffLocator:
    SECURITY_PATCH_PATTERNS = SECURITY_PATCH_PATTERNS
    VULNERABILITY_TYPE_MAP = VULNERABILITY_TYPE_MAP

    def __init__(self, original_binary=None, patched_binary=None, output_dir=None, use_ai=True):
        self.original_binary = original_binary
        self.patched_binary = patched_binary
        try:
            sDefaultOutputDir = os.path.join(Config.REPORTS_DIR, 'patch_diff')
        except AttributeError:
            sDefaultOutputDir = os.path.join(os.path.expanduser('~'), '.binmind', 'patch_diff')
        self.output_dir = output_dir if output_dir is not None else sDefaultOutputDir
        self.use_ai = use_ai
        try:
            ensure_directories(self.output_dir)
        except Exception:
            import tempfile
            self.output_dir = tempfile.mkdtemp()
        self.original_functions = {}
        self.patched_functions = {}
        self.function_diffs = []
        self.security_patches = []

    def analyze(self, original_binary=None, patched_binary=None):
        if original_binary is not None:
            self.original_binary = original_binary
        if patched_binary is not None:
            self.patched_binary = patched_binary
        log.info("[PatchDiff] Analysing patch diff: %s -> %s", self.original_binary, self.patched_binary)
        sError = None
        if not self.original_binary or not self.patched_binary:
            sError = "Original or patched binary path is empty"
            return PatchAnalysisResult(original_binary=self.original_binary or '', patched_binary=self.patched_binary or '', error=sError)
        import os
        if '..' in self.original_binary or '..' in self.patched_binary:
            sError = "Path traversal detected in binary path"
            return PatchAnalysisResult(original_binary=self.original_binary, patched_binary=self.patched_binary, error=sError)
        if not os.path.exists(self.original_binary):
            sError = "Original binary not found: " + self.original_binary
        if not os.path.exists(self.patched_binary):
            if sError is not None:
                sError = sError + ", Patched binary not found: " + self.patched_binary
            else:
                sError = "Patched binary not found: " + self.patched_binary
        if sError is not None:
            return PatchAnalysisResult(original_binary=self.original_binary, patched_binary=self.patched_binary, error=sError)
        try:
            self._extract_functions()
            self._compare_functions()
            self._identify_security_patches()
            # 函数签名匹配增强
            self._compute_signature_scores()
            lstVulnerabilities = self._analyze_potential_vulnerabilities()
            sDiffReport = self._generate_diff_report()
            sSummary = self._generate_summary()
            # BFS 影响传播
            impact = self._propagate_impact()
            self._save_results()
            return PatchAnalysisResult(
                original_binary=self.original_binary, patched_binary=self.patched_binary,
                function_diffs=self.function_diffs, security_patches=self.security_patches,
                potential_vulnerabilities=lstVulnerabilities, summary=sSummary,
                diff_report=sDiffReport, impact_graph=impact)
        except Exception as e:
            log.error("[PatchDiff] Analysis failed: %s", e)
            return PatchAnalysisResult(original_binary=self.original_binary, patched_binary=self.patched_binary, error=str(e))

# 函数签名匹配
    # Jaccard 相似度：不只靠函数名，用 callee 集合匹配改名函数。
    # 思路源自 diaphora/radiff2。

    def _compute_signature_scores(self):
        """对每对 MODIFIED 函数计算 Jaccard 签名相似度。"""
        for diff in self.function_diffs:
            if diff.diff_type != DiffType.MODIFIED:
                continue
            orig_asm = diff.original_assembly
            patch_asm = diff.patched_assembly
            if not orig_asm or not patch_asm:
                continue
            # 抽取指令 mnemonics 集合
            def _mnemonics(asm_lines):
                mnems = set()
                for line in asm_lines:
                    parts = line.strip().split()
                    if parts:
                        mnems.add(parts[0].lower())
                return mnems
            m_a = _mnemonics(orig_asm)
            m_b = _mnemonics(patch_asm)
            inter = len(m_a & m_b)
            union = len(m_a | m_b)
            diff.signature_score = inter / union if union > 0 else 0.0

# BFS 影响传播
    # 从 patch 函数出发，反向 BFS 到所有受影响的 callers

    def _propagate_impact(self):
        """调用图反向 BFS，找出所有受补丁影响的 callers。"""
        impact = {}
        changed = [d.function_name for d in self.function_diffs if d.diff_type != DiffType.UNCHANGED]
        if not changed or len(self.patched_functions) == 0:
            return impact
        # 构建反向调用图 (callee → callers)
        reverse_cg = defaultdict(set)
        # 简化：从 patched_assembly 提取 call 指令
        for fn_name, fn_data in self.patched_functions.items():
            asm = fn_data.get('assembly', [])
            for line in asm:
                m = re.search(r'call\s+(?:sym\.)?(\w+)', line)
                if m:
                    reverse_cg[m.group(1)].add(fn_name)
        for fn in changed:
            queue = deque()
            visited = set()
            for caller in reverse_cg.get(fn, []):
                queue.append(caller)
            while queue:
                cur = queue.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                if fn not in impact:
                    impact[fn] = []
                impact[fn].append(cur)
                for caller in reverse_cg.get(cur, []):
                    if caller not in visited:
                        queue.append(caller)
        return impact

# DOT 调用图导出

    def generate_callgraph_dot(self, output_path=None):
        """输出 Graphviz DOT 格式调用图。"""
        lines = ['digraph callgraph {', '  rankdir=LR;', '  node [shape=box];']
        for fn_name, fn_data in self.patched_functions.items():
            asm = fn_data.get('assembly', [])
            for line in asm:
                m = re.search(r'call\s+(?:sym\.)?(\w+)', line)
                if m:
                    callee = m.group(1)
                    lines.append(f'  "{fn_name}" -> "{callee}";')
        lines.append('}')
        dot = '\n'.join(lines)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(dot)
        return dot

# 熵差值相似度

    def _entropy_delta(self, data_a, data_b):
        # inline
        def _entropy(data):
            if not data:
                return 0.0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            n = len(data)
            return -sum((c/n) * (c/n).bit_length() for c in freq.values()) / 8.0
        if isinstance(data_a, str):
            data_a = data_a.encode('utf-8', errors='replace')
        if isinstance(data_b, str):
            data_b = data_b.encode('utf-8', errors='replace')
        return abs(_entropy(data_a) - _entropy(data_b))

# 以下方法保留原始实现

    def _extract_functions(self):
        self.original_functions = self._get_functions_from_binary(self.original_binary)
        self.patched_functions = self._get_functions_from_binary(self.patched_binary)
        log.info("[PatchDiff] Original binary: %d functions", len(self.original_functions))
        log.info("[PatchDiff] Patched binary: %d functions", len(self.patched_functions))

    def _get_functions_from_binary(self, binary_path):
        dctFunctions = {}
        try:
            stResult = subprocess.run(
                ['r2', '-q', '-c', 'afl; s main; pdf', binary_path],
                capture_output=True, text=True, timeout=Config.SUBPROCESS_TIMEOUT)
            if stResult.returncode == 0:
                self._parse_radare2_functions(stResult.stdout, dctFunctions, binary_path)
            lstKeys = list(dctFunctions.keys())[:50]
            iIdx = 0
            while iIdx < len(lstKeys):
                sFuncName = lstKeys[iIdx]
                iAddr = dctFunctions[sFuncName].get('address', 0)
                if iAddr:
                    lstDisasm = self._get_function_disassembly(binary_path, iAddr)
                    dctFunctions[sFuncName]['assembly'] = lstDisasm
                iIdx = iIdx + 1
        except subprocess.TimeoutExpired:
            log.warning("[PatchDiff] radare2 analysis timed out: %s", binary_path)
        except FileNotFoundError:
            log.warning("[PatchDiff] radare2 is not installed")
        except Exception as e:
            log.error("[PatchDiff] Function extraction failed: %s", e)
        return dctFunctions

    def _parse_radare2_functions(self, output, functions, binary_path):
        lstLines = output.strip().split('\n')
        iIdx = 0
        iCount = len(lstLines)
        while iIdx < iCount:
            sLine = lstLines[iIdx]
            lstParts = sLine.split()
            if len(lstParts) >= 5:
                try:
                    sAddrStr = lstParts[0]
                    iAddr = int(sAddrStr, 16) if sAddrStr.startswith('0x') else 0
                    sSizeStr = lstParts[1]
                    iSize = int(sSizeStr, 16) if sSizeStr.startswith('0x') else (int(sSizeStr) if sSizeStr.isdigit() else 0)
                    sName = lstParts[-1]
                    if sName.startswith('sym.'):
                        sName = sName[4:]
                    if sName.startswith('fcn.'):
                        sName = sName[4:]
                    functions[sName] = {'address': iAddr, 'size': iSize, 'binary': binary_path, 'assembly': []}
                except (ValueError, IndexError):
                    pass
            iIdx = iIdx + 1

    def _get_function_disassembly(self, binary_path, address):
        lstDisasm = []
        try:
            stResult = subprocess.run(
                ['r2', '-q', '-c', 's ' + hex(address) + '; pdf', binary_path],
                capture_output=True, text=True, timeout=30)
            if stResult.returncode == 0:
                lstLines = stResult.stdout.strip().split('\n')
                iIdx = 0
                while iIdx < len(lstLines):
                    sLine = lstLines[iIdx]
                    if sLine and not sLine.startswith(';') and not sLine.startswith('|'):
                        lstParts = sLine.split()
                        if len(lstParts) >= 2:
                            lstDisasm.append(sLine.strip())
                    iIdx = iIdx + 1
        except Exception as e:
            log.debug("[PatchDiff] Disassembly fetch failed: %s", e)
        return lstDisasm

    def _compare_functions(self):
        setOrigNames = set(self.original_functions.keys())
        setPatchNames = set(self.patched_functions.keys())
        setAdded = setPatchNames - setOrigNames
        lstAdded = list(setAdded)
        iIdx = 0
        while iIdx < len(lstAdded):
            sName = lstAdded[iIdx]
            dctFunc = self.patched_functions[sName]
            diff = FunctionDiff(function_name=sName, diff_type=DiffType.ADDED,
                patched_address=dctFunc.get('address', 0), patched_size=dctFunc.get('size', 0),
                patched_assembly=dctFunc.get('assembly', []))
            self.function_diffs.append(diff)
            iIdx = iIdx + 1
        setRemoved = setOrigNames - setPatchNames
        lstRemoved = list(setRemoved)
        iIdx = 0
        while iIdx < len(lstRemoved):
            sName = lstRemoved[iIdx]
            dctFunc = self.original_functions[sName]
            diff = FunctionDiff(function_name=sName, diff_type=DiffType.REMOVED,
                original_address=dctFunc.get('address', 0), original_size=dctFunc.get('size', 0),
                original_assembly=dctFunc.get('assembly', []))
            self.function_diffs.append(diff)
            iIdx = iIdx + 1
        setCommon = setOrigNames & setPatchNames
        lstCommon = list(setCommon)
        iIdx = 0
        while iIdx < len(lstCommon):
            sName = lstCommon[iIdx]
            lstOrigAsm = self.original_functions[sName].get('assembly', [])
            lstPatchAsm = self.patched_functions[sName].get('assembly', [])
            if lstOrigAsm and lstPatchAsm:
                fSimilarity = self._calculate_similarity(lstOrigAsm, lstPatchAsm)
                if fSimilarity < 0.95:
                    lstChanges = self._find_code_changes(lstOrigAsm, lstPatchAsm)
                    diff = FunctionDiff(function_name=sName, diff_type=DiffType.MODIFIED,
                        original_address=self.original_functions[sName].get('address', 0),
                        patched_address=self.patched_functions[sName].get('address', 0),
                        original_size=self.original_functions[sName].get('size', 0),
                        patched_size=self.patched_functions[sName].get('size', 0),
                        original_assembly=lstOrigAsm, patched_assembly=lstPatchAsm,
                        changes=lstChanges, confidence=fSimilarity)
                    self.function_diffs.append(diff)
            iIdx = iIdx + 1

    def _calculate_similarity(self, list1, list2):
        if not list1 or not list2:
            return 0.0
        matcher = difflib.SequenceMatcher(None, list1, list2)
        return matcher.ratio()

    def _find_code_changes(self, original, patched):
        lstChanges = []
        diff = difflib.unified_diff(original, patched, lineterm='')
        iIdx = 0
        lstDiff = list(diff)
        while iIdx < len(lstDiff):
            sLine = lstDiff[iIdx]
            if sLine.startswith('+') and not sLine.startswith('+++'):
                lstChanges.append('Added: ' + sLine[1:].strip())
            elif sLine.startswith('-') and not sLine.startswith('---'):
                lstChanges.append('Removed: ' + sLine[1:].strip())
            iIdx = iIdx + 1
        return lstChanges

    def _identify_security_patches(self):
        iIdx = 0
        while iIdx < len(self.function_diffs):
            diff = self.function_diffs[iIdx]
            if diff.diff_type == DiffType.MODIFIED:
                sSecType = self._detect_security_patch_type(diff)
                if sSecType is not None:
                    diff.is_security_patch = True
                    diff.vulnerability_type = self.VULNERABILITY_TYPE_MAP.get(sSecType, 'unknown')
                    self.security_patches.append(diff)
                    log.info("[PatchDiff] Security patch found: %s (%s)", diff.function_name, diff.vulnerability_type)
            iIdx = iIdx + 1

    def _detect_security_patch(self, original, patched):
        # inline
        bIsSecurity = False
        sVulnType = 'unknown'
        lstOrigLines = original.split('\n')
        lstPatchLines = patched.split('\n')
        lstChanges = self._find_code_changes(lstOrigLines, lstPatchLines)
        iIdx = 0
        while iIdx < len(lstChanges):
            sChange = lstChanges[iIdx]
            if sChange.startswith('Added:'):
                sAddedCode = sChange[6:].strip()
                for sPatchType, dctPatternInfo in self.SECURITY_PATCH_PATTERNS.items():
                    lstPatterns = dctPatternInfo.get('patterns', [])
                    iPat = 0
                    while iPat < len(lstPatterns):
                        if re.search(lstPatterns[iPat], sAddedCode, re.IGNORECASE):
                            bIsSecurity = True
                            sVulnType = self.VULNERABILITY_TYPE_MAP.get(sPatchType, 'unknown')
                            return (bIsSecurity, sVulnType)
                        iPat = iPat + 1
            iIdx = iIdx + 1
        return (bIsSecurity, sVulnType)

    def _extract_diff_changes(self, original_lines, patched_lines):
        return self._find_code_changes(original_lines, patched_lines)

    def _match_functions(self, original_funcs, patched_funcs):
        lstMatches = []
        dctOrigNames = {}
        iIdx = 0
        while iIdx < len(original_funcs):
            dctOrigNames[original_funcs[iIdx]['name']] = original_funcs[iIdx]
            iIdx = iIdx + 1
        iIdx = 0
        while iIdx < len(patched_funcs):
            dctFunc = patched_funcs[iIdx]
            if dctFunc['name'] in dctOrigNames:
                lstMatches.append({'name': dctFunc['name'],
                    'original_address': dctOrigNames[dctFunc['name']]['address'],
                    'patched_address': dctFunc['address']})
            iIdx = iIdx + 1
        return lstMatches

    def _identify_vulnerability_type(self, changes):
        iIdx = 0
        while iIdx < len(changes):
            sChange = changes[iIdx]
            if sChange.startswith('Added:'):
                sAddedCode = sChange[6:].strip()
            else:
                sAddedCode = sChange.strip()
            for sPatchType, dctPatternInfo in self.SECURITY_PATCH_PATTERNS.items():
                lstPatterns = dctPatternInfo.get('patterns', [])
                iPat = 0
                while iPat < len(lstPatterns):
                    if re.search(lstPatterns[iPat], sAddedCode, re.IGNORECASE):
                        return self.VULNERABILITY_TYPE_MAP.get(sPatchType, 'unknown')
                    iPat = iPat + 1
            iIdx = iIdx + 1
        return 'unknown'

    def _assess_overall_risk(self, diffs):
        iSecCount = 0
        iIdx = 0
        while iIdx < len(diffs):
            if diffs[iIdx].is_security_patch:
                iSecCount = iSecCount + 1
            iIdx = iIdx + 1
        if iSecCount >= 1:
            return 'high'
        else:
            return 'low'

    def _detect_security_patch_type(self, diff):
        iIdx = 0
        while iIdx < len(diff.changes):
            sChange = diff.changes[iIdx]
            if sChange.startswith('Added:'):
                sAddedCode = sChange[6:].strip()
                for sPatchType, dctPatternInfo in self.SECURITY_PATCH_PATTERNS.items():
                    lstPatterns = dctPatternInfo.get('patterns', [])
                    iPat = 0
                    while iPat < len(lstPatterns):
                        if re.search(lstPatterns[iPat], sAddedCode, re.IGNORECASE):
                            return sPatchType
                        iPat = iPat + 1
            iIdx = iIdx + 1
        iIdx = 0
        while iIdx < len(diff.patched_assembly):
            sAsmLine = diff.patched_assembly[iIdx]
            for sPatchType, dctPatternInfo in self.SECURITY_PATCH_PATTERNS.items():
                lstPatterns = dctPatternInfo.get('patterns', [])
                iPat = 0
                while iPat < len(lstPatterns):
                    if re.search(lstPatterns[iPat], sAsmLine, re.IGNORECASE):
                        bFoundInOrig = False
                        iOrig = 0
                        while iOrig < len(diff.original_assembly):
                            if re.search(lstPatterns[iPat], diff.original_assembly[iOrig], re.IGNORECASE):
                                bFoundInOrig = True
                                break
                            iOrig = iOrig + 1
                        if not bFoundInOrig:
                            return sPatchType
                    iPat = iPat + 1
            iIdx = iIdx + 1
        return None

    def _analyze_potential_vulnerabilities(self):
        lstVulnerabilities = []
        iIdx = 0
        while iIdx < len(self.security_patches):
            patch = self.security_patches[iIdx]
            dctVuln = {
                'function': patch.function_name,
                'type': patch.vulnerability_type,
                'severity': self._estimate_severity(patch.vulnerability_type),
                'description': 'Patch addresses ' + patch.vulnerability_type + ' vulnerability',
                'original_address': hex(patch.original_address),
                'patched_address': hex(patch.patched_address),
                'changes': patch.changes[:10],
                'recommendation': self._get_vulnerability_recommendation(patch.vulnerability_type)
            }
            lstVulnerabilities.append(dctVuln)
            iIdx = iIdx + 1
        if self.use_ai and lstVulnerabilities:
            lstVulnerabilities = self._ai_analyze_vulnerabilities(lstVulnerabilities)
        return lstVulnerabilities

    def _estimate_severity(self, vuln_type):
        dctSeverityMap = {
            'buffer_overflow': 'critical', 'integer_overflow': 'high',
            'null_pointer_dereference': 'medium', 'memory_safety': 'high',
            'input_validation': 'medium', 'permission_check': 'high',
            'crypto_security': 'medium', 'error_handling': 'low', 'concurrency_issue': 'high',
        }
        return dctSeverityMap.get(vuln_type, 'medium')

    def _get_vulnerability_recommendation(self, vuln_type):
        dctRecommendations = {
            'buffer_overflow': 'Use safe string functions (strncpy, snprintf); add bounds checks',
            'integer_overflow': 'Use checked arithmetic operations; add overflow guards',
            'null_pointer_dereference': 'Add null pointer check before dereference',
            'memory_safety': 'Use safe memory functions; manage memory lifecycle correctly',
            'input_validation': 'Validate and sanitise all inputs strictly',
            'permission_check': 'Add appropriate permission checks and access control',
            'crypto_security': 'Use modern cryptographic algorithms; avoid hard-coded secrets',
            'error_handling': 'Implement proper error handling; avoid resource leaks',
            'concurrency_issue': 'Use appropriate synchronisation primitives; avoid data races',
        }
        return dctRecommendations.get(vuln_type, 'Apply fix appropriate to patch content')

    def _ai_analyze_vulnerabilities(self, vulnerabilities):
        try:
            dctContext = {
                'vulnerabilities': vulnerabilities,
                'security_patches': [{'function': p.function_name, 'type': p.vulnerability_type, 'changes': p.changes[:5]} for p in self.security_patches]
            }
            from prompts import PATCH_DIFF_ANALYSIS_TEMPLATE
            sResult = call_ai_with_retry(
                model=get_current_ai_model(),
                messages=[{"role": "system", "content": PATCH_DIFF_ANALYSIS_TEMPLATE},
                          {"role": "user", "content": json.dumps(dctContext, ensure_ascii=False, indent=2)}],
                temperature=0.2, max_tokens=2000)
            try:
                dctAiAnalysis = json.loads(sResult)
                if isinstance(dctAiAnalysis, list):
                    iIdx = 0
                    while iIdx < len(vulnerabilities):
                        if iIdx < len(dctAiAnalysis):
                            vulnerabilities[iIdx]['ai_analysis'] = dctAiAnalysis[iIdx].get('analysis', '')
                        iIdx = iIdx + 1
            except json.JSONDecodeError:
                iIdx = 0
                while iIdx < len(vulnerabilities):
                    vulnerabilities[iIdx]['ai_analysis'] = sResult[:500]
                    iIdx = iIdx + 1
        except Exception as e:
            log.error("[PatchDiff] AI analysis failed: %s", e)
        return vulnerabilities

    def _generate_diff_report(self, result=None):
        # 不拆——保持上下文连贯
        if result is not None:
            lstDiffs = result.function_diffs if hasattr(result, 'function_diffs') else []
            lstSecPatches = result.security_patches if hasattr(result, 'security_patches') else []
            sOrigBin = result.original_binary if hasattr(result, 'original_binary') else 'unknown'
            sPatchBin = result.patched_binary if hasattr(result, 'patched_binary') else 'unknown'
        else:
            lstDiffs = self.function_diffs
            lstSecPatches = self.security_patches
            sOrigBin = self.original_binary if self.original_binary is not None else 'unknown'
            sPatchBin = self.patched_binary if self.patched_binary is not None else 'unknown'
        lstLines = [
            'Patch Diff Analysis Report',
            'Original binary:  ' + (os.path.basename(sOrigBin) if sOrigBin != "unknown" else "unknown"),
            'Patched binary:   ' + (os.path.basename(sPatchBin) if sPatchBin != "unknown" else "unknown"),
            'Analysis time:    ' + self._get_timestamp(), '', '=' * 50, '',
            'Function diff statistics:',
            '  - Added:    ' + str(sum(1 for d in lstDiffs if d.diff_type == DiffType.ADDED)),
            '  - Removed:  ' + str(sum(1 for d in lstDiffs if d.diff_type == DiffType.REMOVED)),
            '  - Modified: ' + str(sum(1 for d in lstDiffs if d.diff_type == DiffType.MODIFIED)),
            '', '=' * 50, '', 'Security patch analysis:',
        ]
        if lstSecPatches:
            iIdx = 0
            while iIdx < len(lstSecPatches):
                patch = lstSecPatches[iIdx]
                lstLines.extend([
                    '', 'Function: ' + patch.function_name,
                    '  Type:             ' + patch.vulnerability_type,
                    '  Original address: ' + hex(patch.original_address),
                    '  Patched address:  ' + hex(patch.patched_address),
                    '  Signature score:  ' + '{:.2f}'.format(patch.signature_score),
                    '  Changes:',
                ])
                iCh = 0
                while iCh < len(patch.changes) and iCh < 5:
                    lstLines.append('    ' + patch.changes[iCh])
                    iCh = iCh + 1
                iIdx = iIdx + 1
        else:
            lstLines.append('  No clear security patches identified')
        lstLines.extend(['', '=' * 50, '', 'Detailed function diffs:'])
        iIdx = 0
        iDiffLimit = min(max(len(lstDiffs), 0), 20)
        while iIdx < iDiffLimit:
            diff = lstDiffs[iIdx]
            lstLines.extend(['', 'Function: ' + diff.function_name + ' (' + diff.diff_type.value + ')'])
            if diff.diff_type == DiffType.MODIFIED:
                lstLines.append('  Similarity: ' + '{:.2%}'.format(diff.confidence))
                lstLines.append('  Signature:  ' + '{:.2f}'.format(diff.signature_score))
                if diff.original_assembly and diff.patched_assembly:
                    lstLines.append('  Original assembly:')
                    iAsm = 0
                    while iAsm < len(diff.original_assembly) and iAsm < 3:
                        lstLines.append('    ' + diff.original_assembly[iAsm])
                        iAsm = iAsm + 1
                    lstLines.append('  Patched assembly:')
                    iAsm = 0
                    while iAsm < len(diff.patched_assembly) and iAsm < 3:
                        lstLines.append('    ' + diff.patched_assembly[iAsm])
                        iAsm = iAsm + 1
            iIdx = iIdx + 1
        return '\n'.join(lstLines)

    def _generate_summary(self):
        iTotalChanges = len(self.function_diffs)
        iSecCount = len(self.security_patches)
        lstLines = [
            'Patch Diff Analysis Summary',
            'Functions changed: ' + str(iTotalChanges),
            'Security patches identified: ' + str(iSecCount),
        ]
        if self.security_patches:
            dctVulnTypes = defaultdict(int)
            iIdx = 0
            while iIdx < len(self.security_patches):
                dctVulnTypes[self.security_patches[iIdx].vulnerability_type] += 1
                iIdx = iIdx + 1
            lstLines.append('')
            lstLines.append('Vulnerability type distribution:')
            lstSorted = sorted(list(dctVulnTypes.items()), key=lambda x: x[1], reverse=True)
            iIdx = 0
            while iIdx < len(lstSorted):
                sVulnType = lstSorted[iIdx][0]
                iCount = lstSorted[iIdx][1]
                lstLines.append('  - ' + sVulnType + ': ' + str(iCount))
                iIdx = iIdx + 1
        return '\n'.join(lstLines)

    def _get_timestamp(self):
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _save_results(self):
        sReportPath = os.path.join(self.output_dir, 'patch_diff_report.txt')
        with open(sReportPath, 'w', encoding='utf-8') as f:
            f.write(self._generate_diff_report())
        sJsonPath = os.path.join(self.output_dir, 'patch_diff_result.json')
        dctResult = {
            'original_binary': self.original_binary, 'patched_binary': self.patched_binary,
            'function_diffs': [{'function_name': d.function_name, 'diff_type': d.diff_type,
                'is_security_patch': d.is_security_patch, 'vulnerability_type': d.vulnerability_type,
                'signature_score': d.signature_score} for d in self.function_diffs],
            'security_patches': [{'function_name': p.function_name, 'vulnerability_type': p.vulnerability_type,
                'changes': p.changes} for p in self.security_patches]
        }
        with open(sJsonPath, 'w', encoding='utf-8') as f:
            json.dump(dctResult, f, ensure_ascii=False, indent=2)
        log.info("[PatchDiff] Results saved: %s", self.output_dir)

    def analyze_source_patch(self, patch_file):
        dctResult = {'patch_file': patch_file, 'changes': [], 'security_changes': [], 'affected_functions': []}
        try:
            with open(patch_file, 'r', encoding='utf-8', errors='ignore') as f:
                sPatchContent = f.read()
            lstChanges = self._parse_patch_file(sPatchContent)
            dctResult['changes'] = lstChanges
            iIdx = 0
            while iIdx < len(lstChanges):
                dctChange = lstChanges[iIdx]
                for sPatchType, dctPatternInfo in self.SECURITY_PATCH_PATTERNS.items():
                    lstPatterns = dctPatternInfo.get('patterns', [])
                    iPat = 0
                    while iPat < len(lstPatterns):
                        if re.search(lstPatterns[iPat], dctChange.get('content', ''), re.IGNORECASE):
                            dctChange['security_type'] = sPatchType
                            dctChange['vulnerability_type'] = self.VULNERABILITY_TYPE_MAP.get(sPatchType, 'unknown')
                            dctResult['security_changes'].append(dctChange)
                            break
                        iPat = iPat + 1
                iIdx = iIdx + 1
                iIdx2 = 0
                while iIdx2 < len(lstChanges):
                    sFuncName = lstChanges[iIdx2].get('function', '')
                    if sFuncName and sFuncName in self.original_functions:
                        dctResult['affected_functions'].append(sFuncName)
                    iIdx2 = iIdx2 + 1
        except FileNotFoundError:
            log.error("[PatchDiff] Patch file not found: %s", patch_file)
        except Exception as e:
            log.error("[PatchDiff] Patch file analysis failed: %s", e)
        return dctResult

    def _parse_patch_file(self, content):
        lstChanges = []
        sCurrentFile = ''
        sCurrentFunction = ''
        iIdx = 0
        lstLines = content.split('\n')
        while iIdx < len(lstLines):
            sLine = lstLines[iIdx]
            if sLine.startswith('diff --git'):
                lstParts = sLine.split()
                if len(lstParts) >= 4:
                    sCurrentFile = lstParts[2].replace('a/', '')
            elif sLine.startswith('@@'):
                match = re.search(r'@@.*@@\s*(.*)', sLine)
                if match:
                    sCurrentFunction = match.group(1).strip()
            elif sLine.startswith('+') and not sLine.startswith('++'):
                lstChanges.append({'type': 'added', 'file': sCurrentFile, 'function': sCurrentFunction, 'content': sLine[1:].strip()})
            elif sLine.startswith('-') and not sLine.startswith('--'):
                lstChanges.append({'type': 'removed', 'file': sCurrentFile, 'function': sCurrentFunction, 'content': sLine[1:].strip()})
            iIdx = iIdx + 1
        return lstChanges

    def generate_side_by_side_diff(self, function_name):
        diff = None
        iIdx = 0
        while iIdx < len(self.function_diffs):
            if self.function_diffs[iIdx].function_name == function_name:
                diff = self.function_diffs[iIdx]
                break
            iIdx = iIdx + 1
        if diff is None:
            return 'Function ' + function_name + ' — no diff found'
        lstLines = ['Function ' + function_name + ' — side-by-side diff', '',
                    '{:<40} | {:<40}'.format('Original', 'Patched'),
                    '{:<40} | {:<40}'.format('-'*40, '-'*40)]
        lstOrigLines = diff.original_assembly[:30]
        lstPatchLines = diff.patched_assembly[:30]
        iMax = len(lstOrigLines)
        if len(lstPatchLines) > iMax:
            iMax = len(lstPatchLines)
        iIdx = 0
        while iIdx < iMax:
            sOrig = lstOrigLines[iIdx] if iIdx < len(lstOrigLines) else ''
            sPatch = lstPatchLines[iIdx] if iIdx < len(lstPatchLines) else ''
            if sOrig != sPatch:
                if not sOrig:
                    lstLines.append('{:<40} | {:<40}'.format('(added)', sPatch))
                elif not sPatch:
                    lstLines.append('{:<40} | {:<40}'.format(sOrig, '(removed)'))
                else:
                    lstLines.append('{:<40} | {:<40}'.format(sOrig, sPatch))
            else:
                lstLines.append('{:<40} | {:<40}'.format(sOrig, sPatch))
            iIdx = iIdx + 1
        return '\n'.join(lstLines)

    def to_dict(self):
        return {
            'original_binary': self.original_binary, 'patched_binary': self.patched_binary,
            'function_diff_count': len(self.function_diffs), 'security_patch_count': len(self.security_patches),
            'function_diffs': [{'function_name': d.function_name, 'diff_type': d.diff_type,
                'is_security_patch': d.is_security_patch, 'vulnerability_type': d.vulnerability_type,
                'signature_score': d.signature_score} for d in self.function_diffs[:50]],
            'security_patches': [{'function_name': p.function_name, 'vulnerability_type': p.vulnerability_type,
                'severity': self._estimate_severity(p.vulnerability_type)} for p in self.security_patches],
            'summary': self._generate_summary()
        }

def analyze_patch_diff(original_binary, patched_binary, output_dir=None, use_ai=True):
    locator = PatchDiffLocator(original_binary, patched_binary, output_dir, use_ai)
    return locator.analyze()

def locate_patch_diff(original_binary, patched_binary, output_dir=None, use_ai=True):
    try:
        locator = PatchDiffLocator(original_binary, patched_binary, output_dir, use_ai)
        result = locator.analyze()
        return {
            'success': True,
            'original_binary': result.original_binary, 'patched_binary': result.patched_binary,
            'function_diff_count': len(result.function_diffs), 'security_patch_count': len(result.security_patches),
            'summary': result.summary, 'diff_report': result.diff_report,
            'function_diffs': [{'function_name': d.function_name, 'diff_type': d.diff_type,
                'is_security_patch': d.is_security_patch, 'vulnerability_type': d.vulnerability_type}
                for d in result.function_diffs],
            'security_patches': [{'function_name': p.function_name, 'vulnerability_type': p.vulnerability_type}
                for p in result.security_patches]
        }
    except Exception as e:
        log.error("Patch diff locate failed: %s", e)
        return {'success': False, 'error': str(e)}
