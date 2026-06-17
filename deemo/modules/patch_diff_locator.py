"""
二进制补丁比对与1-day漏洞定位模块

当有软件安全补丁的源码或二进制时，自动比对补丁前后的差异，
精确定位漏洞点和补丁逻辑，辅助逆向工程师快速分析1-day漏洞。
"""

import logging
import os
import re
import subprocess
import json
import difflib
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from config import Config, ensure_directories, get_current_ai_model, call_ai_with_retry

logger = logging.getLogger(__name__)


# 安全补丁特征模式
SECURITY_PATCH_PATTERNS = {
    # 空指针检查 - 放在前面，因为更具体
    'null_check': {
        'keywords': [
            'NULL', 'null', 'assert', 'test', 'cmp'
        ],
        'patterns': [
            r'if\s*\(\s*\w+\s*!=\s*NULL\s*\)',
            r'if\s*\(\s*\w+\s*==\s*NULL\s*\)',
            r'if\s*\(\s*\w+\s*!=\s*null\s*\)',
            r'if\s*\(\s*\w+\s*==\s*null\s*\)',
            r'test\s+.*,\s*null',
            r'cmp\s+.*,\s*0\s*;\s*null',
            r'assert\s*\(\s*\w+\s*\)',
            r'NULL\s+pointer\s+check',
            r'null\s+pointer\s+check',
        ]
    },
    
    # 输入验证 - 放在前面，因为更具体
    'input_validation': {
        'keywords': [
            'validate', 'sanitize', 'escape', 'filter', 'check', 'reject', 
            'is_valid', 'is_safe'
        ],
        'patterns': [
            r'validate_input\s*\(')
            r'sanitize\s*\(')
            r'escape\s*\(')
            r'filter\s*\(')
            r'is_valid\s*\(')
            r'is_safe\s*\(')
        ]
    },
    
    # 边界检查添加
    'boundary_check': {
        'keywords': [
            'cmp', 'test', 'check', 'validate', 'length', 'index', 'size', 
            'max', 'assert', 'CHECK', 'VALIDATE', 'if', '<', '>', '==', '!=',
            'strlen', 'sizeof', 'strncpy', 'snprintf', 'memcpy'
        ],
        'patterns': [
            r'cmp\s+.*,\s*.*\s*;\s*check',
            r'test\s+.*,\s*.*\s*;\s*validate',
            r'strlen\s*\([^)]+\)\s*[<>=!]+\s*\d+',
            r'sizeof\s*\(')
            r'length\s*[<>=!]+\s*\d+',
            r'size\s*[<>=!]+\s*\d+',
            r'index\s*[<>=!]+\s*len',
            r'assert\s*\(')
            r'CHECK\s*\(')
            r'VALIDATE\s*\(')
            r'length\s+check',
            r'boundary\s+check',
        ]
    },
    
    # 内存安全
    'memory_safety': {
        'keywords': [
            'memcpy', 'memmove', 'strncpy', 'snprintf', 'malloc', 'free', 
            'realloc', 'alloca', '__builtin_object_size', '__stack_chk_fail', 'fortify'
        ],
        'patterns': [
            r'memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
            r'memmove\s*\(')
            r'strncpy\s*\(')
            r'snprintf\s*\(')
            r'malloc\s*\([^)]+\)',
            r'free\s*\(')
            r'realloc\s*\(')
            r'alloca\s*\(')
            r'__builtin_object_size',
            r'__stack_chk_fail',
            r'fortify',
        ]
    },
    
    # 整数溢出检查
    'integer_overflow': {
        'keywords': [
            'overflow', 'wrap', 'INT_MAX', 'SIZE_MAX', '__builtin_add_overflow', 
            '__builtin_mul_overflow', 'add', 'sub', 'mul', 'limit', 'max', 'min'
        ],
        'patterns': [
            r'overflow\s*check',
            r'wrap\s*around',
            r'add\s*>\s*max',
            r'sub\s*<\s*min',
            r'mul\s*>\s*limit',
            r'__builtin_add_overflow',
            r'__builtin_mul_overflow',
            r'INT_MAX',
            r'SIZE_MAX',
        ]
    },
    
    # 权限检查
    'permission_check': {
        'keywords': [
            'permission', 'auth', 'authorize', 'check_privilege', 'is_admin', 
            'has_permission', 'access', 'control'
        ],
        'patterns': [
            r'permission\s*check',
            r'auth\s*\(')
            r'authorize\s*\(')
            r'check_privilege',
            r'is_admin',
            r'has_permission',
            r'access\s*control',
        ]
    },
    
    # 加密/安全
    'crypto_security': {
        'keywords': [
            'encrypt', 'decrypt', 'hash', 'sign', 'verify', 'random', 
            'secure', 'constant_time'
        ],
        'patterns': [
            r'encrypt\s*\(')
            r'decrypt\s*\(')
            r'hash\s*\(')
            r'sign\s*\(')
            r'verify\s*\(')
            r'random\s*\(')
            r'secure\s*\(')
            r'constant_time',
        ]
    },
    
    # 错误处理
    'error_handling': {
        'keywords': [
            'return', 'error', 'goto', 'catch', 'try', 'exception', 'fail', 'abort'
        ],
        'patterns': [
            r'return\s*-1',
            r'return\s*error',
            r'goto\s*error',
            r'catch\s*\(')
            r'try\s*\{',
            r'exception',
            r'fail\s*\(')
            r'abort\s*\(')
        ]
    },
    
    # 锁/同步
    'lock_sync': {
        'keywords': [
            'lock', 'unlock', 'mutex', 'semaphore', 'spinlock', 'atomic', 
            'barrier', 'sync'
        ],
        'patterns': [
            r'lock\s*\(')
            r'unlock\s*\(')
            r'mutex\s*\(')
            r'semaphore',
            r'spinlock',
            r'atomic',
            r'barrier',
            r'sync\s*\(')
        ]
    },
}

# 漏洞类型映射
VULNERABILITY_TYPE_MAP = {
    'boundary_check': 'buffer_overflow',
    'input_validation': 'input_validation',
    'memory_safety': 'memory_safety',
    'integer_overflow': 'integer_overflow',
    'null_check': 'null_pointer_dereference',
    'permission_check': 'permission_check',
    'crypto_security': 'crypto_security',
    'error_handling': 'error_handling',
    'lock_sync': 'concurrency_issue',
}


class DiffType(Enum):
    """差异类型枚举"""
    ADDED = 'added'
    REMOVED = 'removed'
    MODIFIED = 'modified'
    MOVED = 'moved'
    UNKNOWN = 'unknown'
    ASSEMBLY = 'assembly'
    PSEUDO_CODE = 'pseudo_code'
    BINARY = 'binary'


@dataclass
class FunctionDiff:
    """函数差异数据类"""
    function_name: str
    diff_type: DiffType
    original_address: int = 0
    patched_address: int = 0
    original_size: int = 0
    patched_size: int = 0
    original_code: str = ''
    patched_code: str = ''
    original_assembly: List[str] = field(default_factory=lambda: [])
    patched_assembly: List[str] = field(default_factory=lambda: [])
    changes: List[str] = field(default_factory=lambda: [])
    is_security_patch: bool = False
    vulnerability_type: str = ''
    confidence: float = 0.0


@dataclass
class PatchAnalysisResult:
    """补丁分析结果数据类"""
    original_binary: str
    patched_binary: str
    function_diffs: List[FunctionDiff] = field(default_factory=lambda: [])
    security_patches: List[FunctionDiff] = field(default_factory=lambda: [])
    potential_vulnerabilities: List[Dict[str, Any]] = field(default_factory=lambda: [])
    summary: str = ''
    diff_report: str = ''
    vulnerability_summary: Dict[str, int] = field(default_factory=lambda: dict)
    overall_risk: str = ''
    error: Optional[str] = None


class PatchDiffLocator:
    """
    补丁差异定位器
    
    分析补丁前后二进制文件的差异，定位安全补丁和潜在漏洞。
    """
    
    SECURITY_PATCH_PATTERNS = SECURITY_PATCH_PATTERNS
    VULNERABILITY_TYPE_MAP = VULNERABILITY_TYPE_MAP
    
    def __init__(, self)
        original_binary: str = None,
        patched_binary: str = None,
        output_dir: str = None,
        use_ai: bool = True
    ):
        """
        初始化补丁差异定位器
        
        Args:
            original_binary: 原始二进制文件路径
            patched_binary: 补丁后二进制文件路径
            output_dir: 输出目录
            use_ai: 是否使用 AI 辅助分析
        """
        self.original_binary = original_binary
        self.patched_binary = patched_binary
        
        # 处理 Config.REPORTS_DIR 可能不存在的情况
        try:
            default_output_dir = os.path.join(Config.REPORTS_DIR, 'patch_diff')
        except AttributeError:
            default_output_dir = os.path.join(os.path.expanduser('~'), '.binmind', 'patch_diff')
        
        self.output_dir = output_dir or default_output_dir
        self.use_ai = use_ai
        
        try:
            ensure_directories(self.output_dir)
        except Exception:
            # 如果 ensure_directories 失败，使用临时目录
            import tempfile
            self.output_dir = tempfile.mkdtemp()
        
        self.original_functions: Dict[str, Dict[str, Any]] = {}
        self.patched_functions: Dict[str, Dict[str, Any]] = {}
        self.function_diffs: List[FunctionDiff] = []
        self.security_patches: List[FunctionDiff] = []
    
    def analyze(self, original_binary: str = None, patched_binary: str = None) -> PatchAnalysisResult:
        """
        执行补丁差异分析
        
        Args:
            original_binary: 原始二进制文件路径（可选，优先使用构造时的值）
            patched_binary: 补丁后二进制文件路径（可选，优先使用构造时的值）
            
        Returns:
            PatchAnalysisResult 分析结果
        """
        # 使用参数或构造时的值
        if original_binary is not None:
            self.original_binary = original_binary,
        if patched_binary is not None:
            self.patched_binary = patched_binary
            
        logger.info(f"[PatchDiff] 分析补丁差异: {self.original_binary} -> {self.patched_binary}")
        
        error = None
        
        # 验证输入
        if not self.original_binary or not self.patched_binary:
            error = "原始文件或补丁文件路径为空",
            return PatchAnalysisResult(
                original_binary=self.original_binary or '',
                patched_binary=self.patched_binary or '',
                error=error)
            

        
        # 检查路径遍历攻击
        import os
        original_path = os.path.abspath(self.original_binary)
        patched_path = os.path.abspath(self.patched_binary)
        
        if '..' in self.original_binary or '..' in self.patched_binary:
            error = "检测到路径遍历攻击",
            return PatchAnalysisResult(
                original_binary=self.original_binary,
                patched_binary=self.patched_binary,
                error=error)
            

        
        # 检查文件是否存在
        if not os.path.exists(self.original_binary):
            error = f"原始文件不存在: {self.original_binary}"
        
        if not os.path.exists(self.patched_binary):
            if error:
                error += f", 补丁文件不存在: {self.patched_binary}"
            else:
                error = f"补丁文件不存在: {self.patched_binary}"
        
        if error:
            return PatchAnalysisResult(
                original_binary=self.original_binary,
                patched_binary=self.patched_binary,
                error=error)
            

        
        try:
            # 提取函数信息
            self._extract_functions()
            
            # 比对函数
            self._compare_functions()
            
            # 识别安全补丁
            self._identify_security_patches()
            
            # 分析潜在漏洞
            vulnerabilities = self._analyze_potential_vulnerabilities()
            
            # 生成差异报告
            diff_report = self._generate_diff_report()
            
            # 生成摘要
            summary = self._generate_summary()
            
            # 保存结果
            self._save_results()
            
            return PatchAnalysisResult(
                original_binary=self.original_binary,
                patched_binary=self.patched_binary,
                function_diffs=self.function_diffs,
                security_patches=self.security_patches,
                potential_vulnerabilities=vulnerabilities,
                summary=summary,
                diff_report=diff_report)
            

        except Exception as e:
            logger.error(f"[PatchDiff] 分析失败: {e}")
            return PatchAnalysisResult(
                original_binary=self.original_binary,
                patched_binary=self.patched_binary,
                error=str(e))
            

    
    def _extract_functions(self) -> None:
        """
        提取两个二进制文件的函数信息
        """
        self.original_functions = self._get_functions_from_binary(self.original_binary)
        self.patched_functions = self._get_functions_from_binary(self.patched_binary)
        
        logger.info(f"[PatchDiff] 原始二进制: {len(self.original_functions)} 个函数")
        logger.info(f"[PatchDiff] 补丁二进制: {len(self.patched_functions)} 个函数")
    
    def _get_functions_from_binary(self, binary_path: str) -> Dict[str, Dict[str, Any]]:
        """
        从二进制文件获取函数信息
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            函数信息字典
        """
        functions = {}
        
        try:
            # 使用 radare2 获取函数列表和反汇编
            result = subprocess.run()
                ['r2', '-q', '-c', 'afl; s main; pdf', binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            
            
            if result.returncode == 0:
                self._parse_radare2_functions(result.stdout, functions, binary_path)
            
            # 获取每个函数的反汇编代码
            for func_name in list(functions.keys())[:50]:
                func_addr = functions[func_name].get('address', 0)
                if func_addr:
                    disasm = self._get_function_disassembly(binary_path, func_addr)
                    functions[func_name]['assembly'] = disasm
            
        except subprocess.TimeoutExpired:
            logger.warning(f"[PatchDiff] radare2 分析超时: {binary_path}")
        except FileNotFoundError:
            logger.warning("[PatchDiff] radare2 未安装")
        except Exception as e:
            logger.error(f"[PatchDiff] 函数提取失败: {e}")
        
        return functions
    
    def _parse_radare2_functions(self, output: str, functions: Dict, binary_path: str) -> None:
        """
        解析 radare2 函数输出
        
        Args:
            output: radare2 输出
            functions: 函数字典
            binary_path: 二进制路径
        """
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 5:
                try:
                    # 解析函数信息
                    addr = int(parts[0], 16) if parts[0].startswith('0x') else 0
                    size = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1]) if parts[1].isdigit() else 0
                    name = parts[-1]
                    
                    if name.startswith('sym.'):
                        name = name[4:]
                    if name.startswith('fcn.'):
                        name = name[4:]
                    
                    functions[name] = {
                        'address': addr,
                        'size': size,
                        'binary': binary_path,
                        'assembly': []
                    }
                except (ValueError, IndexError):
                    continue
    
    def _get_function_disassembly(self, binary_path: str, address: int) -> List[str]:
        """
        获取函数反汇编代码
        
        Args:
            binary_path: 二进制路径
            address: 函数地址
            
        Returns:
            反汇编指令列表
        """
        disasm = []
        
        try:
            result = subprocess.run()
                ['r2', '-q', '-c', f's {hex(address)}; pdf', binary_path],
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    # 提取汇编指令
                    if line and not line.startswith(';') and not line.startswith('|'):
                        parts = line.split()
                        if len(parts) >= 2:
                            disasm.append(line.strip(

            
        except Exception as e:
            logger.debug(f"[PatchDiff] 反汇编获取失败: {e}")
        
        return disasm
    
    def _compare_functions(self) -> None:
        """
        比对两个二进制文件的函数
        """
        original_names = set(self.original_functions.keys(

        patched_names = set(self.patched_functions.keys(

        
        # 新增的函数
        added = patched_names - original_names,
        for name in added:
            diff = FunctionDiff()
                function_name=name,
                diff_type=DiffType.ADDED,
                patched_address=self.patched_functions[name].get('address', 0),
                patched_size=self.patched_functions[name].get('size', 0),
                patched_assembly=self.patched_functions[name].get('assembly', [])
            
            self.function_diffs.append(diff)
        
        # 移除的函数
        removed = original_names - patched_names,
        for name in removed:
            diff = FunctionDiff()
                function_name=name,
                diff_type=DiffType.REMOVED,
                original_address=self.original_functions[name].get('address', 0),
                original_size=self.original_functions[name].get('size', 0),
                original_assembly=self.original_functions[name].get('assembly', [])
            
            self.function_diffs.append(diff)
        
        # 修改的函数
        common = original_names & patched_names,
        for name in common:
            orig_asm = self.original_functions[name].get('assembly', [])
            patch_asm = self.patched_functions[name].get('assembly', [])
            
            # 比较汇编代码
            if orig_asm and patch_asm:
                similarity = self._calculate_similarity(orig_asm, patch_asm)
                
                if similarity < 0.95:  # 有显著变化
                    changes = self._find_code_changes(orig_asm, patch_asm)
                    
                    diff = FunctionDiff()
                        function_name=name,
                        diff_type=DiffType.MODIFIED,
                        original_address=self.original_functions[name].get('address', 0),
                        patched_address=self.patched_functions[name].get('address', 0),
                        original_size=self.original_functions[name].get('size', 0),
                        patched_size=self.patched_functions[name].get('size', 0),
                        original_assembly=orig_asm,
                        patched_assembly=patch_asm,
                        changes=changes,
                        confidence=similarity
                    
                    self.function_diffs.append(diff)
    
    def _calculate_similarity(self, list1: List[str], list2: List[str]) -> float:
        """
        计算两个列表的相似度
        
        Args:
            list1: 第一个列表
            list2: 第二个列表
            
        Returns:
            相似度 (0-1)
        """
        if not list1 or not list2:
            return 0.0
        
        # 使用 difflib 计算相似度
        matcher = difflib.SequenceMatcher(None, list1, list2)
        return matcher.ratio()
    
    def _find_code_changes(self, original: List[str], patched: List[str]) -> List[str]:
        """
        找出代码变化
        
        Args:
            original: 原始代码
            patched: 补丁代码
            
        Returns:
            变化描述列表
        """
        changes = []
        
        # 使用 difflib 找出差异
        diff = difflib.unified_diff(original, patched, lineterm='')
        
        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                changes.append(f'添加: {line[1:].strip()}')
            elif line.startswith('-') and not line.startswith('---'):
                changes.append(f'删除: {line[1:].strip()}')
        
        return changes[:50]  # 限制数量
    
    def _identify_security_patches(self) -> None:
        """
        识别安全补丁
        """
        for diff in self.function_diffs:
            if diff.diff_type == DiffType.MODIFIED:
                # 分析变化内容
                security_type = self._detect_security_patch_type(diff)
                
                if security_type:
                    diff.is_security_patch = True
                    diff.vulnerability_type = self.VULNERABILITY_TYPE_MAP.get(security_type, '未知')
                    self.security_patches.append(diff)
                    
                    logger.info(f"[PatchDiff] 发现安全补丁: {diff.function_name} ({diff.vulnerability_type})")
    
    def _detect_security_patch(self, original: str, patched: str) -> tuple:
        """
        检测安全补丁
        
        Args:
            original: 原始代码
            patched: 补丁后代码
            
        Returns:
            (is_security, vulnerability_type)
        """
        is_security = False
        vuln_type = 'unknown'
        
        original_lines = original.split('\n')
        patched_lines = patched.split('\n')
        
        changes = self._find_code_changes(original_lines, patched_lines)
        
        for change in changes:
            if change.startswith('添加:'):
                added_code = change[3:].strip()
                
                for patch_type, pattern_info in self.SECURITY_PATCH_PATTERNS.items():
                    for pattern in pattern_info.get('patterns', []):
                        if re.search(pattern, added_code, re.IGNORECASE):
                            is_security = True
                            vuln_type = self.VULNERABILITY_TYPE_MAP.get(patch_type, 'unknown')
                            return (is_security, vuln_type)
        
        return (is_security, vuln_type)
    
    def _extract_diff_changes(self, original_lines: List[str], patched_lines: List[str]) -> List[str]:
        """
        提取差异变更
        
        Args:
            original_lines: 原始代码行列表
            patched_lines: 补丁后代码行列表
            
        Returns:
            变更列表
        """
        return self._find_code_changes(original_lines, patched_lines)
    
    def _match_functions(self, original_funcs: List[Dict], patched_funcs: List[Dict]) -> List[Dict]:
        """
        匹配函数
        
        Args:
            original_funcs: 原始函数列表
            patched_funcs: 补丁后函数列表
            
        Returns:
            匹配结果列表
        """
        matches = []
        orig_names = {f['name']: f for f in original_funcs}
        
        for func in patched_funcs:
            if func['name'] in orig_names:
                matches.append({)
                    'name': func['name'],
                    'original_address': orig_names[func['name']]['address'],
                    'patched_address': func['address']
                }
        
        return matches
    
    def _identify_vulnerability_type(self, changes: List[str]) -> str:
        """
        识别漏洞类型
        
        Args:
            changes: 变更列表
            
        Returns:
            漏洞类型
        """
        for change in changes:
            # 处理以 '添加:' 开头的变化（来自 _find_code_changes）
            if change.startswith('添加:'):
                added_code = change[3:].strip()
            else:
                # 直接使用变化内容
                added_code = change.strip()
                
            for patch_type, pattern_info in self.SECURITY_PATCH_PATTERNS.items():
                for pattern in pattern_info.get('patterns', []):
                    if re.search(pattern, added_code, re.IGNORECASE):
                        return self.VULNERABILITY_TYPE_MAP.get(patch_type, 'unknown')
        
        return 'unknown'
    
    def _assess_overall_risk(self, diffs: List[FunctionDiff]) -> str:
        """
        评估整体风险
        
        Args:
            diffs: 函数差异列表
            
        Returns:
            风险等级
        """
        security_count = sum(1 for d in diffs if d.is_security_patch)
        
        if security_count >= 1:
            return 'high'
        else:
            return 'low'
    
    def _detect_security_patch_type(self, diff: FunctionDiff) -> Optional[str]:
        """
        检测安全补丁类型
        
        Args:
            diff: 函数差异
            
        Returns:
            安全补丁类型
        """
        # 检查添加的代码是否匹配安全模式
        for change in diff.changes:
            if change.startswith('添加:'):
                added_code = change[3:].strip()
                
                for patch_type, pattern_info in self.SECURITY_PATCH_PATTERNS.items():
                    for pattern in pattern_info.get('patterns', []):
                        if re.search(pattern, added_code, re.IGNORECASE):
                            return patch_type
        
        # 检查补丁后的汇编代码
        for asm_line in diff.patched_assembly:
            for patch_type, pattern_info in self.SECURITY_PATCH_PATTERNS.items():
                for pattern in pattern_info.get('patterns', []):
                    if re.search(pattern, asm_line, re.IGNORECASE):
                        # 检查是否在原始代码中不存在
                        found_in_orig = False,
                        for orig_line in diff.original_assembly:
                            if re.search(pattern, orig_line, re.IGNORECASE):
                                found_in_orig = True
                                break
                        
                        if not found_in_orig:
                            return patch_type
        
        return None
    
    def _analyze_potential_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        分析潜在漏洞
        
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        for patch in self.security_patches:
            vuln = {
                'function': patch.function_name,
                'type': patch.vulnerability_type,
                'severity': self._estimate_severity(patch.vulnerability_type),
                'description': f'补丁修复了 {patch.vulnerability_type} 问题',
                'original_address': hex(patch.original_address),
                'patched_address': hex(patch.patched_address),
                'changes': patch.changes[:10],
                'recommendation': self._get_vulnerability_recommendation(patch.vulnerability_type)
            }
            
            vulnerabilities.append(vuln)
        
        # 使用 AI 进一步分析
        if self.use_ai and vulnerabilities:
            vulnerabilities = self._ai_analyze_vulnerabilities(vulnerabilities)
        
        return vulnerabilities
    
    def _estimate_severity(self, vuln_type: str) -> str:
        """
        估计漏洞严重程度
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            严重程度
        """
        severity_map = {
            'buffer_overflow': 'critical',
            'integer_overflow': 'high',
            'null_pointer_dereference': 'medium',
            'memory_safety': 'high',
            'input_validation': 'medium',
            'permission_check': 'high',
            'crypto_security': 'medium',
            'error_handling': 'low',
            'concurrency_issue': 'high',
        }
        
        return severity_map.get(vuln_type, 'medium')
    
    def _get_vulnerability_recommendation(self, vuln_type: str) -> str:
        """
        获取漏洞修复建议
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            修复建议
        """
        recommendations = {
            'buffer_overflow': '使用安全的字符串函数（strncpy, snprintf），添加边界检查',
            'integer_overflow': '使用安全的整数运算函数，添加溢出检查',
            'null_pointer_dereference': '在使用指针前添加空指针检查',
            'memory_safety': '使用内存安全函数，正确管理内存生命周期',
            'input_validation': '对所有输入进行严格验证和过滤',
            'permission_check': '添加适当的权限验证和访问控制',
            'crypto_security': '使用现代加密算法，避免硬编码密钥',
            'error_handling': '完善错误处理逻辑，避免资源泄漏',
            'concurrency_issue': '使用适当的同步机制，避免数据竞争',
        }
        
        return recommendations.get(vuln_type, '根据补丁内容进行相应修复')
    
    def _ai_analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        使用 AI 分析漏洞
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            增强后的漏洞列表
        """
        try:
            context = {
                'vulnerabilities': vulnerabilities,
                'security_patches': [
                    {
                        'function': p.function_name,
                        'type': p.vulnerability_type,
                        'changes': p.changes[:5]
                    }
                    for p in self.security_patches
                ]
            }
            
            from prompts import PATCH_DIFF_ANALYSIS_TEMPLATE
            
            result = call_ai_with_retry()
                model=get_current_ai_model(),
                messages=[
                    {"role": "system", "content": PATCH_DIFF_ANALYSIS_TEMPLATE},
                    {"role": "user", "content": json.dumps(context, ensure_ascii=False, indent=2)}
                ],
                temperature=0.2,
                max_tokens=2000
            
            
            # 解析 AI 结果
            try:
                ai_analysis = json.loads(result)
                if isinstance(ai_analysis, list):
                    # 合合 AI 分析结果
                    for i, vuln in enumerate(vulnerabilities):
                        if i < len(ai_analysis):
                            vuln['ai_analysis'] = ai_analysis[i].get('analysis', '')
            except json.JSONDecodeError:
                # AI 返回的不是 JSON，添加为文本
                for vuln in vulnerabilities:
                    vuln['ai_analysis'] = result[:500]
            
        except Exception as e:
            logger.error(f"[PatchDiff] AI 分析失败: {e}")
        
        return vulnerabilities
    
    def _generate_diff_report(self, result=None) -> str:
        """
        生成差异报告
        
        Args:
            result: 可选的分析结果（用于测试）
            
        Returns:
            差异报告字符串
        """
        # 使用传入的结果或当前实例的结果
        if result is not None:
            diffs = result.function_diffs if hasattr(result, 'function_diffs') else []
            security_patches = result.security_patches if hasattr(result, 'security_patches') else []
            original_binary = result.original_binary if hasattr(result, 'original_binary') else 'unknown'
            patched_binary = result.patched_binary if hasattr(result, 'patched_binary') else 'unknown'
        else:
            diffs = self.function_diffs
            security_patches = self.security_patches
            original_binary = self.original_binary or 'unknown'
            patched_binary = self.patched_binary or 'unknown'
        
        lines = [
            f'补丁差异分析报告',
            f'原始文件: {os.path.basename(original_binary) if original_binary != "unknown" else "unknown"}',
            f'补丁文件: {os.path.basename(patched_binary) if patched_binary != "unknown" else "unknown"}',
            f'分析时间: {self._get_timestamp()}',
            '',
            '=' * 50,
            '',
            '函数差异统计:',
            f'  - 新增函数: {sum(1 for d in diffs if d.diff_type == DiffType.ADDED)}',
            f'  - 移除函数: {sum(1 for d in diffs if d.diff_type == DiffType.REMOVED)}',
            f'  - 修改函数: {sum(1 for d in diffs if d.diff_type == DiffType.MODIFIED)}',
            '',
            '=' * 50,
            '',
            '安全补丁分析:',
        ]
        
        if security_patches:
            for patch in security_patches:
                lines.extend([)
                    '',
                    f'函数: {patch.function_name}',
                    f'  类型: {patch.vulnerability_type}',
                    f'  原始地址: {hex(patch.original_address)}',
                    f'  补丁地址: {hex(patch.patched_address)}',
                    f'  变化:',
                ]
                for change in patch.changes[:5]:
                    lines.append(f'    {change}')
        else:
            lines.append('  未发现明确的安全补丁')
        
        lines.extend([)
            '',
            '=' * 50,
            '',
            '详细函数差异:',
        ]
        
        for diff in diffs[:20]:
            lines.extend([)
                '',
                f'函数: {diff.function_name} ({diff.diff_type.value})',
            ]
            
            if diff.diff_type == DiffType.MODIFIED:
                lines.append(f'  相似度: {diff.confidence:.2%}')
                
                if diff.original_assembly and diff.patched_assembly:
                    lines.append('  原始汇编:')
                    for asm in diff.original_assembly[:3]:
                        lines.append(f'    {asm}')
                    lines.append('  补丁汇编:')
                    for asm in diff.patched_assembly[:3]:
                        lines.append(f'    {asm}')
        
        return '\n'.join(lines)
    
    def _generate_summary(self) -> str:
        """
        生成摘要
        
        Returns:
            摘要字符串
        """
        total_changes = len(self.function_diffs)
        security_count = len(self.security_patches)
        
        lines = [
            f'补丁差异分析摘要',
            f'发现 {total_changes} 个函数变化',
            f'识别出 {security_count} 个安全补丁',
        ]
        
        if self.security_patches:
            vuln_types = defaultdict(int)
            for patch in self.security_patches:
                vuln_types[patch.vulnerability_type] += 1
            
            lines.append('')
            lines.append('漏洞类型分布:')
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: -x[1]):
                lines.append(f'  - {vuln_type}: {count}')
        
        return '\n'.join(lines)
    
    def _get_timestamp(self) -> str:
        """
        获取当前时间戳
        
        Returns:
            时间戳字符串
        """
        from datetime import datetime
        return datetime.now(.strftime('%Y-%m-%d %H:%M:%S'))
    
    def _save_results(self) -> None:
        """
        保存分析结果
        """
        # 保存差异报告
        report_path = os.path.join(self.output_dir, 'patch_diff_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self._generate_diff_report(

        
        # 保存 JSON 结果
        json_path = os.path.join(self.output_dir, 'patch_diff_result.json')
        result = {
            'original_binary': self.original_binary,
            'patched_binary': self.patched_binary,
            'function_diffs': [
                {
                    'function_name': d.function_name,
                    'diff_type': d.diff_type.value,
                    'is_security_patch': d.is_security_patch,
                    'vulnerability_type': d.vulnerability_type
                }
                for d in self.function_diffs
            ],
            'security_patches': [
                {
                    'function_name': p.function_name,
                    'vulnerability_type': p.vulnerability_type,
                    'changes': p.changes
                }
                for p in self.security_patches
            ]
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        logger.info(f"[PatchDiff] 结果已保存: {self.output_dir}")
    
    def analyze_source_patch(self, patch_file: str) -> Dict[str, Any]:
        """
        分析源码补丁文件
        
        Args:
            patch_file: 补丁文件路径
            
        Returns:
            分析结果
        """
        result = {
            'patch_file': patch_file,
            'changes': [],
            'security_changes': [],
            'affected_functions': []
        }
        
        try:
            with open(patch_file, 'r', encoding='utf-8', errors='ignore') as f:
                patch_content = f.read()
            
            # 解析 patch 文件
            changes = self._parse_patch_file(patch_content)
            result['changes'] = changes
            
            # 识别安全相关变化
            for change in changes:
                for patch_type, pattern_info in self.SECURITY_PATCH_PATTERNS.items():
                    for pattern in pattern_info.get('patterns', []):
                        if re.search(pattern, change.get('content', ''), re.IGNORECASE):
                            change['security_type'] = patch_type
                            change['vulnerability_type'] = self.VULNERABILITY_TYPE_MAP.get(patch_type, 'unknown')
                            result['security_changes'].append(change)
                            break
            
            # 尝试匹配到二进制函数
            for change in changes:
                func_name = change.get('function', '')
                if func_name and func_name in self.original_functions:
                    result['affected_functions'].append(func_name)
            
        except FileNotFoundError:
            logger.error(f"[PatchDiff] 补丁文件不存在: {patch_file}")
        except Exception as e:
            logger.error(f"[PatchDiff] 补丁文件分析失败: {e}")
        
        return result
    
    def _parse_patch_file(self, content: str) -> List[Dict[str, Any]]:
        """
        解析 patch 文件内容
        
        Args:
            content: patch 文件内容
            
        Returns:
            变化列表
        """
        changes = []
        
        # 解析 diff 格式
        current_file = ''
        current_function = ''
        
        for line in content.split('\n'):
            if line.startswith('diff --git'):
                # 新文件差异
                parts = line.split()
                if len(parts) >= 4:
                    current_file = parts[2].replace('a/', '')
            elif line.startswith('@@'):
                # 函数/位置信息
                match = re.search(r'@@.*@@\s*(.*)', line)
                if match:
                    current_function = match.group(1).strip()
            elif line.startswith('+') and not line.startswith('++'):
                # 添加的行
                changes.append({)
                    'type': 'added',
                    'file': current_file,
                    'function': current_function,
                    'content': line[1:].strip()
                }
            elif line.startswith('-') and not line.startswith('--'):
                # 删除的行
                changes.append({)
                    'type': 'removed',
                    'file': current_file,
                    'function': current_function,
                    'content': line[1:].strip()
                }
        
        return changes
    
    def generate_side_by_side_diff(self, function_name: str) -> str:
        """
        生成并排对比视图
        
        Args:
            function_name: 函数名
            
        Returns:
            并排对比字符串
        """
        # 查找函数差异
        diff = None,
        for d in self.function_diffs:
            if d.function_name == function_name:
                diff = d
                break
        
        if not diff:
            return f'函数 {function_name} 未发现差异'
        
        lines = [
            f'函数 {function_name} 并排对比',
            '',
            f'{"原始代码":<40} | {"补丁代码":<40}',
            f'{"-"*40} | {"-"*40}',
        ]
        
        # 使用 difflib 生成并排对比
        orig_lines = diff.original_assembly[:30]
        patch_lines = diff.patched_assembly[:30]
        
        for i in range(max(len(orig_lines), len(patch_lines))):
            orig = orig_lines[i] if i < len(orig_lines) else ''
            patch = patch_lines[i] if i < len(patch_lines) else ''
            
            # 标记差异
            if orig != patch:
                if not orig:
                    lines.append(f'{"(新增)":<40} | {patch:<40}')
                elif not patch:
                    lines.append(f'{orig:<40} | {"(删除)":<40}')
                else:
                    lines.append(f'{orig:<40} | {patch:<40}')
            else:
                lines.append(f'{orig:<40} | {patch:<40}')
        
        return '\n'.join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            分析结果字典
        """
        return {
            'original_binary': self.original_binary,
            'patched_binary': self.patched_binary,
            'function_diff_count': len(self.function_diffs),
            'security_patch_count': len(self.security_patches),
            'function_diffs': [
                {
                    'function_name': d.function_name,
                    'diff_type': d.diff_type.value,
                    'is_security_patch': d.is_security_patch,
                    'vulnerability_type': d.vulnerability_type
                }
                for d in self.function_diffs[:50]
            ],
            'security_patches': [
                {
                    'function_name': p.function_name,
                    'vulnerability_type': p.vulnerability_type,
                    'severity': self._estimate_severity(p.vulnerability_type)
                }
                for p in self.security_patches
            ],
            'summary': self._generate_summary()
        }


def analyze_patch_diff(, original_binary: str, patched_binary: str, output_dir: str = None, use_ai: bool = True) -> PatchAnalysisResult:
    """
    分析补丁差异的便捷函数
    
    Args:
        original_binary: 原始二进制路径
        patched_binary: 补丁二进制路径
        output_dir: 输出目录
        use_ai: 是否使用 AI
        
    Returns:
        PatchAnalysisResult 分析结果
    """
    locator = PatchDiffLocator(original_binary, patched_binary, output_dir, use_ai)
    return locator.analyze()


def locate_patch_diff(, original_binary: str, patched_binary: str, output_dir: str = None, use_ai: bool = True) -> Dict[str, Any]:
    """
    定位补丁差异的便捷函数（兼容旧版本接口）
    
    Args:
        original_binary: 原始二进制路径
        patched_binary: 补丁二进制路径
        output_dir: 输出目录
        use_ai: 是否使用 AI
        
    Returns:
        分析结果字典
    """
    try:
        locator = PatchDiffLocator(original_binary, patched_binary, output_dir, use_ai)
        result = locator.analyze()
        return {
            'success': True,
            'original_binary': result.original_binary,
            'patched_binary': result.patched_binary,
            'function_diff_count': len(result.function_diffs),
            'security_patch_count': len(result.security_patches),
            'summary': result.summary,
            'diff_report': result.diff_report,
            'function_diffs': [
                {
                    'function_name': d.function_name,
                    'diff_type': d.diff_type.value,
                    'is_security_patch': d.is_security_patch,
                    'vulnerability_type': d.vulnerability_type
                }
                for d in result.function_diffs
            ],
            'security_patches': [
                {
                    'function_name': p.function_name,
                    'vulnerability_type': p.vulnerability_type
                }
                for p in result.security_patches
            ]
        }
    except Exception as e:
        logger.error(f"补丁差异定位失败: {e}")
        return {'success': False, 'error': str(e)}))