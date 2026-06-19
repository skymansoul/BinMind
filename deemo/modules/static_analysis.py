#!/usr/bin/env python3
"""
静态数据流分析模块

提供基于 angr 或 radare2 ESIL 的静态数据流分析功能：
- Use-Def 链分析
- 潜在整数溢出检测
- 格式化字符串漏洞检测
- 未初始化内存使用检测
- 静态污点分析
"""

import logging
import subprocess
import os
import json
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

ANGR_AVAILABLE = False
try:
    import angr
    from angr.analyses import ReachingDefinitions, CFGEmulated, VariableRecoveryFast
    from angr.knowledge_plugins.functions import Function
    ANGR_AVAILABLE = True
except ImportError:
    logger.debug("angr 未安装，将使用 radare2 作为后备")


@dataclass
class TaintSource:
    """
    污点源定义
    """
    name: str
    address: int
    type: str  # 'input', 'network', 'file', 'environment'
    registers: Set[str] = field(default_factory=set)
    description: str = ""


@dataclass
class TaintSink:
    """
    污点汇点定义
    """
    name: str
    address: int
    type: str  # 'system', 'execve', 'printf_family', 'memcpy', 'strcpy'
    argument_positions: List[int] = field(default_factory=list)
    description: str = ""


@dataclass
class TaintFlow:
    """
    污点传播路径
    """
    source: TaintSource
    sink: TaintSink
    path: List[int] = field(default_factory=list)
    tainted_variables: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class StaticVulnerability:
    """
    静态检测到的漏洞
    """
    type: str  # 'integer_overflow', 'format_string', 'uninitialized_memory', 'tainted_sink'
    function_name: str
    address: int
    description: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    evidence: List[str] = field(default_factory=list)
    tainted_variables: List[str] = field(default_factory=list)


class StaticDataFlowAnalyzer:
    """
    静态数据流分析器
    
    提供多种静态分析能力：
    1. Use-Def 链分析
    2. 整数溢出检测
    3. 格式化字符串漏洞检测
    4. 未初始化内存检测
    5. 静态污点分析
    """
    
    DEFAULT_TAINT_SOURCES = [
        ('read', 'input', [0], "标准输入"),
        ('fread', 'file', [0], "文件读取"),
        ('recv', 'network', [0], "网络接收"),
        ('recvfrom', 'network', [0], "网络接收"),
        ('gets', 'input', [], "危险的 gets 函数"),
        ('scanf', 'input', [0], "格式化输入"),
        ('getenv', 'environment', [], "环境变量"),
    ]
    
    DEFAULT_TAINT_SINKS = [
        ('system', 'system', [0], "命令执行"),
        ('execve', 'execve', [0, 1, 2], "执行新程序"),
        ('execl', 'execve', [0], "执行新程序"),
        ('execlp', 'execve', [0], "执行新程序"),
        ('execv', 'execve', [0], "执行新程序"),
        ('execvp', 'execve', [0], "执行新程序"),
        ('printf', 'printf_family', [0], "格式化输出"),
        ('fprintf', 'printf_family', [1], "格式化输出"),
        ('sprintf', 'printf_family', [1], "格式化字符串"),
        ('snprintf', 'printf_family', [2], "格式化字符串"),
        ('vprintf', 'printf_family', [0], "格式化输出"),
        ('vfprintf', 'printf_family', [1], "格式化输出"),
        ('memcpy', 'memcpy', [0, 1, 2], "内存复制"),
        ('memmove', 'memcpy', [0, 1, 2], "内存移动"),
        ('strcpy', 'strcpy', [0, 1], "字符串复制"),
        ('strncpy', 'strcpy', [0, 1, 2], "受限字符串复制"),
        ('strcat', 'strcpy', [0, 1], "字符串拼接"),
        ('strncat', 'strcpy', [0, 1, 2], "受限字符串拼接"),
    ]
    
    def __init__(self, binary_path: str, use_angr: bool = True):
        """
        初始化静态数据流分析器
        
        Args:
            binary_path: 二进制文件路径
            use_angr: 是否优先使用 angr（如果可用）
        """
        self.binary_path = binary_path
        self.use_angr = use_angr and ANGR_AVAILABLE
        self.project = None
        self.cfg = None
        self.taint_sources: List[TaintSource] = []
        self.taint_sinks: List[TaintSink] = []
        self._load_binary()
        self._setup_default_sources_sinks()
    
    def _load_binary(self) -> None:
        """
        加载二进制文件
        """
        if self.use_angr:
            try:
                self.project = angr.Project(self.binary_path, auto_load_libs=False)
                logger.info(f"[Static] 已加载二进制到 angr: {self.binary_path}")
                
                logger.info("[Static] 正在构建 CFG...")
                self.cfg = self.project.analyses.CFGFast(normalize=True)
                logger.info(f"[Static] CFG 构建完成，{len(self.cfg.functions)} 个函数")
                
            except Exception as e:
                logger.warning(f"[Static] angr 加载失败: {e}")
                self.use_angr = False
                self.project = None
    
    def _setup_default_sources_sinks(self) -> None:
        """
        设置默认的污点源和汇点
        """
        for name, source_type, regs, desc in self.DEFAULT_TAINT_SOURCES:
            self.taint_sources.append(TaintSource(
                name=name,
                address=0,
                type=source_type,
                registers=set(regs),
                description=desc
            ))
        
        for name, sink_type, args, desc in self.DEFAULT_TAINT_SINKS:
            self.taint_sinks.append(TaintSink(
                name=name,
                address=0,
                type=sink_type,
                argument_positions=args,
                description=desc
            ))
    
    def _check_radare2_available(self) -> bool:
        """
        检查 radare2 是否可用
        """
        try:
            subprocess.run(['r2', '-v'], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def is_available(self) -> bool:
        """
        检查分析器是否可用
        """
        return self.use_angr or self._check_radare2_available()
    
    def perform_static_taint_analysis(
        self,
        function_name: str = 'main'
    ) -> Dict[str, Any]:
        """
        执行静态污点分析
        
        Args:
            function_name: 要分析的函数名
            
        Returns:
            包含污点传播信息的字典：
            - tainted_variables: 受污染的变量列表
            - propagation_paths: 传播路径
            - potential_vulnerabilities: 潜在漏洞
            - function_name: 函数名
        """
        logger.info(f"[Static] 开始静态污点分析: {function_name}")
        
        result = {
            'function_name': function_name,
            'tainted_variables': [],
            'propagation_paths': [],
            'potential_vulnerabilities': [],
            'analysis_method': 'angr' if self.use_angr else 'radare2',
            'success': False
        }
        
        if self.use_angr and self.project:
            return self._taint_analysis_angr(function_name, result)
        else:
            return self._taint_analysis_radare2(function_name, result)
    
    def _taint_analysis_angr(
        self,
        function_name: str,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        使用 angr 进行污点分析
        """
        try:
            if function_name not in self.project.kb.functions:
                logger.warning(f"[Static] 未找到函数: {function_name}")
                return result
            
            func = self.project.kb.functions[function_name]
            func_addr = func.addr
            
            logger.info(f"[Static] angr 分析函数: {function_name} (0x{func_addr:x})")
            
            input_sources = self._find_input_sources_in_function(func)
            vulns = []
            
            for block in func.blocks:
                block_addr = block.addr
                
                for insn in block.capstone.insns:
                    insn_str = f"{insn.mnemonic} {insn.op_str}"
                    
                    if self._is_potential_integer_overflow(insn_str):
                        vulns.append(StaticVulnerability(
                            type='integer_overflow',
                            function_name=function_name,
                            address=insn.address,
                            description=f"潜在整数溢出: {insn_str}",
                            severity='High',
                            evidence=[insn_str]
                        ))
                    
                    if self._is_potential_format_string(insn_str, self.project, block_addr):
                        vulns.append(StaticVulnerability(
                            type='format_string',
                            function_name=function_name,
                            address=insn.address,
                            description=f"潜在格式化字符串漏洞: {insn_str}",
                            severity='Critical',
                            evidence=[insn_str]
                        ))
            
            tainted_vars = self._analyze_use_def_chain(func)
            
            result['tainted_variables'] = [str(v) for v in tainted_vars]
            result['potential_vulnerabilities'] = [
                {
                    'type': v.type,
                    'function': v.function_name,
                    'address': hex(v.address),
                    'description': v.description,
                    'severity': v.severity,
                    'evidence': v.evidence
                }
                for v in vulns
            ]
            result['success'] = True
            
            logger.info(f"[Static] angr 分析完成，发现 {len(vulns)} 个潜在漏洞")
            
        except Exception as e:
            logger.error(f"[Static] angr 污点分析失败: {e}")
        
        return result
    
    def _find_input_sources_in_function(self, func: 'Function') -> List[Tuple[int, str]]:
        """
        在函数中查找输入源调用
        """
        sources = []
        input_func_names = ['read', 'gets', 'scanf', 'fread', 'recv', 'recvfrom', 'getenv']
        
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    target = insn.op_str
                    for src_name in input_func_names:
                        if src_name in target:
                            sources.append((insn.address, src_name))
        
        return sources
    
    def _is_potential_integer_overflow(self, insn_str: str) -> bool:
        """
        检测潜在的整数溢出
        """
        overflow_patterns = [
            r'add\s+(?:e|r)(ax|bx|cx|dx|si|di|sp|bp)',
            r'sub\s+(?:e|r)(ax|bx|cx|dx|si|di|sp|bp)',
            r'mul\s+(?:e|r)(ax|bx|cx|dx)',
            r'imul\s+',
            r'shl\s+',
            r'sal\s+',
        ]
        
        for pattern in overflow_patterns:
            if re.search(pattern, insn_str, re.IGNORECASE):
                return True
        
        return False
    
    def _is_potential_format_string(
        self, 
        insn_str: str, 
        project, 
        block_addr: int
    ) -> bool:
        """
        检测潜在的格式化字符串漏洞
        
        检测调用 printf/sprintf 等函数时格式字符串参数是否来自用户输入
        """
        printf_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf']
        
        if 'call' in insn_str.lower():
            for func in printf_funcs:
                if func in insn_str:
                    return True
        
        return False
    
    def _analyze_use_def_chain(self, func: 'Function') -> Set[str]:
        """
        分析 use-def 链
        """
        tainted = set()
        
        try:
            vr = self.project.analyses.VariableRecoveryFast(func)
            
            var_manager = vr.variable_manager
            for var in var_manager.get_variables():
                var_name = str(var)
                
                if 'arg' in var_name.lower() or 'param' in var_name.lower():
                    tainted.add(var_name)
                
                if 'buf' in var_name.lower() or 'input' in var_name.lower():
                    tainted.add(var_name)
        
        except Exception as e:
            logger.debug(f"[Static] Use-Def 分析失败: {e}")
        
        return tainted
    
    def _taint_analysis_radare2(
        self,
        function_name: str,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        使用 radare2 ESIL 进行后备污点分析
        """
        if not self._check_radare2_available():
            logger.warning("[Static] radare2 不可用，无法进行分析")
            return result
        
        try:
            logger.info(f"[Static] radare2 分析函数: {function_name}")
            
            safe_func = self._sanitize_for_r2(function_name)
            
            cmd = [
                'r2', '-q', '-e', 'io.color=false', '-c',
                f'aaa; s sym.{safe_func}; pdf; afl~{safe_func}; q',
                self.binary_path
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60
            )
            
            if proc.returncode != 0:
                logger.warning(f"[Static] radare2 执行失败: {proc.stderr[:200]}")
                return result
            
            from modules.decomp_ai import strip_ansi_escape
            disassembly = strip_ansi_escape(proc.stdout)
            vulns = []
            tainted_vars = []
            
            vulns.extend(self._scan_assembly_for_vulns(disassembly, function_name))
            
            arg_pattern = re.compile(r'arg[_\d\w]+', re.IGNORECASE)
            args = arg_pattern.findall(disassembly)
            tainted_vars.extend(set(args))
            
            result['tainted_variables'] = tainted_vars
            result['potential_vulnerabilities'] = [
                {
                    'type': v.type,
                    'function': v.function_name,
                    'address': hex(v.address),
                    'description': v.description,
                    'severity': v.severity,
                    'evidence': v.evidence
                }
                for v in vulns
            ]
            result['success'] = True
            
            logger.info(f"[Static] radare2 分析完成，发现 {len(vulns)} 个潜在漏洞")
            
        except Exception as e:
            logger.error(f"[Static] radare2 污点分析失败: {e}")
        
        return result
    
    def _sanitize_for_r2(self, name: str) -> str:
        """
        清理用于 radare2 命令的函数名
        """
        import re
        return re.sub(r'[^\w\-_\.]', '_', name)
    
    def _scan_assembly_for_vulns(
        self,
        disassembly: str,
        function_name: str
    ) -> List[StaticVulnerability]:
        """
        从汇编代码中扫描漏洞
        """
        vulns = []
        lines = disassembly.split('\n')
        
        dangerous_patterns = {
            'format_string': {
                'patterns': [
                    (r'call.*printf', 'printf 调用'),
                    (r'call.*sprintf', 'sprintf 调用'),
                    (r'call.*fprintf', 'fprintf 调用'),
                ],
                'severity': 'Critical'
            },
            'dangerous_string': {
                'patterns': [
                    (r'call.*strcpy\b', 'strcpy 调用 - 不受限字符串复制'),
                    (r'call.*strcat\b', 'strcat 调用 - 不受限字符串拼接'),
                    (r'call.*gets\b', 'gets 调用 - 极度危险'),
                ],
                'severity': 'High'
            },
            'integer_overflow': {
                'patterns': [
                    (r'(?:add|sub|mul|imul|shl|sal)\s+(?:e|r)', '潜在整数运算溢出'),
                ],
                'severity': 'Medium'
            }
        }
        
        addr_pattern = re.compile(r'0x([0-9a-fA-F]+)')
        
        for line in lines:
            for vuln_type, info in dangerous_patterns.items():
                for pattern, desc in info['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        addr_match = addr_pattern.search(line)
                        addr = int(addr_match.group(1), 16) if addr_match else 0
                        
                        vulns.append(StaticVulnerability(
                            type=vuln_type,
                            function_name=function_name,
                            address=addr,
                            description=f"{desc}: {line.strip()}",
                            severity=info['severity'],
                            evidence=[line.strip()]
                        ))
        
        return vulns
    
    def detect_uninitialized_memory(
        self,
        function_name: str = 'main'
    ) -> List[Dict[str, Any]]:
        """
        检测未初始化内存使用
        
        Args:
            function_name: 要分析的函数名
            
        Returns:
            未初始化内存使用列表
        """
        logger.info(f"[Static] 检测未初始化内存: {function_name}")
        
        issues = []
        
        if self.use_angr and self.project:
            try:
                if function_name in self.project.kb.functions:
                    func = self.project.kb.functions[function_name]
                    vr = self.project.analyses.VariableRecoveryFast(func)
                    
                    var_manager = vr.variable_manager
                    for var in var_manager.get_variables():
                        var_name = str(var)
                        
                        if 'uninit' in var_name.lower():
                            issues.append({
                                'variable': var_name,
                                'function': function_name,
                                'type': 'uninitialized_variable',
                                'description': f'检测到可能未初始化的变量: {var_name}',
                                'severity': 'Medium'
                            })
            
            except Exception as e:
                logger.debug(f"[Static] 未初始化检测 (angr) 失败: {e}")
        
        if not self.use_angr or not issues:
            if self._check_radare2_available():
                issues.extend(self._detect_uninit_radare2(function_name))
        
        return issues
    
    def _detect_uninit_radare2(self, function_name: str) -> List[Dict[str, Any]]:
        """
        使用 radare2 检测未初始化内存
        """
        issues = []
        try:
            from modules.decomp_ai import strip_ansi_escape
            safe_func = self._sanitize_for_r2(function_name)
            cmd = [
                'r2', '-q', '-e', 'io.color=false', '-c',
                f'aaa; s sym.{safe_func}; afv; q',
                self.binary_path
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            output = strip_ansi_escape(proc.stdout)
            
            uninit_patterns = [
                r'var_.*?\s+uninitialized',
                r'stack.*?uninit',
            ]
            
            for pattern in uninit_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                for match in matches:
                    issues.append({
                        'variable': match,
                        'function': function_name,
                        'type': 'uninitialized_variable',
                        'description': f'radare2 检测到未初始化变量: {match}',
                        'severity': 'Medium',
                        'source': 'radare2'
                    })
        
        except Exception as e:
            logger.debug(f"[Static] 未初始化检测 (radare2) 失败: {e}")
        
        return issues
    
    def analyze_function(
        self,
        function_name: str
    ) -> Dict[str, Any]:
        """
        完整分析一个函数
        
        Args:
            function_name: 函数名
            
        Returns:
            包含所有分析结果的字典
        """
        logger.info(f"[Static] 完整分析函数: {function_name}")
        
        result = {
            'function_name': function_name,
            'taint_analysis': None,
            'uninitialized_memory': [],
            'vulnerabilities': [],
            'summary': ''
        }
        
        taint_result = self.perform_static_taint_analysis(function_name)
        result['taint_analysis'] = taint_result
        
        if taint_result.get('success'):
            result['vulnerabilities'].extend(taint_result.get('potential_vulnerabilities', []))
        
        uninit_issues = self.detect_uninitialized_memory(function_name)
        result['uninitialized_memory'] = uninit_issues
        
        total_issues = len(result['vulnerabilities']) + len(uninit_issues)
        result['summary'] = f"发现 {len(result['vulnerabilities'])} 个潜在漏洞, {len(uninit_issues)} 个未初始化变量问题"
        
        logger.info(f"[Static] {result['summary']}")
        
        return result
    
    def get_cached_analysis(
        self,
        function_name: str,
        cache_dir: str = './data/cache'
    ) -> Optional[Dict[str, Any]]:
        """
        从缓存获取分析结果（如果存在）
        
        Args:
            function_name: 函数名
            cache_dir: 缓存目录
            
        Returns:
            缓存的分析结果，如果没有返回 None
        """
        try:
            binary_hash = self._compute_binary_hash()
            cache_file = os.path.join(
                cache_dir,
                f'static_{binary_hash}_{function_name}.json'
            )
            
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        
        return None
    
    def save_to_cache(
        self,
        function_name: str,
        result: Dict[str, Any],
        cache_dir: str = './data/cache'
    ) -> bool:
        """
        保存分析结果到缓存
        
        Args:
            function_name: 函数名
            result: 分析结果
            cache_dir: 缓存目录
            
        Returns:
            是否保存成功
        """
        try:
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
            
            binary_hash = self._compute_binary_hash()
            cache_file = os.path.join(
                cache_dir,
                f'static_{binary_hash}_{function_name}.json'
            )
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            
            logger.info(f"[Static] 分析结果已缓存: {cache_file}")
            return True
            
        except Exception as e:
            logger.warning(f"[Static] 缓存保存失败: {e}")
            return False
    
    def _compute_binary_hash(self) -> str:
        """
        计算二进制文件的哈希
        """
        try:
            hasher = hashlib.md5()
            with open(self.binary_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return 'unknown'


def perform_static_taint_analysis(
    binary_path: str,
    function_name: str = 'main',
    use_angr: bool = True
) -> Dict[str, Any]:
    """
    便捷函数：执行静态污点分析
    
    Args:
        binary_path: 二进制文件路径
        function_name: 目标函数名
        use_angr: 是否使用 angr
        
    Returns:
        污点分析结果
    """
    analyzer = StaticDataFlowAnalyzer(binary_path, use_angr)
    return analyzer.analyze_function(function_name)
