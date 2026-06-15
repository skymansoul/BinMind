#!/usr/bin/env python3
"""
并发漏洞与竞态条件检测模块

提供静态分析能力检测二进制程序中的并发安全问题：
- 数据竞争（data race）检测
- 死锁（deadlock）风险分析
- 基于时间的竞态条件（TOCTOU）检测
"""

import logging
import re
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ThreadCreatePoint:
    """
    线程创建点信息
    """
    function_name: str
    address: int
    thread_func: str
    args: List[str] = field(default_factory=list)


@dataclass
class SyncOperation:
    """
    同步操作信息
    """
    operation_type: str  # 'lock', 'unlock', 'wait', 'post'
    lock_name: str
    address: int
    function_name: str


@dataclass
class SharedVariableAccess:
    """
    共享变量访问信息
    """
    variable_name: str
    address: int
    function_name: str
    access_type: str  # 'read', 'write', 'read_write'
    locks_held: Set[str] = field(default_factory=set)


@dataclass
class ConcurrencyIssue:
    """
    并发问题描述
    """
    issue_type: str  # 'data_race', 'deadlock', 'toctou'
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    description: str
    location: str
    function_name: str
    variables: List[str] = field(default_factory=list)
    locks: List[str] = field(default_factory=list)
    call_stack: List[str] = field(default_factory=list)


class ConcurrencyAnalyzer:
    """
    并发安全分析器
    
    核心功能：
    1. 识别线程创建点和同步原语
    2. 构建共享变量访问图
    3. 基于Lockset算法检测数据竞争
    4. 检测死锁风险
    5. 检测TOCTOU竞态条件
    """
    
    # 线程创建函数模式
    THREAD_CREATE_FUNCTIONS = {
        'pthread_create': {
            'pattern': r'pthread_create\s*\(',
            'thread_arg_index': 2
        },
        'CreateThread': {
            'pattern': r'CreateThread\s*\(',
            'thread_arg_index': 3
        },
        '_beginthread': {
            'pattern': r'_beginthread\s*\(',
            'thread_arg_index': 0
        },
        '_beginthreadex': {
            'pattern': r'_beginthreadex\s*\(',
            'thread_arg_index': 3
        },
        'std::thread': {
            'pattern': r'std::thread\s*\{?',
            'thread_arg_index': 0
        }
    }
    
    # 同步原语模式
    SYNC_PRIMITIVES = {
        'mutex_lock': [
            r'pthread_mutex_lock\s*\(',
            r'mutex_lock\s*\(',
            r'pthread_mutex_lock\s*\(',
            r'EnterCriticalSection\s*\(',
            r'Lock\s*\('
        ],
        'mutex_unlock': [
            r'pthread_mutex_unlock\s*\(',
            r'mutex_unlock\s*\(',
            r'LeaveCriticalSection\s*\(',
            r'UnLock\s*\('
        ],
        'sem_wait': [
            r'pthread_sem_wait\s*\(',
            r'sem_wait\s*\(',
            r'WaitForSingleObject\s*\(',
            r'WaitForMultipleObjects\s*\('
        ],
        'sem_post': [
            r'pthread_sem_post\s*\(',
            r'sem_post\s*\(',
            r'ReleaseSemaphore\s*\(',
            r'SetEvent\s*\('
        ],
        'rwlock': [
            r'pthread_rwlock_rdlock\s*\(',
            r'pthread_rwlock_wrlock\s*\(',
            r'pthread_rwlock_unlock\s*\('
        ]
    }
    
    # TOCTOU 文件操作配对
    TOCTOU_PAIRS = [
        ('access', 'open'),
        ('stat', 'fopen'),
        ('lstat', 'open'),
        ('stat64', 'open'),
        ('lstat64', 'open'),
        ('fstat', 'fopen'),
        ('access', 'creat'),
        ('stat', 'creat')
    ]
    
    # 信号处理函数
    SIGNAL_HANDLER_FUNCTIONS = [
        'signal',
        'sigaction',
        'signal_handler',
        'sig_handler'
    ]
    
    # 信号处理中不安全的函数
    SIGNAL_UNSAFE_FUNCTIONS = [
        'malloc', 'free', 'realloc', 'calloc',
        'printf', 'fprintf', 'sprintf', 'vsprintf',
        'strcpy', 'strcat', 'memcpy', 'memmove',
        'exit', 'abort', 'longjmp', 'siglongjmp'
    ]
    
    def __init__(self, pseudocode: str, binary_info: Dict[str, Any] = None):
        """
        初始化并发分析器
        
        Args:
            pseudocode: 反编译后的伪代码
            binary_info: 二进制文件信息（包含导入函数等）
        """
        self.pseudocode = pseudocode
        self.binary_info = binary_info or {}
        self.thread_create_points: List[ThreadCreatePoint] = []
        self.sync_operations: List[SyncOperation] = []
        self.shared_variable_accesses: List[SharedVariableAccess] = []
        self.functions: Set[str] = set()
        self.global_variables: Set[str] = set()
        
        self._parse_pseudocode()
    
    def _parse_pseudocode(self) -> None:
        """
        解析伪代码，提取关键信息
        """
        logger.info("[Concurrency] 开始解析伪代码")
        
        lines = self.pseudocode.split('\n')
        current_function = 'unknown'
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            func_match = re.match(r'^\s*(?:int|void|char|long|short|float|double|\w+\s+\*?)\s+(\w+)\s*\(', line)
            if func_match:
                current_function = func_match.group(1)
                self.functions.add(current_function)
            
            var_match = re.match(r'^\s*(?:static\s+)?(?:int|char|long|void|float|double|\w+)\s+(\w+)\s*[=;]', line)
            if var_match and current_function == 'unknown':
                self.global_variables.add(var_match.group(1))
            
            self._detect_thread_creation(line, line_num, current_function)
            self._detect_sync_operations(line, line_num, current_function)
            self._detect_shared_variable_access(line, line_num, current_function)
        
        logger.info(f"[Concurrency] 解析完成: {len(self.thread_create_points)} 个线程创建点, "
                   f"{len(self.sync_operations)} 个同步操作, {len(self.global_variables)} 个全局变量")
    
    def _detect_thread_creation(self, line: str, line_num: int, function_name: str) -> None:
        """
        检测线程创建点
        """
        for func_name, info in self.THREAD_CREATE_FUNCTIONS.items():
            if re.search(info['pattern'], line):
                args = self._extract_function_args(line)
                thread_func = args[info['thread_arg_index']] if args else 'unknown'
                
                self.thread_create_points.append(ThreadCreatePoint(
                    function_name=function_name,
                    address=line_num,
                    thread_func=thread_func,
                    args=args
                ))
                logger.debug(f"[Concurrency] 检测到线程创建: {func_name} in {function_name}")
    
    def _detect_sync_operations(self, line: str, line_num: int, function_name: str) -> None:
        """
        检测同步操作
        """
        for op_type, patterns in self.SYNC_PRIMITIVES.items():
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    lock_name = self._extract_lock_name(line)
                    self.sync_operations.append(SyncOperation(
                        operation_type=op_type,
                        lock_name=lock_name,
                        address=line_num,
                        function_name=function_name
                    ))
                    logger.debug(f"[Concurrency] 检测到同步操作: {op_type} on {lock_name} in {function_name}")
    
    def _detect_shared_variable_access(self, line: str, line_num: int, function_name: str) -> None:
        """
        检测共享变量访问
        """
        for var in self.global_variables:
            if var in line:
                access_type = 'write' if '=' in line else 'read'
                
                locks_held = self._find_held_locks(function_name, line_num)
                
                self.shared_variable_accesses.append(SharedVariableAccess(
                    variable_name=var,
                    address=line_num,
                    function_name=function_name,
                    access_type=access_type,
                    locks_held=locks_held
                ))
    
    def _extract_function_args(self, line: str) -> List[str]:
        """
        从函数调用中提取参数
        """
        args_pattern = r'\(([^)]+)\)'
        match = re.search(args_pattern, line)
        if match:
            args_str = match.group(1)
            args = [arg.strip() for arg in args_str.split(',')]
            return args
        return []
    
    def _extract_lock_name(self, line: str) -> str:
        """
        从同步操作中提取锁变量名
        """
        args = self._extract_function_args(line)
        if args:
            return args[0].replace('&', '').strip()
        return 'unknown_lock'
    
    def _find_held_locks(self, function_name: str, up_to_line: int) -> Set[str]:
        """
        查找在当前位置之前持有的锁
        """
        held_locks = set()
        operations_before = [op for op in self.sync_operations 
                            if op.function_name == function_name and op.address < up_to_line]
        
        for op in operations_before:
            if op.operation_type in ['mutex_lock', 'sem_wait', 'rwlock']:
                held_locks.add(op.lock_name)
            elif op.operation_type in ['mutex_unlock', 'sem_post']:
                held_locks.discard(op.lock_name)
        
        return held_locks
    
    def analyze_data_race(self) -> List[ConcurrencyIssue]:
        """
        基于Lockset算法检测数据竞争
        
        检测规则：如果两个或多个线程对同一内存位置进行至少一个写操作
        且无共同锁保护，则报告数据竞争风险
        """
        logger.info("[Concurrency] 开始检测数据竞争")
        
        issues = []
        var_access_map: Dict[str, List[SharedVariableAccess]] = {}
        
        for access in self.shared_variable_accesses:
            if access.variable_name not in var_access_map:
                var_access_map[access.variable_name] = []
            var_access_map[access.variable_name].append(access)
        
        for var_name, accesses in var_access_map.items():
            write_accesses = [a for a in accesses if a.access_type == 'write']
            if len(write_accesses) < 2:
                continue
            
            for i, access1 in enumerate(write_accesses):
                for j, access2 in enumerate(write_accesses[i+1:], i+1):
                    common_locks = access1.locks_held & access2.locks_held
                    
                    if not common_locks:
                        issues.append(ConcurrencyIssue(
                            issue_type='data_race',
                            severity='High',
                            description=f"检测到数据竞争：变量 '{var_name}' 在函数 '{access1.function_name}' 和 '{access2.function_name}' 中被并发写入，但没有共同的锁保护",
                            location=f"行 {access1.address} 和行 {access2.address}",
                            function_name=f"{access1.function_name}, {access2.function_name}",
                            variables=[var_name],
                            locks=list(access1.locks_held | access2.locks_held)
                        ))
        
        logger.info(f"[Concurrency] 数据竞争检测完成，发现 {len(issues)} 个问题")
        return issues
    
    def analyze_deadlock(self) -> List[ConcurrencyIssue]:
        """
        检测死锁风险
        
        检测规则：分析加锁顺序，若存在不同路径的锁获取顺序不一致则报告潜在死锁
        """
        logger.info("[Concurrency] 开始检测死锁风险")
        
        issues = []
        lock_order_map: Dict[str, List[List[str]]] = {}
        
        for func_name in self.functions:
            func_ops = [op for op in self.sync_operations if op.function_name == func_name]
            func_ops.sort(key=lambda x: x.address)
            
            lock_order = []
            held_locks = []
            
            for op in func_ops:
                if op.operation_type in ['mutex_lock', 'sem_wait']:
                    if op.lock_name not in held_locks:
                        held_locks.append(op.lock_name)
                        lock_order.append(op.lock_name)
                elif op.operation_type in ['mutex_unlock', 'sem_post']:
                    if op.lock_name in held_locks:
                        held_locks.remove(op.lock_name)
            
            if len(lock_order) >= 2:
                if func_name not in lock_order_map:
                    lock_order_map[func_name] = []
                lock_order_map[func_name].append(lock_order)
        
        all_orders = []
        for func_orders in lock_order_map.values():
            all_orders.extend(func_orders)
        
        for i, order1 in enumerate(all_orders):
            for j, order2 in enumerate(all_orders[i+1:], i+1):
                if self._has_inverted_order(order1, order2):
                    issues.append(ConcurrencyIssue(
                        issue_type='deadlock',
                        severity='Critical',
                        description=f"检测到潜在死锁：锁获取顺序不一致。路径1: {' -> '.join(order1)}, 路径2: {' -> '.join(order2)}",
                        location="多个函数",
                        function_name=f"函数组 {i+1} 和 {j+1}",
                        locks=list(set(order1 + order2))
                    ))
        
        logger.info(f"[Concurrency] 死锁检测完成，发现 {len(issues)} 个问题")
        return issues
    
    def _has_inverted_order(self, order1: List[str], order2: List[str]) -> bool:
        """
        检查两个锁获取顺序是否存在反转
        """
        common_locks = [lock for lock in order1 if lock in order2]
        
        if len(common_locks) < 2:
            return False
        
        idx1 = [order1.index(lock) for lock in common_locks]
        idx2 = [order2.index(lock) for lock in common_locks]
        
        return idx1 != sorted(idx1) or idx2 != sorted(idx2) or idx1 != idx2
    
    def analyze_toctou(self) -> List[ConcurrencyIssue]:
        """
        检测TOCTOU（Time-of-check to time-of-use）竞态条件
        
        检测规则：识别文件访问函数配对，检查时间窗口脆弱性
        """
        logger.info("[Concurrency] 开始检测TOCTOU竞态条件")
        
        issues = []
        
        function_calls = self._extract_function_calls()
        
        for check_func, use_func in self.TOCTOU_PAIRS:
            check_calls = [call for call in function_calls if call['name'] == check_func]
            use_calls = [call for call in function_calls if call['name'] == use_func]
            
            for check_call in check_calls:
                for use_call in use_calls:
                    if check_call['function_name'] == use_call['function_name']:
                        args_match = self._args_might_match(check_call['args'], use_call['args'])
                        if args_match:
                            issues.append(ConcurrencyIssue(
                                issue_type='toctou',
                                severity='Medium',
                                description=f"检测到TOCTOU竞态条件：在函数 '{check_call['function_name']}' 中，{check_func} 和 {use_func} 调用使用相同的参数，存在时间窗口漏洞",
                                location=f"行 {check_call['line']} 和行 {use_call['line']}",
                                function_name=check_call['function_name'],
                                variables=args_match
                            ))
        
        signal_issues = self._detect_signal_unsafe_functions()
        issues.extend(signal_issues)
        
        logger.info(f"[Concurrency] TOCTOU检测完成，发现 {len(issues)} 个问题")
        return issues
    
    def _extract_function_calls(self) -> List[Dict[str, Any]]:
        """
        从伪代码中提取所有函数调用
        """
        calls = []
        lines = self.pseudocode.split('\n')
        
        for i, line in enumerate(lines):
            func_pattern = r'(\w+)\s*\('
            matches = re.finditer(func_pattern, line)
            
            for match in matches:
                func_name = match.group(1)
                args = self._extract_function_args(line)
                calls.append({
                    'name': func_name,
                    'args': args,
                    'line': i + 1,
                    'function_name': self._get_function_at_line(i + 1)
                })
        
        return calls
    
    def _get_function_at_line(self, line_num: int) -> str:
        """
        获取指定行所在的函数名
        """
        for op in self.sync_operations:
            if op.address <= line_num:
                return op.function_name
        return 'unknown'
    
    def _args_might_match(self, args1: List[str], args2: List[str]) -> Optional[List[str]]:
        """
        检查两个函数调用的参数是否可能指向同一资源
        """
        if not args1 or not args2:
            return None
        
        common_args = set(args1) & set(args2)
        if common_args:
            return list(common_args)
        
        for arg1 in args1:
            for arg2 in args2:
                if arg1.replace('&', '') == arg2.replace('&', ''):
                    return [arg1, arg2]
        
        return None
    
    def _detect_signal_unsafe_functions(self) -> List[ConcurrencyIssue]:
        """
        检测信号处理函数中使用的非安全函数
        """
        issues = []
        
        lines = self.pseudocode.split('\n')
        in_signal_handler = False
        current_handler = 'unknown'
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            for handler_func in self.SIGNAL_HANDLER_FUNCTIONS:
                if handler_func in line and ('(' in line or '=' in line):
                    func_match = re.match(r'^\s*(?:void|int)\s+(\w+)\s*\(', line)
                    if func_match:
                        current_handler = func_match.group(1)
                        in_signal_handler = True
            
            if in_signal_handler:
                for unsafe_func in self.SIGNAL_UNSAFE_FUNCTIONS:
                    if unsafe_func + '(' in line:
                        issues.append(ConcurrencyIssue(
                            issue_type='toctou',
                            severity='High',
                            description=f"检测到信号处理函数中使用不安全函数：'{unsafe_func}' 在信号处理函数 '{current_handler}' 中被调用，可能导致竞态条件",
                            location=f"行 {line_num}",
                            function_name=current_handler,
                            variables=[unsafe_func]
                        ))
            
            if in_signal_handler and line.strip() == '}' and '{' not in line:
                in_signal_handler = False
        
        return issues
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的并发安全分析
        
        Returns:
            包含所有检测结果的字典：
            - thread_create_points: 线程创建点列表
            - sync_operations: 同步操作列表
            - shared_variables: 共享变量列表
            - issues: 检测到的并发问题列表
        """
        logger.info("[Concurrency] 开始执行完整的并发安全分析")
        
        data_race_issues = self.analyze_data_race()
        deadlock_issues = self.analyze_deadlock()
        toctou_issues = self.analyze_toctou()
        
        all_issues = data_race_issues + deadlock_issues + toctou_issues
        
        result = {
            'thread_create_points': [
                {
                    'function_name': tcp.function_name,
                    'address': tcp.address,
                    'thread_func': tcp.thread_func,
                    'args': tcp.args
                }
                for tcp in self.thread_create_points
            ],
            'sync_operations': [
                {
                    'operation_type': so.operation_type,
                    'lock_name': so.lock_name,
                    'address': so.address,
                    'function_name': so.function_name
                }
                for so in self.sync_operations
            ],
            'shared_variables': list(self.global_variables),
            'issues': [
                {
                    'issue_type': issue.issue_type,
                    'severity': issue.severity,
                    'description': issue.description,
                    'location': issue.location,
                    'function_name': issue.function_name,
                    'variables': issue.variables,
                    'locks': issue.locks,
                    'call_stack': issue.call_stack
                }
                for issue in all_issues
            ],
            'summary': {
                'total_threads': len(self.thread_create_points),
                'total_sync_ops': len(self.sync_operations),
                'total_shared_vars': len(self.global_variables),
                'total_issues': len(all_issues),
                'data_race_count': len(data_race_issues),
                'deadlock_count': len(deadlock_issues),
                'toctou_count': len(toctou_issues)
            }
        }
        
        logger.info(f"[Concurrency] 分析完成，共发现 {len(all_issues)} 个并发问题")
        return result


def analyze_concurrency(pseudocode: str, binary_info: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    便捷函数：执行并发安全分析
    
    Args:
        pseudocode: 反编译后的伪代码
        binary_info: 二进制文件信息
    
    Returns:
        分析结果字典
    """
    analyzer = ConcurrencyAnalyzer(pseudocode, binary_info)
    return analyzer.analyze()