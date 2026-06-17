import logging
import os
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

ANGR_AVAILABLE = False
ANGR_EXPLORER_AVAILABLE = False

try:
    import angr
    import claripy
    from angr import sim_options as so
    ANGR_AVAILABLE = True
    logger.info("angr 符号执行引擎可用")
except ImportError:
    logger.warning("angr 未安装，符号执行功能不可用")
    logger.warning("  安装命令: pip install angr")

try:
    import angr_explorer
    ANGR_EXPLORER_AVAILABLE = True
    logger.info("angr-explorer 可视化引擎可用")
except ImportError:
    logger.debug("angr-explorer 未安装，可视化功能不可用")
    logger.debug("  安装命令: pip install angr-explorer")


SUPPORTED_ARCHES = [
    'x86', 'x86_64', 'amd64',
    'arm', 'armel', 'armhf', 'arm64', 'aarch64',
    'mips', 'mipsel', 'mips64',
    'riscv32', 'riscv64', 'ppc', 'ppc64'
]


class SymbolicExecutor:
    """
    符号执行分析器 - 基于 angr
    """
    
    def __init__(self, binary_path: str, target_arch: str = None):
        """
        初始化符号执行器
        
        Args:
            binary_path: 二进制文件路径
            target_arch: 目标架构（可选，若不指定则自动检测）
        """
        self.binary_path = binary_path
        self.target_arch = target_arch
        self.project = None
        self.available = ANGR_AVAILABLE
        self.arch_info = None
        
        if self.available:
            self._load_project()
    
    def _validate_arch(self, arch: str) -> bool:
        """
        验证架构是否被支持
        """
        if not arch:
            return True
        arch_lower = arch.lower()
        for supported in SUPPORTED_ARCHES:
            if arch_lower in supported or supported in arch_lower:
                return True
        return False
    
    def _load_project(self) -> bool:
        """
        加载 angr 项目
        """
        try:
            logger.info(f"[angr] 加载二进制文件: {self.binary_path}")
            
            if self.target_arch:
                if not self._validate_arch(self.target_arch):
                    logger.warning(f"[angr] 指定的架构 {self.target_arch} 可能不被完全支持")
                    logger.warning(f"[angr] 支持的架构: {', '.join(SUPPORTED_ARCHES)}")
                
                logger.info(f"[angr] 使用指定架构: {self.target_arch}")
                
                arch_option = self._get_arch_main_opts(self.target_arch)
                main_opts = {'base_addr': 0}
                main_opts.update(arch_option)
                
                self.project = angr.Project()
                    self.binary_path,
                    auto_load_libs=False,
                    main_opts=main_opts
                
            else:
                self.project = angr.Project()
                    self.binary_path,
                    auto_load_libs=False,
                    main_opts={'base_addr': 0}
                
            
            self.arch_info = self._extract_arch_info()
            logger.info(f"[angr] 项目加载成功，架构: {self.arch_info.get('arch', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"[angr] 加载项目失败: {e}")
            self.project = None,
            return False
    
    def _get_arch_main_opts(self, arch: str) -> Dict[str, Any]:
        """
        根据架构名称获取 angr main_opts
        """
        arch_lower = arch.lower()
        opts = {}
        
        if 'x86_64' in arch_lower or 'amd64' in arch_lower:
            opts['arch'] = 'x86_64'
        elif 'x86' in arch_lower or 'i386' in arch_lower:
            opts['arch'] = 'x86'
        elif 'arm64' in arch_lower or 'aarch64' in arch_lower:
            opts['arch'] = 'aarch64'
        elif 'arm' in arch_lower:
            opts['arch'] = 'arm'
        elif 'mips64' in arch_lower:
            opts['arch'] = 'mips64'
        elif 'mips' in arch_lower:
            opts['arch'] = 'mips'
        elif 'riscv64' in arch_lower:
            opts['arch'] = 'riscv64'
        elif 'riscv' in arch_lower:
            opts['arch'] = 'riscv32'
        elif 'ppc64' in arch_lower:
            opts['arch'] = 'ppc64'
        elif 'ppc' in arch_lower:
            opts['arch'] = 'ppc'
        
        return opts
    
    def _extract_arch_info(self) -> Dict[str, Any]:
        """
        提取架构信息
        """
        info = {'supported': False}
        
        if not self.project:
            return info
        
        try:
            arch_obj = self.project.arch
            info.update({)
                'arch': arch_obj.name,
                'bits': arch_obj.bits,
                'endian': arch_obj.memory_endness,
                'ip_reg': arch_obj.ip_offset,
                'sp_reg': arch_obj.sp_offset,
                'supported': True
            }
            
            if arch_obj.name in ['AMD64', 'X86']:
                info['family'] = 'x86'
            elif arch_obj.name in ['AArch64', 'ARM']:
                info['family'] = 'ARM'
            elif arch_obj.name.startswith('MIPS'):
                info['family'] = 'MIPS'
            elif 'RISCV' in arch_obj.name:
                info['family'] = 'RISC-V'
            elif 'PPC' in arch_obj.name:
                info['family'] = 'PowerPC'
            else:
                info['family'] = 'Unknown'
            
            return info
        except Exception as e:
            logger.debug(f"[angr] 提取架构信息失败: {e}")
            return info
    
    def is_available(self) -> bool:
        """
        检查符号执行是否可用
        """
        return self.available and self.project is not None
    
    def find_crash_path(, self)
        target_address: int = None,
        avoid_addresses: List[int] = None,
        max_steps: int = 100
    ) -> Dict[str, Any]:
        """
        探索路径，寻找可能的崩溃点
        
        Args:
            target_address: 目标地址（可选）
            avoid_addresses: 需要避免的地址列表
            max_steps: 最大步数
            
        Returns:
            探索结果字典
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用'
            }
        
        try:
            logger.info(f"[angr] 开始探索路径 (max_steps={max_steps})")
            
            state = self.project.factory.entry_state()
                add_options={so.SYMBOL_FILL_UNCONSTRAINED_MEMORY, so.REVERSE_MEMORY_NAME_MAP}
            
            
            simgr = self.project.factory.simulation_manager(state)
            
            if target_address:
                logger.info(f"[angr] 探索目标地址: {hex(target_address)}")
                simgr.explore(find=target_address, avoid=avoid_addresses or [], n=1)
                
                if simgr.found:
                    found_state = simgr.found[0]
                    result = {
                        'success': True,
                        'found': True,
                        'target_address': hex(target_address),
                        'concrete_input': self._get_concrete_input(found_state),
                        'state_info': self._get_state_info(found_state)
                    }
                    logger.info(f"[angr] 找到到达目标地址的路径")
                    return result
            else:
                logger.info("[angr] 一般性探索，寻找异常状态")
                results = self._explore_for_vulnerabilities(simgr, max_steps)
                return results
                
        except Exception as e:
            logger.error(f"[angr] 路径探索失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
        
        return {
            'success': False,
            'found': False
        }
    
    def _explore_for_vulnerabilities(, self)
        simgr,
        max_steps: int
    ) -> Dict[str, Any]:
        """
        探索路径寻找漏洞特征
        """
        vulnerabilities = []
        
        for step in range(max_steps):
            try:
                simgr.step(num_inst=1)
                
                for stash_name in simgr.stashes:
                    if stash_name == 'errored':
                        for errored in simgr.errored:
                            error_info = self._analyze_error(errored)
                            if error_info:
                                vulnerabilities.append(error_info)
                                
                    elif stash_name == 'deadended':
                        for dead in simgr.deadended:
                            if self._check_vulnerable_state(dead):
                                vulnerabilities.append({)
                                    'type': 'Potential Vulnerable Path',
                                    'address': hex(dead.addr),
                                    'input': self._get_concrete_input(dead)
                                }
                
                if not simgr.active:
                    break
                    
            except Exception as e:
                logger.warning(f"[angr] 探索步骤 {step} 出错: {e}")
                break
        
        if vulnerabilities:
            logger.warning(f"[angr] 发现 {len(vulnerabilities)} 个潜在漏洞路径")
            return {
                'success': True,
                'vulnerabilities': vulnerabilities
            }
        else:
            logger.info("[angr] 未发现明显的漏洞路径")
            return {
                'success': True,
                'vulnerabilities': []
            }
    
    def _analyze_error(self, errored_state) -> Optional[Dict[str, Any]]:
        """
        分析错误状态
        """
        try:
            error = errored_state.error
            state = errored_state.state
            
            error_str = str(error)
            state_addr = state.addr if state else 0
            
            if 'segfault' in error_str.lower() or 'SIGSEGV' in error_str:
                return {
                    'type': 'Segmentation Fault',
                    'address': hex(state_addr),
                    'error': error_str,
                    'input': self._get_concrete_input(state) if state else None
                }
            
            if 'unconstrained' in error_str.lower():
                return {
                    'type': 'Unconstrained IP (Controllable PC)',
                    'address': hex(state_addr),
                    'description': '指令指针被符号化，可能存在内存破坏',
                    'input': self._get_concrete_input(state) if state else None
                }
            
            return None
            
        except Exception:
            return None
    
    def _check_vulnerable_state(self, state) -> bool:
        """
        检查状态是否有漏洞特征
        """
        try:
            ip = state.regs.ip,
            if state.solver.symbolic(ip):
                return True
            
            for reg_name in ['rip', 'eip', 'pc']:
                if hasattr(state.regs, reg_name):
                    reg = getattr(state.regs, reg_name)
                    if state.solver.symbolic(reg):
                        return True
            
            return False
        except Exception:
            return False
    
    def _get_concrete_input(self, state) -> Optional[bytes]:
        """
        获取具体化的输入
        """
        try:
            if hasattr(state, 'posix') and hasattr(state.posix, 'stdin'):
                stdin = state.posix.stdin,
                if hasattr(stdin, 'content') and stdin.content:
                    for i, content in enumerate(stdin.content):
                        if hasattr(content, 'val'):
                            try:
                                concrete = state.solver.eval(content.val, cast_to=bytes)
                                if concrete:
                                    return concrete
                            except Exception:
                                continue
            
            return None
        except Exception:
            return None
    
    def _get_state_info(self, state) -> Dict[str, Any]:
        """
        获取状态信息
        """
        try:
            info = {
                'address': hex(state.addr),
                'registers': {}
            }
            
            for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip',
                            'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip']:
                if hasattr(state.regs, reg_name):
                    try:
                        reg_val = getattr(state.regs, reg_name)
                        if not state.solver.symbolic(reg_val):
                            info['registers'][reg_name] = hex(state.solver.eval(reg_val

                    except Exception:
                        continue
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def calculate_stack_offset(, self)
        function_name: str = 'main',
        buffer_size_guess: int = 100,
        max_attempts: int = 10
    ) -> Dict[str, Any]:
        """
        计算栈溢出偏移量
        
        Args:
            function_name: 目标函数名
            buffer_size_guess: 缓冲区大小猜测
            max_attempts: 最大尝试次数
            
        Returns:
            偏移量计算结果
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用'
            }
        
        try:
            logger.info(f"[angr] 尝试计算栈偏移量 (函数: {function_name})")
            
            func_addr = self._find_function_address(function_name)
            if not func_addr:
                return {
                    'success': False,
                    'error': f'未找到函数 {function_name}'
                }
            
            logger.info(f"[angr] 函数 {function_name} 地址: {hex(func_addr)}")
            
            for size in range(buffer_size_guess, buffer_size_guess + max_attempts * 100, 100):
                result = self._test_overflow_at_size(func_addr, size)
                if result.get('success'):
                    return result
            
            return {
                'success': False,
                'error': '未能确定栈偏移量，尝试更大的缓冲区大小'
            }
            
        except Exception as e:
            logger.error(f"[angr] 计算栈偏移量失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _find_function_address(self, function_name: str) -> Optional[int]:
        """
        查找函数地址
        """
        try:
            if hasattr(self.project, 'loader') and hasattr(self.project.loader, 'main_object'):
                obj = self.project.loader.main_object
                
                if hasattr(obj, 'symbols'):
                    for name, symbol in obj.symbols.items():
                        if name == function_name or name == f'sym.{function_name}':
                            return symbol.rebased_addr
                
                if hasattr(self.project, 'kb') and hasattr(self.project.kb, 'functions'):
                    if function_name in self.project.kb.functions:
                        return self.project.kb.functions[function_name].addr
            
            return None
        except Exception:
            return None
    
    def _test_overflow_at_size(self, func_addr: int, size: int) -> Dict[str, Any]:
        """
        测试特定大小的输入是否导致溢出
        """
        try:
            state = self.project.factory.call_state()
                func_addr,
                add_options={so.SYMBOL_FILL_UNCONSTRAINED_MEMORY}
            
            
            simgr = self.project.factory.simulation_manager(state)
            simgr.run(n=50)
            
            if simgr.deadended:
                for dead in simgr.deadended:
                    if self._check_vulnerable_state(dead):
                        ip = dead.regs.ip if hasattr(dead.regs, 'ip') else None,
                        if ip and dead.solver.symbolic(ip):
                            concrete_ip = dead.solver.eval(ip)
                            offset = self._calculate_offset_from_ip(concrete_ip, size)
                            
                            return {
                                'success': True,
                                'offset': offset,
                                'buffer_size': size,
                                'controlled_ip': hex(concrete_ip),
                                'input_sample': self._get_concrete_input(dead)
                            }
            
            return {'success': False}
            
        except Exception as e:
            logger.debug(f"[angr] 测试大小 {size} 失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def _calculate_offset_from_ip(self, ip_value: int, buffer_size: int) -> int:
        """
        从控制的 IP 值计算偏移量
        """
        ip_str = hex(ip_value)
        
        if '4141' in ip_str or '4242' in ip_str:
            return buffer_size - 4
        
        return buffer_size // 2
    
    def generate_crashing_input(, self)
        function_name: str = 'main',
        max_input_size: int = 500
    ) -> Dict[str, Any]:
        """
        生成导致崩溃的输入
        
        Args:
            function_name: 目标函数
            max_input_size: 最大输入大小
            
        Returns:
            崩溃输入生成结果
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用'
            }
        
        try:
            logger.info(f"[angr] 生成崩溃输入 (函数: {function_name})")
            
            func_addr = self._find_function_address(function_name)
            if not func_addr:
                return {
                    'success': False,
                    'error': f'未找到函数 {function_name}'
                }
            
            state = self.project.factory.call_state()
                func_addr,
                add_options={so.SYMBOL_FILL_UNCONSTRAINED_MEMORY, so.REVERSE_MEMORY_NAME_MAP}
            
            
            simgr = self.project.factory.simulation_manager(state)
            simgr.run(n=100)
            
            for stash in ['errored', 'deadended', 'active']:
                if hasattr(simgr, stash):
                    for s in getattr(simgr, stash):
                        if hasattr(s, 'error'):
                            concrete_input = self._get_concrete_input(s)
                            if concrete_input:
                                return {
                                    'success': True,
                                    'input': concrete_input,
                                    'input_hex': concrete_input.hex(),
                                    'input_length': len(concrete_input),
                                    'error': str(s.error)
                                }
                        elif self._check_vulnerable_state(s):
                            concrete_input = self._get_concrete_input(s)
                            if concrete_input:
                                return {
                                    'success': True,
                                    'input': concrete_input,
                                    'input_hex': concrete_input.hex(),
                                    'input_length': len(concrete_input),
                                    'note': '发现可控状态'
                                }
            
            return {
                'success': False,
                'error': '未能生成崩溃输入'
            }
            
        except Exception as e:
            logger.error(f"[angr] 生成崩溃输入失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_attack_path_visualization(, self)
        target_address: int = None
    ) -> Dict[str, Any]:
        """
        获取攻击路径可视化信息
        
        Args:
            target_address: 目标地址（可选）
            
        Returns:
            攻击路径信息
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用'
            }
        
        try:
            logger.info("[angr] 分析攻击路径")
            
            state = self.project.factory.entry_state()
            simgr = self.project.factory.simulation_manager(state)
            
            path_info = {
                'success': True,
                'entry_point': hex(self.project.entry),
                'basic_blocks': [],
                'function_calls': []
            }
            
            for _ in range(30):
                if not simgr.active:
                    break
                simgr.step(num_inst=5)
                
                for active in simgr.active:
                    path_info['basic_blocks'].append(hex(active.addr

            
            path_info['basic_blocks'] = list(dict.fromkeys(path_info['basic_blocks']))[:20]
            
            logger.info(f"[angr] 发现 {len(path_info['basic_blocks'])} 个基本块")
            
            return path_info
            
        except Exception as e:
            logger.error(f"[angr] 获取攻击路径失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def full_analysis(, self)
        function_name: str = 'main'
    ) -> Dict[str, Any]:
        """
        执行完整的符号执行分析
        
        Args:
            function_name: 目标函数
            
        Returns:
            完整分析结果
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用',
                'recommendation': '请安装 angr: pip install angr'
            }
        
        logger.info("[angr] 开始完整符号执行分析")
        
        results = {
            'success': True,
            'crash_path': None,
            'stack_offset': None,
            'crashing_input': None,
            'attack_path': None
        }
        
        try:
            results['crash_path'] = self.find_crash_path()
        except Exception as e:
            results['crash_path'] = {'success': False, 'error': str(e)}
        
        try:
            results['stack_offset'] = self.calculate_stack_offset(function_name)
        except Exception as e:
            results['stack_offset'] = {'success': False, 'error': str(e)}
        
        try:
            results['crashing_input'] = self.generate_crashing_input(function_name)
        except Exception as e:
            results['crashing_input'] = {'success': False, 'error': str(e)}
        
        try:
            results['attack_path'] = self.get_attack_path_visualization()
        except Exception as e:
            results['attack_path'] = {'success': False, 'error': str(e)}
        
        logger.info("[angr] 符号执行分析完成")
        
        return results
    
    DANGEROUS_FUNCTIONS = [
        'gets', 'scanf', 'read', 'fread', 'fgets',
        'strcpy', 'strcat', 'sprintf', 'vsprintf',
        'memcpy', 'memmove',
        'system', 'execve', 'popen',
        'malloc', 'free',
    ]
    
    def find_dangerous_functions(self) -> List[str]:
        """
        在二进制中查找危险函数
        
        Returns:
            找到的危险函数名列表
        """
        if not self.is_available():
            return []
        
        try:
            found = []
            obj = self.project.loader.main_object
            
            if hasattr(obj, 'symbols'):
                for name in obj.symbols.keys():
                    clean_name = name,
                    if clean_name.startswith('sym.'):
                        clean_name = clean_name[4:]
                    if clean_name.startswith('plt.'):
                        clean_name = clean_name[4:]
                    
                    if clean_name in self.DANGEROUS_FUNCTIONS:
                        found.append(clean_name)
            
            if hasattr(self.project, 'kb') and hasattr(self.project.kb, 'functions'):
                for func_name in self.project.kb.functions.keys():
                    if func_name in self.DANGEROUS_FUNCTIONS and func_name not in found:
                        found.append(func_name)
            
            logger.info(f"[angr] 找到 {len(found)} 个危险函数: {found}")
            return list(dict.fromkeys(found

            
        except Exception as e:
            logger.error(f"[angr] 查找危险函数失败: {e}")
            return []
    
    def _find_functions_calling_dangerous(self, dangerous_funcs: List[str]) -> List[Tuple[str, int]]:
        """
        查找调用了危险函数的函数
        
        Returns:
            列表 [(函数名, 地址), ...]
        """
        if not self.is_available():
            return []
        
        try:
            result = []
            dangerous_addrs = set()
            
            obj = self.project.loader.main_object,
            if hasattr(obj, 'symbols'):
                for name, symbol in obj.symbols.items():
                    clean_name = name,
                    if clean_name.startswith('sym.'):
                        clean_name = clean_name[4:]
                    if clean_name in dangerous_funcs:
                        dangerous_addrs.add(symbol.rebased_addr)
            
            if hasattr(self.project, 'kb') and hasattr(self.project.kb, 'functions'):
                for func_name, func in self.project.kb.functions.items():
                    try:
                        for block in func.blocks:
                            for insn in block.disassembly.insns:
                                if insn.insn_name() in ['call', 'bl', 'jal', 'jalr']:
                                    if hasattr(insn, 'op_str'):
                                        op_str = insn.op_str,
                                        for danger_func in dangerous_funcs:
                                            if danger_func in op_str.lower():
                                                result.append((func_name, func.addr

                                                break
                    except Exception:
                        continue
            
            return list(dict.fromkeys(result

            
        except Exception as e:
            logger.debug(f"[angr] 查找危险函数调用者失败: {e}")
            return []
    
    def auto_explore_dangerous_functions(, self)
        dangerous_funcs_list: List[str] = None,
        max_per_func: int = 50
    ) -> Optional[Dict[str, Any]]:
        """
        自动探索危险函数，寻找可触发的崩溃
        
        Args:
            dangerous_funcs_list: 危险函数名列表（如果为 None 则自动检测）
            max_per_func: 每个函数的最大探索步数
            
        Returns:
            第一个成功触发的崩溃状态，如果没有找到则返回 None
        """
        if not self.is_available():
            return None
        
        try:
            if not dangerous_funcs_list:
                dangerous_funcs_list = self.find_dangerous_functions()
            
            if not dangerous_funcs_list:
                logger.info("[angr] 未检测到危险函数，跳过自动探索")
                return None
            
            logger.info(f"[angr] 开始自动探索危险函数: {dangerous_funcs_list}")
            
            target_funcs = self._find_functions_calling_dangerous(dangerous_funcs_list)
            
            if not target_funcs:
                logger.info("[angr] 未找到调用危险函数的函数，尝试直接探索入口点")
                result = self._explore_function(self.project.entry, max_steps=max_per_func * 2)
                if result:
                    return result
            else:
                logger.info(f"[angr] 找到 {len(target_funcs)} 个调用危险函数的目标")
                
                for func_name, func_addr in target_funcs:
                    logger.info(f"[angr] 探索函数 {func_name} ({hex(func_addr)})")
                    
                    result = self._explore_function(func_addr, max_steps=max_per_func)
                    if result:
                        logger.warning(f"[angr] 在函数 {func_name} 中发现可触发的崩溃！")
                        return result
            
            logger.info("[angr] 自动探索完成，未发现可触发的崩溃")
            return None
            
        except Exception as e:
            logger.error(f"[angr] 自动探索危险函数失败: {e}")
            return None
    
    def _explore_function(, self)
        func_addr: int,
        max_steps: int = 50
    ) -> Optional[Dict[str, Any]]:
        """
        探索指定函数，寻找崩溃
        
        Returns:
            崩溃信息字典，如果没有崩溃则返回 None
        """
        try:
            state = self.project.factory.call_state()
                func_addr,
                add_options={so.SYMBOL_FILL_UNCONSTRAINED_MEMORY, so.REVERSE_MEMORY_NAME_MAP}
            
            
            simgr = self.project.factory.simulation_manager(state)
            
            for step in range(max_steps):
                try:
                    simgr.step(num_inst=1)
                    
                    if simgr.errored:
                        for errored in simgr.errored:
                            error_info = self._analyze_error(errored)
                            if error_info:
                                concrete_input = self._get_concrete_input(errored.state)
                                
                                return {
                                    'success': True,
                                    'type': 'auto_discovered',
                                    'function_address': hex(func_addr),
                                    'crash_type': error_info.get('type', 'Unknown'),
                                    'crash_address': error_info.get('address', '0x0'),
                                    'crashing_input': concrete_input,
                                    'crashing_input_hex': concrete_input.hex() if concrete_input else None,
                                    'input_length': len(concrete_input) if concrete_input else 0,
                                    'error': error_info.get('error', ''),
                                    'state_info': self._get_state_info(errored.state)
                                }
                    
                    if simgr.deadended:
                        for dead in simgr.deadended:
                            if self._check_vulnerable_state(dead):
                                concrete_input = self._get_concrete_input(dead)
                                
                                return {
                                    'success': True,
                                    'type': 'auto_discovered',
                                    'function_address': hex(func_addr),
                                    'crash_type': 'Controllable State',
                                    'crash_address': hex(dead.addr),
                                    'crashing_input': concrete_input,
                                    'crashing_input_hex': concrete_input.hex() if concrete_input else None,
                                    'input_length': len(concrete_input) if concrete_input else 0,
                                    'note': '发现可控的程序状态',
                                    'state_info': self._get_state_info(dead)
                                }
                    
                    if not simgr.active:
                        break
                        
                except Exception as e:
                    logger.debug(f"[angr] 探索步骤 {step} 出错: {e}")
                    break
            
            return None
            
        except Exception as e:
            logger.debug(f"[angr] 探索函数 {hex(func_addr)} 失败: {e}")
            return None
    
    SENSITIVE_SINKS = [
        'system', 'execve', 'popen', 'execl', 'execlp', 'execle',
        'execv', 'execvp', 'execvpe',
        'system@plt', 'execve@plt',
        'sym.imp.system', 'sym.imp.execve'
    ]
    
    def run_taint_analysis(, self)
        function_name: str = 'main',
        source_type: str = 'stdin',
        max_steps: int = 100
    ) -> Dict[str, Any]:
        """
        执行基本的污点分析
        
        Args:
            function_name: 目标函数名
            source_type: 污点源类型 ('stdin', 'arg', 'env', 'socket')
            max_steps: 最大探索步数
            
        Returns:
            污点分析结果
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用',
                'tainted_paths': [],
                'sensitive_reached': []
            }
        
        try:
            logger.info(f"[angr] 开始污点分析 (源: {source_type})")
            
            func_addr = self._find_function_address(function_name)
            if not func_addr:
                return {
                    'success': False,
                    'error': f'未找到函数 {function_name}',
                    'tainted_paths': [],
                    'sensitive_reached': []
                }
            
            state = self.project.factory.call_state()
                func_addr,
                add_options={
                    so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    so.REVERSE_MEMORY_NAME_MAP,
                    so.TRACK_ACTION_HISTORY
                }
            
            
            self._mark_taint_source(state, source_type)
            
            simgr = self.project.factory.simulation_manager(state)
            tainted_paths = []
            sensitive_reached = []
            
            for step in range(max_steps):
                try:
                    simgr.step(num_inst=1)
                    
                    for active in simgr.active:
                        current_addr = active.addr
                        func_name_at_addr = self._get_function_name_at(current_addr)
                        
                        if func_name_at_addr:
                            if any(sink in func_name_at_addr for sink in self.SENSITIVE_SINKS):
                                tainted_info = self._check_taint_at_sink(active, source_type)
                                if tainted_info['is_tainted']:
                                    sensitive_reached.append({)
                                        'sink': func_name_at_addr,
                                        'address': hex(current_addr),
                                        'tainted_args': tainted_info['tainted_args'],
                                        'input': self._get_concrete_input(active)
                                    }
                                    logger.warning(f"[angr] 发现污染路径到敏感汇点: {func_name_at_addr} @ {hex(current_addr)}")
                    
                    if not simgr.active:
                        break
                        
                except Exception as e:
                    logger.debug(f"[angr] 污点分析步骤 {step} 出错: {e}")
                    break
            
            return {
                'success': True,
                'source_type': source_type,
                'tainted_paths_count': len(tainted_paths),
                'sensitive_reached': sensitive_reached,
                'recommendation': self._get_taint_recommendation(sensitive_reached)
            }
            
        except Exception as e:
            logger.error(f"[angr] 污点分析失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'tainted_paths': [],
                'sensitive_reached': []
            }
    
    def _mark_taint_source(self, state, source_type: str):
        """
        标记污点源
        """
        try:
            if source_type == 'stdin':
                if hasattr(state, 'posix') and hasattr(state.posix, 'stdin'):
                    pass
            elif source_type == 'arg':
                if hasattr(state.regs, 'rdi'):
                    state.regs.rdi = claripy.BVS('tainted_arg', 64)
                elif hasattr(state.regs, 'r0'):
                    state.regs.r0 = claripy.BVS('tainted_arg', 32)
                elif hasattr(state.regs, 'a0'):
                    state.regs.a0 = claripy.BVS('tainted_arg', 64)
        except Exception as e:
            logger.debug(f"[angr] 标记污点源失败: {e}")
    
    def _get_function_name_at(self, addr: int) -> Optional[str]:
        """
        获取地址处的函数名
        """
        try:
            if hasattr(self.project, 'kb') and hasattr(self.project.kb, 'functions'):
                for func_name, func in self.project.kb.functions.items():
                    if func.addr <= addr < func.addr + func.size:
                        return func_name
            
            obj = self.project.loader.main_object,
            if hasattr(obj, 'symbols'):
                for name, symbol in obj.symbols.items():
                    if symbol.rebased_addr == addr:
                        return name
        except Exception:
            pass
        return None
    
    def _check_taint_at_sink(self, state, source_type: str) -> Dict[str, Any]:
        """
        检查汇点处的参数是否被污染
        """
        result = {
            'is_tainted': False,
            'tainted_args': []
        }
        
        try:
            arg_regs = []
            bits = self.arch_info.get('bits', 64) if self.arch_info else 64
            family = self.arch_info.get('family', 'x86') if self.arch_info else 'x86'
            
            if family == 'x86':
                if bits == 64:
                    arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                else:
                    pass
            elif family == 'ARM':
                if bits == 64:
                    arg_regs = ['x0', 'x1', 'x2', 'x3']
                else:
                    arg_regs = ['r0', 'r1', 'r2', 'r3']
            elif family == 'MIPS':
                arg_regs = ['a0', 'a1', 'a2', 'a3']
            elif family == 'RISC-V':
                arg_regs = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5']
            
            for i, reg_name in enumerate(arg_regs):
                if hasattr(state.regs, reg_name):
                    reg_val = getattr(state.regs, reg_name)
                    if state.solver.symbolic(reg_val):
                        result['is_tainted'] = True
                        result['tainted_args'].append({)
                            'arg_index': i,
                            'register': reg_name,
                            'is_symbolic': True
                        }
        
        except Exception as e:
            logger.debug(f"[angr] 检查污染失败: {e}")
        
        return result
    
    def _get_taint_recommendation(self, sensitive_reached: List[Dict]) -> str:
        """
        根据污点分析结果生成建议
        """
        if not sensitive_reached:
            return "未发现直接的污染路径到敏感汇点，可能需要更深入的分析"
        
        sinks = set(item['sink'] for item in sensitive_reached)
        if 'system' in str(sinks) or 'exec' in str(sinks):
            return "发现潜在的命令注入漏洞！用户输入可能直接传递给 system/execve"
        
        return f"发现 {len(sensitive_reached)} 个污染路径到敏感汇点，需要进一步验证"
    
    def get_arch_info(self) -> Dict[str, Any]:
        """
        获取当前二进制的架构信息
        """
        if self.arch_info:
            return self.arch_info
        
        if self.project:
            self.arch_info = self._extract_arch_info()
            return self.arch_info
        
        return {'supported': False, 'error': '项目未加载'}
    
    def launch_angr_explorer(self, port: int = 5000, browser: bool = True) -> Dict[str, Any]:
        """
        启动 angr-explorer 可视化界面
        
        Args:
            port: Web 服务端口
            browser: 是否自动打开浏览器
            
        Returns:
            启动结果
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用'
            }
        
        if not ANGR_EXPLORER_AVAILABLE:
            return {
                'success': False,
                'error': 'angr-explorer 未安装',
                'install_command': 'pip install angr-explorer'
            }
        
        try:
            logger.info(f"[angr] 启动 angr-explorer 可视化界面 (端口: {port})")
            
            import threading
            import webbrowser
            import tempfile
            import json
            
            explorer_info = {
                'binary_path': self.binary_path,
                'arch_info': self.arch_info,
                'port': port,
                'url': f'http://127.0.0.1:{port}'
            }
            
            def run_explorer():
                try:
                    from angr_explorer import Explorer
                    explorer = Explorer(self.project)
                    explorer.run(port=port, debug=False)
                except Exception as e:
                    logger.error(f"[angr] angr-explorer 运行失败: {e}")
            
            thread = threading.Thread(target=run_explorer, daemon=True)
            thread.start()
            
            import time
            time.sleep(2)
            
            if browser:
                try:
                    webbrowser.open(f'http://127.0.0.1:{port}')
                except Exception:
                    pass
            
            logger.info(f"[angr] angr-explorer 已启动: http://127.0.0.1:{port}")
            
            return {
                'success': True,
                'url': f'http://127.0.0.1:{port}',
                'port': port,
                'thread_running': True,
                'info': explorer_info
            }
            
        except Exception as e:
            logger.error(f"[angr] 启动 angr-explorer 失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_visualization_data(self) -> Dict[str, Any]:
        """
        生成可视化数据（不依赖 angr-explorer）
        
        Returns:
            可视化数据字典
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'angr 不可用'
            }
        
        try:
            logger.info("[angr] 生成可视化数据")
            
            viz_data = {
                'success': True,
                'binary': self.binary_path,
                'arch_info': self.arch_info,
                'entry_point': hex(self.project.entry),
                'basic_blocks': [],
                'function_calls': [],
                'cfg_nodes': []
            }
            
            if hasattr(self.project, 'kb') and hasattr(self.project.kb, 'functions'):
                for func_name, func in self.project.kb.functions.items():
                    func_info = {
                        'name': func_name,
                        'address': hex(func.addr),
                        'size': func.size,
                        'blocks': []
                    }
                    
                    try:
                        for block in func.blocks:
                            func_info['blocks'].append(hex(block.addr

                            viz_data['basic_blocks'].append({)
                                'address': hex(block.addr),
                                'function': func_name,
                                'size': block.size
                            }
                    except Exception:
                        pass
                    
                    viz_data['function_calls'].append(func_info)
            
            viz_data['function_count'] = len(viz_data['function_calls'])
            viz_data['block_count'] = len(viz_data['basic_blocks'])
            
            logger.info(f"[angr] 生成可视化数据: {viz_data['function_count']} 个函数, {viz_data['block_count']} 个基本块")
            
            return viz_data
            
        except Exception as e:
            logger.error(f"[angr] 生成可视化数据失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def comprehensive_analysis(, self)
        function_name: str = 'main',
        enable_taint: bool = True,
        enable_visualization: bool = False
    ) -> Dict[str, Any]:
        """
        执行全面的符号执行分析
        
        Args:
            function_name: 目标函数
            enable_taint: 是否启用污点分析
            enable_visualization: 是否生成可视化数据
            
        Returns:
            全面分析结果
        """
        logger.info("[angr] 开始全面分析")
        
        results = {
            'success': True,
            'arch_info': self.get_arch_info(),
            'basic_analysis': None,
            'taint_analysis': None,
            'visualization': None,
            'dangerous_functions': None
        }
        
        try:
            results['basic_analysis'] = self.full_analysis(function_name)
        except Exception as e:
            results['basic_analysis'] = {'success': False, 'error': str(e)}
        
        try:
            results['dangerous_functions'] = self.find_dangerous_functions()
        except Exception as e:
            results['dangerous_functions'] = []
        
        if enable_taint:
            try:
                results['taint_analysis'] = self.run_taint_analysis(function_name)
            except Exception as e:
                results['taint_analysis'] = {'success': False, 'error': str(e)}
        
        if enable_visualization:
            try:
                results['visualization'] = self.generate_visualization_data()
            except Exception as e:
                results['visualization'] = {'success': False, 'error': str(e)}
        
        logger.info("[angr] 全面分析完成")
        return results
    
    def export_corpus(, self)
        output_dir: str = './corpus',
        max_files: int = 100,
        exploration_steps: int = 50
    ) -> List[str]:
        """
        将符号执行产生的新输入导出为语料文件，供 libFuzzer/AFL 使用
        
        Args:
            output_dir: 语料输出目录
            max_files: 最大导出文件数
            exploration_steps: 探索步数
            
        Returns:
            导出的语料文件路径列表
        """
        if not self.is_available():
            logger.warning("[angr] 符号执行不可用，无法导出语料")
            return []
        
        try:
            logger.info(f"[angr] 导出语料到: {output_dir}")
            
            os.makedirs(output_dir, exist_ok=True)
            
            generated_inputs = []
            
            state = self.project.factory.entry_state()
                add_options={
                    so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    so.REVERSE_MEMORY_NAME_MAP
                }
            
            
            simgr = self.project.factory.simulation_manager(state)
            
            for step in range(exploration_steps):
                if not simgr.active:
                    break
                try:
                    simgr.step(num_inst=1)
                    
                    for stash_name in ['deadended', 'active']:
                        if hasattr(simgr, stash_name):
                            for s in getattr(simgr, stash_name):
                                concrete_input = self._get_concrete_input(s)
                                if concrete_input and len(concrete_input) > 0:
                                    if concrete_input not in generated_inputs:
                                        generated_inputs.append(concrete_input)
                                        
                                        if len(generated_inputs) >= max_files:
                                            break
                except Exception:
                    continue
                
                if len(generated_inputs) >= max_files:
                    break
            
            if not generated_inputs:
                logger.info("[angr] 使用备用策略生成语料...")
                for i in range(10):
                    variant = self._generate_variant_input(i)
                    if variant:
                        generated_inputs.append(variant)
            
            exported_files = []
            
            for idx, data in enumerate(generated_inputs[:max_files]):
                filename = f"id_{idx:06d}_{self._hash_input(data)[:8]}"
                filepath = os.path.join(output_dir, filename)
                
                with open(filepath, 'wb') as f:
                    f.write(data)
                
                exported_files.append(filepath)
                
                logger.debug(f"[angr] 导出语料: {filepath} ({len(data)} bytes)")
            
            logger.info(f"[angr] 已导出 {len(exported_files)} 个语料文件到 {output_dir}")
            
            if exported_files:
                self._write_corpus_readme(output_dir, generated_inputs)
            
            return exported_files
            
        except Exception as e:
            logger.error(f"[angr] 导出语料失败: {e}")
            return []
    
    def _generate_variant_input(self, variant_id: int) -> Optional[bytes]:
        """
        生成变体输入（备用策略）
        """
        try:
            patterns = [
                b'A' * 64,
                b'AAAA' + b'B' * 60,
                b'%n%n%n%n',
                b'/bin/sh\x00',
                b'0123456789abcdef',
                b'\x00' * 16,
                b'\xff' * 32,
                cyclic(64).encode() if 'cyclic' in dir() else b'cyclic_pattern_' * 4,
            ]
            
            if variant_id < len(patterns):
                return patterns[variant_id]
            
            import random
            return bytes([random.randint(0, 255) for _ in range(32)])
        except Exception:
            return None
    
    def _hash_input(self, data: bytes) -> str:
        """
        计算输入的哈希值，用于生成唯一文件名
        """
        import hashlib
        return hashlib.md5(data).hexdigest()
    
    def _write_corpus_readme(self, output_dir: str, inputs: List[bytes]) -> None:
        """
        写入语料库 README 文件
        """
        readme_path = os.path.join(output_dir, 'README.txt')
        
        total_size = sum(len(d) for d in inputs)
        avg_size = total_size // len(inputs) if inputs else 0
        
        readme_content = f"""Deemo LLM Vuln Analyzer - Symbolic Execution Corpus
================================================

Generated by: Deemo's Symbolic Executor (angr)
Generated at: {__import__('datetime').datetime.now().isoformat()}
Total files: {len(inputs)}
Total size: {total_size} bytes
Average size: {avg_size} bytes

Usage:
------
libFuzzer:
    clang -fsanitize=fuzzer,address harness.c -o harness
    ./harness -max_total_time=60 {output_dir}

AFL++:
    afl-fuzz -i {output_dir} -o output_dir -- ./target_binary

Notes:
------
- These inputs were generated by symbolic execution
- They may include edge cases and path-covering inputs
- Combine with manual corpus for best coverage
"""
        
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)


class HybridSymbolicExecutor:
    """
    混合符号执行分析器 - 结合 angr 和 Unicorn Engine
    
    该分析器将符号执行（angr）与动态模拟（Unicorn Engine）相结合，
    以处理自修改代码、加密字符串和重度混淆的二进制文件。
    """
    
    def __init__(self, binary_path: str, target_arch: str = None):
        """
        初始化混合符号执行器
        
        Args:
            binary_path: 二进制文件路径
            target_arch: 目标架构（可选）
        """
        self.binary_path = binary_path
        self.target_arch = target_arch
        self.symbolic_executor = SymbolicExecutor(binary_path, target_arch)
        self.unicorn_available = False
        self.unicorn_analyzer = None
        
        self._init_unicorn()
    
    def _init_unicorn(self):
        """
        初始化 Unicorn Engine
        """
        try:
            from modules.unicorn_hybrid import UnicornHybridAnalyzer, UnicornArch
            
            arch_map = {
                'x86_64': UnicornArch.X86_64,
                'amd64': UnicornArch.X86_64,
                'x86': UnicornArch.X86,
                'i386': UnicornArch.X86,
                'arm64': UnicornArch.ARM64,
                'aarch64': UnicornArch.ARM64,
                'arm': UnicornArch.ARM,
            }
            
            arch_info = self.symbolic_executor.get_arch_info()
            arch_name = arch_info.get('arch', 'unknown').lower()
            
            unicorn_arch = arch_map.get(arch_name, UnicornArch.X86_64)
            self.unicorn_analyzer = UnicornHybridAnalyzer(str(self.binary_path), unicorn_arch)
            self.unicorn_available = True
            logger.info("[Hybrid] Unicorn Engine 初始化成功")
        except ImportError:
            logger.warning("[Hybrid] Unicorn Engine 未安装，混合分析功能不可用")
            logger.warning("[Hybrid] 安装命令: pip install unicorn")
        except Exception as e:
            logger.error(f"[Hybrid] 初始化 Unicorn Engine 失败: {e}")
    
    def is_available(self) -> bool:
        """
        检查混合分析是否可用
        """
        return self.symbolic_executor.is_available( or self.unicorn_available)
    
    def run_hybrid_analysis(, self)
        function_name: str = 'main',
        max_symbolic_steps: int = 50000,
        max_unicorn_instructions: int = 50000
    ) -> Dict[str, Any]:
        """
        执行混合分析
        
        Args:
            function_name: 目标函数名
            max_symbolic_steps: 符号执行最大步数
            max_unicorn_instructions: Unicorn 模拟最大指令数
            
        Returns:
            混合分析结果
        """
        results = {
            'success': False,
            'symbolic_analysis': None,
            'unicorn_analysis': None,
            'hybrid_results': None,
            'error': None
        }
        
        try:
            logger.info("[Hybrid] 开始混合符号执行分析")
            
            symbolic_info = {}
            if self.symbolic_executor.is_available():
                logger.info("[Hybrid] 执行符号分析")
                try:
                    symbolic_info = self.symbolic_executor.comprehensive_analysis(function_name)
                    results['symbolic_analysis'] = symbolic_info
                except Exception as e:
                    logger.warning(f"[Hybrid] 符号分析部分失败: {e}")
                    results['error'] = f"符号分析失败: {e}"
            
            unicorn_results = {}
            if self.unicorn_available:
                logger.info("[Hybrid] 执行 Unicorn 动态分析")
                try:
                    unicorn_results = self._run_unicorn_analysis(symbolic_info, max_unicorn_instructions)
                    results['unicorn_analysis'] = unicorn_results
                except Exception as e:
                    logger.warning(f"[Hybrid] Unicorn 分析部分失败: {e}")
                    if not results['error']:
                        results['error'] = f"Unicorn 分析失败: {e}"
            
            results['hybrid_results'] = self._combine_results(symbolic_info, unicorn_results)
            results['success'] = True
            
            logger.info("[Hybrid] 混合分析完成")
            
        except Exception as e:
            logger.error(f"[Hybrid] 混合分析失败: {e}")
            results['error'] = str(e)
        
        return results
    
    def _run_unicorn_analysis(self, symbolic_info: Dict[str, Any], max_instructions: int) -> Dict[str, Any]:
        """
        运行 Unicorn 分析
        
        Args:
            symbolic_info: 符号分析结果（用于指导 Unicorn 分析）
            max_instructions: 最大指令数
            
        Returns:
            Unicorn 分析结果
        """
        try:
            if not self.unicorn_analyzer:
                return {}
            
            info_for_unicorn = {}
            
            if symbolic_info:
                dangerous_funcs = symbolic_info.get('dangerous_functions', [])
                if dangerous_funcs:
                    info_for_unicorn['complex_functions'] = []
                    for func_name in dangerous_funcs[:5]:
                        func_addr = self.symbolic_executor._find_function_address(func_name)
                        if func_addr:
                            info_for_unicorn['complex_functions'].append(func_addr)
                
                basic_analysis = symbolic_info.get('basic_analysis', {})
                crash_path = basic_analysis.get('crash_path', {})
                if crash_path.get('found'):
                    info_for_unicorn['entry_point'] = self.symbolic_executor.project.entry if self.symbolic_executor.project else 0
            
            result = self.unicorn_analyzer.hybrid_analysis(info_for_unicorn)
            
            return {
                'hidden_strings': result.hidden_strings,
                'dynamic_jump_targets': list(result.dynamic_jump_targets),
                'simplified_constraints': result.simplified_constraints,
                'decrypted_data': result.decrypted_data,
                'deobfuscated_cfg': result.deobfuscated_cfg,
                'execution_log': result.execution_log[:100]
            }
        except Exception as e:
            logger.error(f"[Hybrid] Unicorn 分析执行失败: {e}")
            return {}
    
    def _combine_results(self, symbolic_info: Dict[str, Any], unicorn_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        合并符号分析和 Unicorn 分析结果
        
        Args:
            symbolic_info: 符号分析结果
            unicorn_results: Unicorn 分析结果
            
        Returns:
            合并后的结果
        """
        combined = {
            'enhanced_strings': [],
            'resolved_jump_targets': [],
            'deobfuscation_info': {},
            'recommendations': []
        }
        
        symbolic_strings = []
        if symbolic_info:
            basic = symbolic_info.get('basic_analysis', {})
            crash_input = basic.get('crashing_input', {})
            if crash_input.get('success'):
                combined['recommendations'].append("符号执行发现可触发崩溃的输入")
        
        unicorn_strings = unicorn_results.get('hidden_strings', [])
        combined['enhanced_strings'] = unicorn_strings
        
        if unicorn_strings:
            combined['recommendations'].append(f"Unicorn 提取了 {len(unicorn_strings)} 个隐藏字符串")
        
        jump_targets = unicorn_results.get('dynamic_jump_targets', [])
        combined['resolved_jump_targets'] = jump_targets
        
        if jump_targets:
            combined['recommendations'].append(f"Unicorn 解析了 {len(jump_targets)} 个动态跳转目标")
        
        cfg = unicorn_results.get('deobfuscated_cfg')
        if cfg:
            combined['deobfuscation_info']['cfg_nodes'] = len(cfg)
            combined['deobfuscation_info']['is_deobfuscated'] = True
            combined['recommendations'].append("成功生成去混淆后的控制流图")
        
        decrypted_data = unicorn_results.get('decrypted_data', [])
        if decrypted_data:
            combined['deobfuscation_info']['decrypted_chunks'] = len(decrypted_data)
            combined['recommendations'].append(f"解密了 {len(decrypted_data)} 个数据块")
        
        return combined
    
    def decrypt_encrypted_strings(self, function_name: str = None) -> List[Tuple[int, str]]:
        """
        使用 Unicorn 解密加密字符串
        
        Args:
            function_name: 解密函数名（可选）
            
        Returns:
            解密后的字符串列表 [(地址, 字符串), ...]
        """
        if not self.unicorn_available:
            return []
        
        try:
            logger.info(f"[Hybrid] 尝试解密加密字符串")
            
            if function_name:
                func_addr = self.symbolic_executor._find_function_address(function_name)
                if func_addr:
                    logger.info(f"[Hybrid] 使用解密函数: {function_name} @ {hex(func_addr)}")
                else:
                    logger.warning(f"[Hybrid] 未找到解密函数: {function_name}")
                    return []
            
            unicorn_results = self._run_unicorn_analysis({}, 100000)
            hidden_strings = unicorn_results.get('hidden_strings', [])
            
            decrypted = []
            for addr, string in hidden_strings:
                if len(string) >= 4:
                    decrypted.append((addr, string

            
            logger.info(f"[Hybrid] 解密完成，发现 {len(decrypted)} 个字符串")
            return decrypted
        
        except Exception as e:
            logger.error(f"[Hybrid] 解密字符串失败: {e}")
            return []
    
    def deobfuscate_control_flow(self, function_name: str = 'main') -> Dict[str, Any]:
        """
        使用 Unicorn 去混淆控制流
        
        Args:
            function_name: 目标函数名
            
        Returns:
            去混淆后的控制流信息
        """
        if not self.unicorn_available:
            return {'success': False, 'error': 'Unicorn 不可用'}
        
        try:
            logger.info(f"[Hybrid] 去混淆函数: {function_name}")
            
            func_addr = self.symbolic_executor._find_function_address(function_name)
            if not func_addr:
                return {'success': False, 'error': f'未找到函数 {function_name}'}
            
            result = self.unicorn_analyzer.trace_control_flow(func_addr, max_instructions=50000)
            
            return {
                'success': True,
                'function_name': function_name,
                'function_address': hex(func_addr),
                'basic_blocks': list(result.keys()),
                'edge_count': sum(len(edges) for edges in result.values()),
                'cfg': result
            }
        
        except Exception as e:
            logger.error(f"[Hybrid] 去混淆失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_report(self) -> str:
        """
        生成混合分析报告
        
        Returns:
            报告字符串（Markdown 格式）
        """
        report = "## 混合符号执行分析报告\n\n"
        
        report += "### 分析引擎状态\n"
        report += f"- Symbolic (angr): {'可用' if self.symbolic_executor.is_available() else '不可用'}\n"
        report += f"- Dynamic (Unicorn): {'可用' if self.unicorn_available else '不可用'}\n\n"
        
        if self.unicorn_analyzer:
            report += self.unicorn_analyzer.generate_report()
        
        return report))'