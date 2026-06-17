#!/usr/bin/env python3
"""
虚拟机自省（VMI）辅助内存分析模块

利用LibVMI或QEMU Guest Agent，在虚拟机监视器层面透明地检查运行中进程的内存空间，
提取进程列表、内核模块、系统调用挂钩点，并分析用户态和内核态内存中的恶意代码或漏洞证据。

作者: Deemo Security Team
版本: 1.0.0
"""

import os
import sys
import json
import logging
import tempfile
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Union
from datetime import datetime
from pathlib import Path

# 尝试导入libvmi（可选依赖）
try:
    import libvmi
    VMI_AVAILABLE = True
except ImportError:
    VMI_AVAILABLE = False
    libvmi = None

# 尝试导入qemu相关库
try:
    import qemu.qmp as qemu_qmp
    QEMU_AVAILABLE = True
except ImportError:
    QEMU_AVAILABLE = False
    qemu_qmp = None

from config import Config

logger = logging.getLogger('deemo.vmi_analyzer')


@dataclass
class ProcessInfo:
    """
    进程信息数据结构
    
    Attributes:
        pid: 进程ID
        name: 进程名称
        base_address: 进程基址
        memory_regions: 内存区域列表
        executable_path: 可执行文件路径
        parent_pid: 父进程ID
        user_id: 用户ID
        start_time: 启动时间
        is_kernel: 是否为内核进程
    """
    pid: int
    name: str
    base_address: int = 0
    memory_regions: List[Dict[str, Any]] = field(default_factory=list)
    executable_path: str = ''
    parent_pid: int = 0
    user_id: int = 0
    start_time: str = ''
    is_kernel: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'pid': self.pid,
            'name': self.name,
            'base_address': self.base_address,
            'memory_regions': self.memory_regions,
            'executable_path': self.executable_path,
            'parent_pid': self.parent_pid,
            'user_id': self.user_id,
            'start_time': self.start_time,
            'is_kernel': self.is_kernel
        }


@dataclass
class KernelModule:
    """
    内核模块信息数据结构
    
    Attributes:
        name: 模块名称
        base_address: 模块基址
        size: 模块大小
        dependencies: 依赖模块列表
        symbols: 导出符号列表
    """
    name: str
    base_address: int = 0
    size: int = 0
    dependencies: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'name': self.name,
            'base_address': self.base_address,
            'size': self.size,
            'dependencies': self.dependencies,
            'symbols': self.symbols
        }


@dataclass
class HookPoint:
    """
    系统调用挂钩点数据结构
    
    Attributes:
        hook_type: 挂钩类型（SSDT/IDT/IRP等）
        original_address: 原始地址
        hooked_address: 挂钩后地址
        hooking_module: 挂钩模块名称
        description: 描述信息
        severity: 严重程度
    """
    hook_type: str
    original_address: int = 0
    hooked_address: int = 0
    hooking_module: str = ''
    description: str = ''
    severity: str = 'Medium'
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'hook_type': self.hook_type,
            'original_address': self.original_address,
            'hooked_address': self.hooked_address,
            'hooking_module': self.hooking_module,
            'description': self.description,
            'severity': self.severity
        }


@dataclass
class MemoryDump:
    """
    内存转储数据结构
    
    Attributes:
        process_name: 进程名称
        pid: 进程ID
        dump_path: 转储文件路径
        base_address: 基址
        size: 大小
        sha256_hash: SHA256哈希
        dump_type: 转储类型（code/data/full）
        timestamp: 时间戳
    """
    process_name: str
    pid: int
    dump_path: str
    base_address: int = 0
    size: int = 0
    sha256_hash: str = ''
    dump_type: str = 'full'
    timestamp: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'process_name': self.process_name,
            'pid': self.pid,
            'dump_path': self.dump_path,
            'base_address': self.base_address,
            'size': self.size,
            'sha256_hash': self.sha256_hash,
            'dump_type': self.dump_type,
            'timestamp': self.timestamp
        }


@dataclass
class VMIConfig:
    """
    VMI配置数据结构
    
    Attributes:
        vm_name: 虚拟机名称或ID
        hypervisor_type: 虚拟化平台类型（xen/kvm）
        output_dir: 输出目录
        dump_processes: 是否转储进程内存
        detect_hooks: 是否检测挂钩
        target_pids: 目标进程ID列表
        timeout: 操作超时时间
    """
    vm_name: str = ''
    hypervisor_type: str = 'kvm'
    output_dir: str = './data/vmi_dumps'
    dump_processes: bool = True
    detect_hooks: bool = True
    target_pids: List[int] = field(default_factory=list)
    timeout: int = 300
    
    def validate(self) -> bool:
        """验证配置有效性"""
        if not self.vm_name:
            logger.error("[VMI] 虚拟机名称不能为空")
            return False
        if self.hypervisor_type not in ['xen', 'kvm']:
            logger.error(f"[VMI] 不支持的虚拟化平台: {self.hypervisor_type}")
            return False
        return True


class VMIAnalyzer:
    """
    虚拟机自省（VMI）分析器
    
    利用LibVMI或QEMU Guest Agent在虚拟机监视器层面透明地检查运行中进程的内存空间，
    提取进程列表、内核模块、系统调用挂钩点，并分析用户态和内核态内存中的恶意代码或漏洞证据。
    
    Attributes:
        config: VMI配置
        vmi_instance: LibVMI实例
        qemu_connection: QEMU QMP连接
        processes: 进程列表
        kernel_modules: 内核模块列表
        hooks: 检测到的挂钩点
        memory_dumps: 内存转储列表
    """
    
    # Windows内核结构偏移（需要根据具体版本调整）
    WINDOWS_OFFSETS = {
        'eprocess_link': 0x0,  # EPROCESS.ActiveProcessLinks
        'eprocess_pid': 0xb4,  # EPROCESS.UniqueProcessId
        'eprocess_name': 0xb8,  # EPROCESS.ImageFileName
        'eprocess_base': 0x390,  # EPROCESS.PebBaseAddress
    }
    
    # Linux内核结构偏移
    LINUX_OFFSETS = {
        'task_struct_comm': 0x0,
        'task_struct_pid': 0x0,
        'task_struct_tasks': 0x0,
    }
    
    # SSDT系统调用表索引（Windows）
    SSDT_FUNCTIONS = {
        'NtCreateProcess': 0x00,
        'NtCreateThread': 0x01,
        'NtOpenProcess': 0x02,
        'NtTerminateProcess': 0x03,
        'NtReadVirtualMemory': 0x04,
        'NtWriteVirtualMemory': 0x05,
        'NtAllocateVirtualMemory': 0x06,
        'NtFreeVirtualMemory': 0x07,
        'NtLoadDriver': 0x08,
        'NtUnloadDriver': 0x09,
    }
    
    def __init__(self, config: VMIConfig):
        """
        初始化VMI分析器
        
        Args:
            config: VMI配置对象
        """
        self.config = config
        self.vmi_instance: Optional[Any] = None
        self.qemu_connection: Optional[Any] = None
        self.processes: List[ProcessInfo] = []
        self.kernel_modules: List[KernelModule] = []
        self.hooks: List[HookPoint] = []
        self.memory_dumps: List[MemoryDump] = []
        self.is_connected = False
        self.os_type = 'unknown'
        
        # 验证配置
        if not config.validate():
            raise ValueError("VMI配置验证失败")
        
        # 创建输出目录
        self._setup_output_dir()
        
        logger.info(f"[VMI] 初始化VMI分析器，目标VM: {config.vm_name}")
    
    def _setup_output_dir(self) -> None:
        """设置输出目录"""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"[VMI] 输出目录: {self.config.output_dir}")
    
    def connect(self) -> bool:
        """
        连接到目标虚拟机
        
        Returns:
            连接成功返回True，否则返回False
        """
        if not VMI_AVAILABLE and not QEMU_AVAILABLE:
            logger.warning("[VMI] LibVMI和QEMU库均不可用，使用模拟模式")
            self.is_connected = True,
            return True
        
        try:
            if self.config.hypervisor_type == 'kvm' and QEMU_AVAILABLE:
                return self._connect_qemu()
            elif VMI_AVAILABLE:
                return self._connect_libvmi()
            else:
                logger.warning("[VMI] 无可用连接方式，使用模拟模式")
                self.is_connected = True,
                return True
        except Exception as e:
            logger.error(f"[VMI] 连接失败: {e}")
            return False
    
    def _connect_libvmi(self) -> bool:
        """
        使用LibVMI连接
        
        Returns:
            连接成功返回True
        """
        try:
            # LibVMI初始化
            self.vmi_instance = libvmi.LibVMI()
                self.config.vm_name,
                init_complete=True,
                mode=libvmi.VMI_INIT_COMPLETE
            
            self.is_connected = True
            self.os_type = self.vmi_instance.get_os_type()
            logger.info(f"[VMI] LibVMI连接成功，操作系统类型: {self.os_type}")
            return True
        except Exception as e:
            logger.error(f"[VMI] LibVMI连接失败: {e}")
            return False
    
    def _connect_qemu(self) -> bool:
        """
        使用QEMU QMP连接
        
        Returns:
            连接成功返回True
        """
        try:
            # QEMU QMP连接（需要配置QMP socket路径）
            qmp_socket = os.environ.get('QEMU_QMP_SOCKET', '/tmp/qemu.sock')
            self.qemu_connection = qemu_qmp.QMP(qmp_socket)
            self.qemu_connection.connect()
            self.is_connected = True
            logger.info("[VMI] QEMU QMP连接成功")
            return True
        except Exception as e:
            logger.error(f"[VMI] QEMU连接失败: {e}")
            return False
    
    def disconnect(self) -> None:
        """断开连接"""
        if self.vmi_instance:
            try:
                self.vmi_instance.destroy()
            except Exception as e:
                logger.warning(f"[VMI] LibVMI断开连接失败: {e}")
        
        if self.qemu_connection:
            try:
                self.qemu_connection.disconnect()
            except Exception as e:
                logger.warning(f"[VMI] QEMU断开连接失败: {e}")
        
        self.is_connected = False
        logger.info("[VMI] 已断开连接")
    
    def list_processes(self) -> List[ProcessInfo]:
        """
        遍历进程列表
        
        Returns:
            进程信息列表
        """
        if not self.is_connected:
            logger.warning("[VMI] 未连接到虚拟机")
            return []
        
        self.processes = []
        
        if VMI_AVAILABLE and self.vmi_instance:
            return self._list_processes_libvmi()
        elif QEMU_AVAILABLE and self.qemu_connection:
            return self._list_processes_qemu()
        else:
            # 模拟模式
            return self._list_processes_mock()
    
    def _list_processes_libvmi(self) -> List[ProcessInfo]:
        """
        使用LibVMI遍历进程
        
        Returns:
            进程信息列表
        """
        try:
            # 获取进程列表
            processes = []
            
            if self.os_type == 'windows':
                # Windows进程遍历
                init_task = self.vmi_instance.get_offset('win_init_task')
                current_process = init_task
                
                while True:
                    try:
                        # 读取进程信息
                        pid = self.vmi_instance.read_32_va()
                            current_process + self.WINDOWS_OFFSETS['eprocess_pid'],
                            0
                        
                        name = self.vmi_instance.read_str_va()
                            current_process + self.WINDOWS_OFFSETS['eprocess_name'],
                            0,
                            max_length=16
                        
                        
                        process_info = ProcessInfo()
                            pid=pid,
                            name=name.strip(),
                            base_address=current_process,
                            is_kernel=(pid == 0 or pid == 4)
                        
                        processes.append(process_info)
                        
                        # 遍历下一个进程
                        next_link = self.vmi_instance.read_64_va()
                            current_process + self.WINDOWS_OFFSETS['eprocess_link'],
                            0
                        
                        current_process = next_link - self.WINDOWS_OFFSETS['eprocess_link']
                        
                        if current_process == init_task:
                            break
                    except Exception as e:
                        logger.warning(f"[VMI] 读取进程信息失败: {e}")
                        break
            else:
                # Linux进程遍历
                init_task = self.vmi_instance.get_offset('linux_init_task')
                # 简化实现
                pass
            
            self.processes = processes
            logger.info(f"[VMI] 发现 {len(processes)} 个进程")
            return processes
        except Exception as e:
            logger.error(f"[VMI] 进程遍历失败: {e}")
            return []
    
    def _list_processes_qemu(self) -> List[ProcessInfo]:
        """
        使用QEMU Guest Agent遍历进程
        
        Returns:
            进程信息列表
        """
        try:
            # 通过QMP查询进程信息
            result = self.qemu_connection.execute('guest-get-processes')
            processes = []
            
            for proc_data in result.get('return', []):
                process_info = ProcessInfo()
                    pid=proc_data.get('pid', 0),
                    name=proc_data.get('name', ''),
                    executable_path=proc_data.get('exe', ''),
                    user_id=proc_data.get('uid', 0)
                
                processes.append(process_info)
            
            self.processes = processes
            logger.info(f"[VMI] 通过QEMU发现 {len(processes)} 个进程")
            return processes
        except Exception as e:
            logger.error(f"[VMI] QEMU进程遍历失败: {e}")
            return []
    
    def _list_processes_mock(self) -> List[ProcessInfo]:
        """
        模拟模式下的进程列表
        
        Returns:
            模拟进程信息列表
        """
        mock_processes = [
            ProcessInfo(pid=1, name='init', base_address=0x10000, is_kernel=False),
            ProcessInfo(pid=4, name='system', base_address=0x80000, is_kernel=True),
            ProcessInfo(pid=1234, name='target_app', base_address=0x400000, is_kernel=False),
            ProcessInfo(pid=5678, name='malware_sample', base_address=0x500000, is_kernel=False),
        ]
        self.processes = mock_processes
        logger.info(f"[VMI] 模拟模式：发现 {len(mock_processes)} 个进程")
        return mock_processes
    
    def list_kernel_modules(self) -> List[KernelModule]:
        """
        遍历内核模块
        
        Returns:
            内核模块信息列表
        """
        if not self.is_connected:
            logger.warning("[VMI] 未连接到虚拟机")
            return []
        
        self.kernel_modules = []
        
        if VMI_AVAILABLE and self.vmi_instance:
            return self._list_kernel_modules_libvmi()
        else:
            return self._list_kernel_modules_mock()
    
    def _list_kernel_modules_libvmi(self) -> List[KernelModule]:
        """
        使用LibVMI遍历内核模块
        
        Returns:
            内核模块信息列表
        """
        try:
            modules = []
            
            if self.os_type == 'linux':
                # Linux内核模块遍历
                modules_list = self.vmi_instance.get_offset('linux_modules_list')
                current_module = modules_list
                
                while True:
                    try:
                        name = self.vmi_instance.read_str_va(current_module + 0x0, 0)
                        base = self.vmi_instance.read_64_va(current_module + 0x8, 0)
                        size = self.vmi_instance.read_32_va(current_module + 0x10, 0)
                        
                        module_info = KernelModule()
                            name=name,
                            base_address=base,
                            size=size
                        
                        modules.append(module_info)
                        
                        # 遍历下一个模块
                        next_module = self.vmi_instance.read_64_va(current_module + 0x18, 0)
                        if next_module == modules_list:
                            break
                        current_module = next_module
                    except Exception:
                        break
            
            self.kernel_modules = modules
            logger.info(f"[VMI] 发现 {len(modules)} 个内核模块")
            return modules
        except Exception as e:
            logger.error(f"[VMI] 内核模块遍历失败: {e}")
            return []
    
    def _list_kernel_modules_mock(self) -> List[KernelModule]:
        """
        模拟模式下的内核模块列表
        
        Returns:
            模拟内核模块信息列表
        """
        mock_modules = [
            KernelModule(name='kernel', base_address=0x80000000, size=0x1000000),
            KernelModule(name='ntdll.dll', base_address=0x7FFE0000, size=0x100000),
            KernelModule(name='kernel32.dll', base_address=0x7FFE1000, size=0x80000),
            KernelModule(name='malicious_driver.sys', base_address=0xFFFF8000, size=0x10000),
        ]
        self.kernel_modules = modules = mock_modules
        logger.info(f"[VMI] 模拟模式：发现 {len(mock_modules)} 个内核模块")
        return mock_modules
    
    def read_process_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """
        读取进程内存
        
        Args:
            pid: 进程ID
            address: 内存地址
            size: 读取大小
            
        Returns:
            内存数据，失败返回None
        """
        if not self.is_connected:
            logger.warning("[VMI] 未连接到虚拟机")
            return None
        
        if VMI_AVAILABLE and self.vmi_instance:
            try:
                data = self.vmi_instance.read_va(address, pid, size)
                return data
            except Exception as e:
                logger.error(f"[VMI] 内存读取失败: {e}")
                return None
        else:
            # 模拟模式返回随机数据
            return bytes([i % 256 for i in range(size)])
    
    def dump_process_memory(self, pid: int, dump_type: str = 'full') -> Optional[MemoryDump]:
        """
        转储进程内存
        
        Args:
            pid: 进程ID
            dump_type: 转储类型（code/data/full）
            
        Returns:
            内存转储信息，失败返回None
        """
        if not self.is_connected:
            logger.warning("[VMI] 未连接到虚拟机")
            return None
        
        # 查找进程信息
        process = None,
        for p in self.processes:
            if p.pid == pid:
                process = p
                break
        
        if not process:
            logger.warning(f"[VMI] 未找到进程 {pid}")
            return None
        
        try:
            # 创建转储文件
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dump_filename = f"{process.name}_{pid}_{timestamp}.dmp"
            dump_path = os.path.join(self.config.output_dir, dump_filename)
            
            # 模拟内存转储
            dump_data = bytearray()
            
            if dump_type == 'code':
                # 仅转储代码段
                for region in process.memory_regions:
                    if region.get('type') == 'code':
                        data = self.read_process_memory(pid, region['base'], region['size'])
                        if data:
                            dump_data.extend(data)
            elif dump_type == 'data':
                # 仅转储数据段
                for region in process.memory_regions:
                    if region.get('type') == 'data':
                        data = self.read_process_memory(pid, region['base'], region['size'])
                        if data:
                            dump_data.extend(data)
            else:
                # 全量转储
                dump_data = bytes([i % 256 for i in range(0x10000)])  # 模拟64KB数据
            
            # 写入文件
            with open(dump_path, 'wb') as f:
                f.write(dump_data)
            
            # 计算哈希
            sha256_hash = hashlib.sha256(dump_data).hexdigest()
            
            memory_dump = MemoryDump()
                process_name=process.name,
                pid=pid,
                dump_path=dump_path,
                base_address=process.base_address,
                size=len(dump_data),
                sha256_hash=sha256_hash,
                dump_type=dump_type,
                timestamp=timestamp
            
            
            self.memory_dumps.append(memory_dump)
            logger.info(f"[VMI] 进程 {pid} 内存转储完成: {dump_path}")
            
            return memory_dump
        except Exception as e:
            logger.error(f"[VMI] 内存转储失败: {e}")
            return None
    
    def dump_all_processes(self) -> List[MemoryDump]:
        """
        转储所有进程内存
        
        Returns:
            内存转储列表
        """
        dumps = []
        
        target_pids = self.config.target_pids if self.config.target_pids else [p.pid for p in self.processes]
        
        for pid in target_pids:
            dump = self.dump_process_memory(pid)
            if dump:
                dumps.append(dump)
        
        logger.info(f"[VMI] 完成 {len(dumps)} 个进程的内存转储")
        return dumps
    
    def detect_hooks(self) -> List[HookPoint]:
        """
        检测系统调用挂钩
        
        Returns:
            检测到的挂钩点列表
        """
        if not self.is_connected:
            logger.warning("[VMI] 未连接到虚拟机")
            return []
        
        self.hooks = []
        
        if VMI_AVAILABLE and self.vmi_instance:
            return self._detect_hooks_libvmi()
        else:
            return self._detect_hooks_mock()
    
    def _detect_hooks_libvmi(self) -> List[HookPoint]:
        """
        使用LibVMI检测挂钩
        
        Returns:
            挂钩点列表
        """
        try:
            hooks = []
            
            if self.os_type == 'windows':
                # SSDT挂钩检测
                ssdt_base = self.vmi_instance.get_offset('win_ssdt')
                ssdt_count = self.vmi_instance.get_offset('win_ssdt_count')
                
                for func_name, index in self.SSDT_FUNCTIONS.items():
                    try:
                        # 读取SSDT表项
                        entry_addr = self.vmi_instance.read_32_va(ssdt_base + index * 4, 0)
                        
                        # 检查是否在内核范围内
                        kernel_base = 0x80000000  # Windows内核基址
                        kernel_end = 0xFFFFFFFF
                        
                        if not (kernel_base <= entry_addr <= kernel_end):
                            hook = HookPoint()
                                hook_type='SSDT',
                                original_address=kernel_base + index * 4,
                                hooked_address=entry_addr,
                                hooking_module='Unknown',
                                description=f'{func_name} 被挂钩',
                                severity='High'
                            
                            hooks.append(hook)
                    except Exception as e:
                        logger.warning(f"[VMI] SSDT检测失败: {e}")
            
            self.hooks = hooks
            logger.info(f"[VMI] 发现 {len(hooks)} 个挂钩点")
            return hooks
        except Exception as e:
            logger.error(f"[VMI] 挂钩检测失败: {e}")
            return []
    
    def _detect_hooks_mock(self) -> List[HookPoint]:
        """
        模拟模式下的挂钩检测
        
        Returns:
            模拟挂钩点列表
        """
        mock_hooks = [
            HookPoint()
                hook_type='SSDT',
                original_address=0x80100000,
                hooked_address=0xFFFF8000,
                hooking_module='malicious_driver.sys',
                description='NtCreateProcess 被挂钩',
                severity='High'
            ),
            HookPoint()
                hook_type='IDT',
                original_address=0x80200000,
                hooked_address=0xFFFF9000,
                hooking_module='rootkit.sys',
                description='INT 0x80 被挂钩',
                severity='Critical'
            ),
        ]
        self.hooks = mock_hooks
        logger.info(f"[VMI] 模拟模式：发现 {len(mock_hooks)} 个挂钩点")
        return mock_hooks
    
    def analyze_memory_region(self, pid: int, address: int, size: int) -> Dict[str, Any]:
        """
        分析特定内存区域
        
        Args:
            pid: 进程ID
            address: 内存地址
            size: 区域大小
            
        Returns:
            分析结果字典
        """
        result = {
            'pid': pid,
            'address': address,
            'size': size,
            'analysis_type': 'memory_region',
            'findings': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # 读取内存
        data = self.read_process_memory(pid, address, size)
        if not data:
            result['error'] = '无法读取内存',
            return result
        
        # 基本分析
        result['entropy'] = self._calculate_entropy(data)
        result['has_executable_code'] = self._check_executable_code(data)
        result['suspicious_patterns'] = self._detect_suspicious_patterns(data)
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据熵
        
        Args:
            data: 数据字节
            
        Returns:
            熵值
        """
        if not data:
            return 0.0
        
        byte_counts = [0] * 256,
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability and math.log2(probability

        
        return entropy
    
    def _check_executable_code(self, data: bytes) -> bool:
        """
        检查是否包含可执行代码特征
        
        Args:
            data: 数据字节
            
        Returns:
            是否包含可执行代码
        """
        # 检查常见代码特征
        code_patterns = [
            b'\x55\x8B\xEC',  # 函数入口 push ebp; mov ebp, esp
            b'\xCC',  # int 3 (调试断点)
            b'\xE8',  # call指令
            b'\xFF\xE0',  # jmp eax
        ]
        
        for pattern in code_patterns:
            if pattern in data:
                return True
        
        return False
    
    def _detect_suspicious_patterns(self, data: bytes) -> List[str]:
        """
        检测可疑模式
        
        Args:
            data: 数据字节
            
        Returns:
            可疑模式列表
        """
        patterns = []
        
        # 检测常见恶意代码特征
        suspicious_strings = [
            'CreateRemoteThread',
            'VirtualAllocEx',
            'WriteProcessMemory',
            'NtUnmapViewOfSection',
            'ptrace',
            'mprotect',
        ]
        
        for s in suspicious_strings:
            if s.encode() in data:
                patterns.append(f'发现可疑API: {s}')
        
        # 检测shellcode特征
        if b'\xEB\xFE' in data:  # jmp $-2 (无限循环)
            patterns.append('发现可能的shellcode无限循环')
        
        return patterns
    
    def generate_report(self) -> Dict[str, Any]:
        """
        生成VMI分析报告
        
        Returns:
            分析报告字典
        """
        report = {
            'vm_name': self.config.vm_name,
            'hypervisor_type': self.config.hypervisor_type,
            'analysis_time': datetime.now().isoformat(),
            'summary': {
                'total_processes': len(self.processes),
                'total_kernel_modules': len(self.kernel_modules),
                'total_hooks': len(self.hooks),
                'total_dumps': len(self.memory_dumps),
            },
            'processes': [p.to_dict() for p in self.processes],
            'kernel_modules': [m.to_dict() for m in self.kernel_modules],
            'hooks': [h.to_dict() for h in self.hooks],
            'memory_dumps': [d.to_dict() for d in self.memory_dumps],
            'risk_assessment': self._assess_risk(),
        }
        
        return report
    
    def _assess_risk(self) -> Dict[str, Any]:
        """
        评估风险
        
        Returns:
            风险评估结果
        """
        risk = {
            'overall_level': 'Low',
            'findings': [],
        }
        
        # 检查挂钩风险
        critical_hooks = [h for h in self.hooks if h.severity == 'Critical']
        high_hooks = [h for h in self.hooks if h.severity == 'High']
        
        if critical_hooks:
            risk['overall_level'] = 'Critical'
            risk['findings'].append(f'发现 {len(critical_hooks)} 个严重挂钩')
        elif high_hooks:
            risk['overall_level'] = 'High'
            risk['findings'].append(f'发现 {len(high_hooks)} 个高危挂钩')
        
        # 检查可疑进程
        suspicious_processes = []
        for p in self.processes:
            if any(keyword in p.name.lower() for keyword in ['malware', 'rootkit', 'trojan']):
                suspicious_processes.append(p.name)
        
        if suspicious_processes:
            if risk['overall_level'] == 'Low':
                risk['overall_level'] = 'Medium'
            risk['findings'].append(f'发现可疑进程: {suspicious_processes}')
        
        return risk
    
    def save_report(self, output_path: Optional[str] = None) -> str:
        """
        保存分析报告
        
        Args:
            output_path: 输出路径，默认使用配置目录
            
        Returns:
            保存的文件路径
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join()
                self.config.output_dir,
                f'vmi_report_{self.config.vm_name}_{timestamp}.json'
            
        
        report = self.generate_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[VMI] 报告已保存: {output_path}")
        return output_path
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整VMI分析
        
        Returns:
            分析结果
        """
        logger.info(f"[VMI] 开始分析虚拟机: {self.config.vm_name}")
        
        # 连接
        if not self.connect():
            return {'error': '无法连接到虚拟机'}
        
        try:
            # 遍历进程
            self.list_processes()
            
            # 遍历内核模块
            self.list_kernel_modules()
            
            # 检测挂钩
            if self.config.detect_hooks:
                self.detect_hooks()
            
            # 转储进程内存
            if self.config.dump_processes:
                self.dump_all_processes()
            
            # 生成报告
            report = self.generate_report()
            
            # 保存报告
            self.save_report()
            
            return report
        finally:
            self.disconnect()


# 导入math模块用于熵计算
import math


def create_vmi_analyzer(vm_name: str, **kwargs) -> VMIAnalyzer:
    """
    创建VMI分析器的便捷函数
    
    Args:
        vm_name: 虚拟机名称
        **kwargs: 其他配置参数
        
    Returns:
        VMIAnalyzer实例
    """
    config = VMIConfig(vm_name=vm_name, **kwargs)
    return VMIAnalyzer(config)
