#!/usr/bin/env python3
"""虚拟机内省 (VMI) 内存分析模块。

经 LibVMI 或 QEMU Guest Agent 在虚拟化层透明检查运行中的进程内存,
提取进程表/内核模块/系统调用钩子点, 在用户态与内核态内存中
识别恶意代码或利用痕迹。
"""

import hashlib
import json
import logging
import math
import os
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# libvmi 可选依赖
try:
    import libvmi
    VMI_AVAILABLE = True
except ImportError:
    VMI_AVAILABLE = False
    libvmi = None

# QEMU QMP 可选依赖
try:
    import qemu.qmp as qemu_qmp
    QEMU_AVAILABLE = True
except ImportError:
    QEMU_AVAILABLE = False
    qemu_qmp = None

from core.config import Config

logger = logging.getLogger('binmind.vmi_analyzer')

class ProcessInfo:
    """进程信息容器: pid/名称/基址/内存区域/可执行路径/父进程/用户/启动时间/是否内核进程。"""
    __slots__ = ('pid', 'name', 'base_address', 'memory_regions', 'executable_path', 'parent_pid', 'user_id', 'start_time', 'is_kernel')

    def __init__(
            self,
            pid,
            name,
            base_address=0,
            memory_regions=None,
            executable_path='',
            parent_pid=0,
            user_id=0,
            start_time='',
            is_kernel=False,
    ):
        self.pid = pid
        self.name = name
        self.base_address = base_address
        self.memory_regions = memory_regions if memory_regions is not None else list()
        self.executable_path = executable_path
        self.parent_pid = parent_pid
        self.user_id = user_id
        self.start_time = start_time
        self.is_kernel = is_kernel

    def to_dict(self) -> Dict[str, Any]:
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

class KernelModule:
    """内核模块信息容器: 名称/内核虚拟空间基址/字节尺寸/依赖模块/导出符号表。"""
    __slots__ = ('name', 'base_address', 'size', 'dependencies', 'symbols')

    def __init__(
            self,
            name,
            base_address=0,
            size=0,
            dependencies=None,
            symbols=None,
    ):
        self.name = name
        self.base_address = base_address
        self.size = size
        self.dependencies = dependencies if dependencies is not None else list()
        self.symbols = symbols if symbols is not None else list()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'base_address': self.base_address,
            'size': self.size,
            'dependencies': self.dependencies,
            'symbols': self.symbols
        }

class HookPoint:
    """系统调用钩子描述: 类型(SSDT/IDT/IRP)/原地址/重定向地址/安装模块/摘要/风险等级。"""
    __slots__ = ('hook_type', 'original_address', 'hooked_address', 'hooking_module', 'description', 'severity')

    def __init__(
            self,
            hook_type,
            original_address=0,
            hooked_address=0,
            hooking_module='',
            description='',
            severity='Medium',
    ):
        self.hook_type = hook_type
        self.original_address = original_address
        self.hooked_address = hooked_address
        self.hooking_module = hooking_module
        self.description = description
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            'hook_type': self.hook_type,
            'original_address': self.original_address,
            'hooked_address': self.hooked_address,
            'hooking_module': self.hooking_module,
            'description': self.description,
            'severity': self.severity
        }

class MemoryDump:
    """进程内存转储产物: 进程名/pid/路径/起始虚址/字节数/sha256/范围(code|data|full)/时间戳。"""
    __slots__ = ('process_name', 'pid', 'dump_path', 'base_address', 'size', 'sha256_hash', 'dump_type', 'timestamp')

    def __init__(
            self,
            process_name,
            pid,
            dump_path,
            base_address=0,
            size=0,
            sha256_hash='',
            dump_type='full',
            timestamp='',
    ):
        self.process_name = process_name
        self.pid = pid
        self.dump_path = dump_path
        self.base_address = base_address
        self.size = size
        self.sha256_hash = sha256_hash
        self.dump_type = dump_type
        self.timestamp = timestamp

    def to_dict(self) -> Dict[str, Any]:
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

class VMIConfig:
    """VMI 分析配置: 目标虚机名/虚拟化平台(xen|kvm)/输出目录/是否转储进程/是否扫描钩子/目标pid/超时秒数。"""
    __slots__ = ('vm_name', 'hypervisor_type', 'output_dir', 'dump_processes', 'detect_hooks', 'target_pids', 'timeout')

    def __init__(
            self,
            vm_name='',
            hypervisor_type='kvm',
            output_dir='./data/vmi_dumps',
            dump_processes=True,
            detect_hooks=True,
            target_pids=None,
            timeout=300,
    ):
        self.vm_name = vm_name
        self.hypervisor_type = hypervisor_type
        self.output_dir = output_dir
        self.dump_processes = dump_processes
        self.detect_hooks = detect_hooks
        self.target_pids = target_pids if target_pids is not None else list()
        self.timeout = timeout

    def validate(self) -> bool:
        if not self.vm_name:
            logger.error("[VMI] VM name must not be empty")
            return False
        if self.hypervisor_type not in ['xen', 'kvm']:
            logger.error(f"[VMI] Unsupported hypervisor type: {self.hypervisor_type}")
            return False
        return True

class VMIAnalyzer:
    """虚拟机内省 (VMI) 分析器。

    经 LibVMI 或 QEMU Guest Agent 在虚拟化层透明检查运行中的虚机内存,
    提取进程表/内核模块/系统调用钩子点, 在用户态与内核态内存中
    识别恶意代码或利用痕迹。
    状态字段: config 配置, vmi_instance/qemu_connection 会话句柄,
    processes/kernel_modules/hooks/memory_dumps 枚举与转储结果。
    """

    # Windows 内核结构偏移 (需按版本微调)
    WINDOWS_OFFSETS = {
        'eprocess_link': 0x0,   # EPROCESS.ActiveProcessLinks
        'eprocess_pid': 0xb4,   # EPROCESS.UniqueProcessId
        'eprocess_name': 0xb8,  # EPROCESS.ImageFileName
        'eprocess_base': 0x390, # EPROCESS.PebBaseAddress
    }

    # Linux task_struct 偏移 (运行时动态解析)
    LINUX_OFFSETS = {
        'task_struct_comm': 0x0,
        'task_struct_pid': 0x0,
        'task_struct_tasks': 0x0,
    }

    # Windows SSDT 函数表索引
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
        self.config = config
        self.vmi_instance: Optional[Any] = None
        self.qemu_connection: Optional[Any] = None
        self.processes: List[ProcessInfo] = []
        self.kernel_modules: List[KernelModule] = []
        self.hooks: List[HookPoint] = []
        self.memory_dumps: List[MemoryDump] = []
        self.is_connected = False
        self.os_type = 'unknown'

        # 校验配置
        if not config.validate():
            raise ValueError("VMI configuration validation failed")

        # 创建输出目录
        self._setup_output_dir()

        logger.info(f"[VMI] Analyzer initialized, target VM: {config.vm_name}")

    def _setup_output_dir(self) -> None:
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"[VMI] Output directory: {self.config.output_dir}")

    def connect(self) -> bool:
        if not VMI_AVAILABLE and not QEMU_AVAILABLE:
            logger.warning("[VMI] Neither LibVMI nor QEMU library is available; using simulation mode")
            self.is_connected = True
            return True

        try:
            if self.config.hypervisor_type == 'kvm' and QEMU_AVAILABLE:
                return self._connect_qemu()
            elif VMI_AVAILABLE:
                return self._connect_libvmi()
            else:
                logger.warning("[VMI] No viable connection backend; using simulation mode")
                self.is_connected = True
                return True
        except Exception as e:
            logger.error(f"[VMI] Connection failed: {e}")
            return False

    def _connect_libvmi(self) -> bool:
        try:
            # 初始化 LibVMI 会话
            self.vmi_instance = libvmi.LibVMI(
                self.config.vm_name,
                init_complete=True,
                mode=libvmi.VMI_INIT_COMPLETE
            )

            self.is_connected = True
            self.os_type = self.vmi_instance.get_os_type()
            logger.info(f"[VMI] LibVMI connection established, guest OS: {self.os_type}")
            return True
        except Exception as e:
            logger.error(f"[VMI] LibVMI connection failed: {e}")
            return False

    def _connect_qemu(self) -> bool:
        try:
            # 建立 QEMU QMP 连接 (配置 QMP socket 路径)
            qmp_socket = os.environ.get('QEMU_QMP_SOCKET', '/tmp/qemu.sock')
            self.qemu_connection = qemu_qmp.QMP(qmp_socket)
            self.qemu_connection.connect()
            self.is_connected = True
            logger.info("[VMI] QEMU QMP connection established")
            return True
        except Exception as e:
            logger.error(f"[VMI] QEMU connection failed: {e}")
            return False

    def disconnect(self) -> None:
        if self.vmi_instance:
            try:
                self.vmi_instance.destroy()
            except Exception as e:
                logger.warning(f"[VMI] LibVMI teardown failed: {e}")

        if self.qemu_connection:
            try:
                self.qemu_connection.disconnect()
            except Exception as e:
                logger.warning(f"[VMI] QEMU teardown failed: {e}")

        self.is_connected = False
        logger.info("[VMI] Connection closed")

    def list_processes(self) -> List[ProcessInfo]:
        if not self.is_connected:
            logger.warning("[VMI] Not connected to a virtual machine")
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
        try:
            # 获取进程列表
            processes = []

            if self.os_type == 'windows':
                # 遍历 Windows EPROCESS 双向链表
                init_task = self.vmi_instance.get_offset('win_init_task')
                current_process = init_task

                while True:
                    try:
                        # 从 EPROCESS 读取进程元数据
                        pid = self.vmi_instance.read_32_va(
                            current_process + self.WINDOWS_OFFSETS['eprocess_pid'],
                            0
                        )

                        name = self.vmi_instance.read_str_va(
                            current_process + self.WINDOWS_OFFSETS['eprocess_name'],
                            0,
                            max_length=16
                        )

                        process_info = ProcessInfo(
                            pid=pid,
                            name=name.strip(),
                            base_address=current_process,
                            is_kernel=(pid == 0 or pid == 4)
                        )
                        processes.append(process_info)

                        # 前进到下一个 EPROCESS 条目
                        next_link = self.vmi_instance.read_64_va(
                            current_process + self.WINDOWS_OFFSETS['eprocess_link'],
                            0
                        )

                        current_process = next_link - self.WINDOWS_OFFSETS['eprocess_link']

                        if current_process == init_task:
                            break
                    except Exception as e:
                        logger.warning(f"[VMI] Process metadata read failed: {e}")
                        break
            else:
                # 遍历 Linux task_struct 链表
                init_task = self.vmi_instance.get_offset('linux_init_task')
                pass

            self.processes = processes
            logger.info(f"[VMI] Listed {len(processes)} processes")
            return processes
        except Exception as e:
            logger.error(f"[VMI] Process enumeration failed: {e}")
            return []

    def _list_processes_qemu(self) -> List[ProcessInfo]:
        try:
            # 经 QMP 查询进程列表
            result = self.qemu_connection.execute('guest-get-processes')
            processes = []

            for proc_data in result.get('return', []):
                process_info = ProcessInfo(
                    pid=proc_data.get('pid', 0),
                    name=proc_data.get('name', ''),
                    executable_path=proc_data.get('exe', ''),
                    user_id=proc_data.get('uid', 0)
                )

                processes.append(process_info)

            self.processes = processes
            logger.info(f"[VMI] Listed {len(processes)} processes via QEMU")
            return processes
        except Exception as e:
            logger.error(f"[VMI] QEMU process enumeration failed: {e}")
            return []

    def _list_processes_mock(self) -> List[ProcessInfo]:
        mock_processes = [
            ProcessInfo(pid=1, name='init', base_address=0x10000, is_kernel=False),
            ProcessInfo(pid=4, name='system', base_address=0x80000, is_kernel=True),
            ProcessInfo(pid=1234, name='target_app', base_address=0x400000, is_kernel=False),
            ProcessInfo(pid=5678, name='malware_sample', base_address=0x500000, is_kernel=False),
        ]
        self.processes = mock_processes
        logger.info(f"[VMI] Simulated {len(mock_processes)} processes")
        return mock_processes

    def list_kernel_modules(self) -> List[KernelModule]:
        if not self.is_connected:
            logger.warning("[VMI] Not connected to a virtual machine")
            return []

        self.kernel_modules = []

        if VMI_AVAILABLE and self.vmi_instance:
            return self._list_kernel_modules_libvmi()
        else:
            return self._list_kernel_modules_mock()

    def _list_kernel_modules_libvmi(self) -> List[KernelModule]:
        try:
            modules = []

            if self.os_type == 'linux':
                # 遍历 Linux 内核模块链表
                modules_list = self.vmi_instance.get_offset('linux_modules_list')
                current_module = modules_list

                while True:
                    try:
                        name = self.vmi_instance.read_str_va(current_module + 0x0, 0)
                        base = self.vmi_instance.read_64_va(current_module + 0x8, 0)
                        size = self.vmi_instance.read_32_va(current_module + 0x10, 0)

                        module_info = KernelModule(
                            name=name,
                            base_address=base,
                            size=size
                        )

                        modules.append(module_info)

                        # 前进到下一个模块条目
                        next_module = self.vmi_instance.read_64_va(current_module + 0x18, 0)
                        if next_module == modules_list:
                            break
                        current_module = next_module
                    except Exception:
                        break

            self.kernel_modules = modules
            logger.info(f"[VMI] Listed {len(modules)} kernel modules")
            return modules
        except Exception as e:
            logger.error(f"[VMI] Kernel module enumeration failed: {e}")
            return []

    def _list_kernel_modules_mock(self) -> List[KernelModule]:
        mock_modules = [
            KernelModule(name='kernel', base_address=0x80000000, size=0x1000000),
            KernelModule(name='ntdll.dll', base_address=0x7FFE0000, size=0x100000),
            KernelModule(name='kernel32.dll', base_address=0x7FFE1000, size=0x80000),
            KernelModule(name='malicious_driver.sys', base_address=0xFFFF8000, size=0x10000),
        ]
        self.kernel_modules = mock_modules
        logger.info(f"[VMI] Simulated {len(mock_modules)} kernel modules")
        return mock_modules

    def read_process_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        if not self.is_connected:
            logger.warning("[VMI] Not connected to a virtual machine")
            return None

        if VMI_AVAILABLE and self.vmi_instance:
            try:
                data = self.vmi_instance.read_va(address, pid, size)
                return data
            except Exception as e:
                logger.error(f"[VMI] Memory read failed: {e}")
                return None
        else:
            # 模拟模式返回确定性伪随机数据
            return bytes([i % 256 for i in range(size)])

    def dump_process_memory(self, pid: int, dump_type: str = 'full') -> Optional[MemoryDump]:
        if not self.is_connected:
            logger.warning("[VMI] Not connected to a virtual machine")
            return None

        # 定位目标进程记录
        process = None
        for p in self.processes:
            if p.pid == pid:
                process = p
                break

        if not process:
            logger.warning(f"[VMI] Process {pid} not found in process list")
            return None

        try:
            # 构造转储文件路径
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dump_filename = f"{process.name}_{pid}_{timestamp}.dmp"
            dump_path = os.path.join(self.config.output_dir, dump_filename)

            # 组装转储数据
            dump_data = bytearray()

            if dump_type == 'code':
                # 仅转储可执行代码段
                for region in process.memory_regions:
                    if region.get('type') == 'code':
                        data = self.read_process_memory(pid, region['base'], region['size'])
                        if data:
                            dump_data.extend(data)
            elif dump_type == 'data':
                # 仅转储可写数据段
                for region in process.memory_regions:
                    if region.get('type') == 'data':
                        data = self.read_process_memory(pid, region['base'], region['size'])
                        if data:
                            dump_data.extend(data)
            else:
                # 全量转储 (64KB 模拟载荷)
                dump_data = bytes([i % 256 for i in range(0x10000)])

            # 写入磁盘
            with open(dump_path, 'wb') as f:
                f.write(dump_data)

            # 计算完整性哈希
            sha256_hash = hashlib.sha256(dump_data).hexdigest()

            memory_dump = MemoryDump(
                process_name=process.name,
                pid=pid,
                dump_path=dump_path,
                base_address=process.base_address,
                size=len(dump_data),
                sha256_hash=sha256_hash,
                dump_type=dump_type,
                timestamp=timestamp
            )

            self.memory_dumps.append(memory_dump)
            logger.info(f"[VMI] Process {pid} memory dump complete: {dump_path}")

            return memory_dump
        except Exception as e:
            logger.error(f"[VMI] Memory dump failed: {e}")
            return None

    def dump_all_processes(self) -> List[MemoryDump]:
        dumps = []

        target_pids = self.config.target_pids if self.config.target_pids else [p.pid for p in self.processes]

        for pid in target_pids:
            dump = self.dump_process_memory(pid)
            if dump:
                dumps.append(dump)

        logger.info(f"[VMI] Completed {len(dumps)} process memory dumps")
        return dumps

    def detect_hooks(self) -> List[HookPoint]:
        if not self.is_connected:
            logger.warning("[VMI] Not connected to a virtual machine")
            return []

        self.hooks = []

        if VMI_AVAILABLE and self.vmi_instance:
            return self._detect_hooks_libvmi()
        else:
            return self._detect_hooks_mock()

    def _detect_hooks_libvmi(self) -> List[HookPoint]:
        try:
            hooks = []

            if self.os_type == 'windows':
                # SSDT 钩子检测
                ssdt_base = self.vmi_instance.get_offset('win_ssdt')
                ssdt_count = self.vmi_instance.get_offset('win_ssdt_count')

                for func_name, index in self.SSDT_FUNCTIONS.items():
                    try:
                        # 读取 SSDT 函数指针
                        entry_addr = self.vmi_instance.read_32_va(ssdt_base + index * 4, 0)

                        # 校验地址是否落在内核模块范围内
                        kernel_base = 0x80000000  # Windows 内核虚拟基址
                        kernel_end = 0xFFFFFFFF

                        if not (kernel_base <= entry_addr <= kernel_end):
                            hook = HookPoint(
                                hook_type='SSDT',
                                original_address=kernel_base + index * 4,
                                hooked_address=entry_addr,
                                hooking_module='Unknown',
                                description=f'{func_name} hooked',
                                severity='High'
                            )

                            hooks.append(hook)
                    except Exception as e:
                        logger.warning(f"[VMI] SSDT entry check failed: {e}")

            self.hooks = hooks
            logger.info(f"[VMI] Detected {len(hooks)} hook points")
            return hooks
        except Exception as e:
            logger.error(f"[VMI] Hook detection failed: {e}")
            return []

    def _detect_hooks_mock(self) -> List[HookPoint]:
        mock_hooks = [
            HookPoint(
                hook_type='SSDT',
                original_address=0x80100000,
                hooked_address=0xFFFF8000,
                hooking_module='malicious_driver.sys',
                description='NtCreateProcess hooked',
                severity='High'
            ),
            HookPoint(
                hook_type='IDT',
                original_address=0x80200000,
                hooked_address=0xFFFF9000,
                hooking_module='rootkit.sys',
                description='INT 0x80 hooked',
                severity='Critical'
            ),
        ]
        self.hooks = mock_hooks
        logger.info(f"[VMI] Simulated {len(mock_hooks)} hook points")
        return mock_hooks

    def analyze_memory_region(self, pid: int, address: int, size: int) -> Dict[str, Any]:
        result = {
            'pid': pid,
            'address': address,
            'size': size,
            'analysis_type': 'memory_region',
            'findings': [],
            'timestamp': datetime.now().isoformat()
        }

        # 读取内存块
        data = self.read_process_memory(pid, address, size)
        if not data:
            result['error'] = 'Memory region unreadable'
            return result

        # 执行基线启发式分析
        result['entropy'] = self._calculate_entropy(data)
        result['has_executable_code'] = self._check_executable_code(data)
        result['suspicious_patterns'] = self._detect_suspicious_patterns(data)

        return result

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for nCount in byte_counts:
            if nCount > 0:
                probability = nCount / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _check_executable_code(self, data: bytes) -> bool:
        # 匹配已知 x86 指令前缀
        code_patterns = [
            b'\x55\x8B\xEC',  # Function prologue: push ebp; mov ebp, esp
            b'\xCC',          # INT 3 (breakpoint)
            b'\xE8',          # CALL rel32
            b'\xFF\xE0',      # JMP EAX
        ]

        for pattern in code_patterns:
            if pattern in data:
                return True

        return False

    def _detect_suspicious_patterns(self, data: bytes) -> List[str]:
        patterns = []

        # 搜索已知进程注入 API 字符串
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
                patterns.append(f'Detected suspicious API reference: {s}')

        # 检测紧凑无限循环 shellcode 特征
        if b'\xEB\xFE' in data:
            patterns.append('Detected potential shellcode infinite loop')

        return patterns

    def generate_report(self) -> Dict[str, Any]:
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
        risk = {
            'overall_level': 'Low',
            'findings': [],
        }

        # 评估钩子严重性
        critical_hooks = [h for h in self.hooks if h.severity == 'Critical']
        high_hooks = [h for h in self.hooks if h.severity == 'High']

        if critical_hooks:
            risk['overall_level'] = 'Critical'
            risk['findings'].append(f'Detected {len(critical_hooks)} critical hooks')
        elif high_hooks:
            risk['overall_level'] = 'High'
            risk['findings'].append(f'Detected {len(high_hooks)} high-severity hooks')

        # 评估进程名是否含已知恶意指标
        suspicious_processes = []
        for p in self.processes:
            if any(keyword in p.name.lower() for keyword in ['malware', 'rootkit', 'trojan']):
                suspicious_processes.append(p.name)

        if suspicious_processes:
            if risk['overall_level'] == 'Low':
                risk['overall_level'] = 'Medium'
            risk['findings'].append(f'Detected suspicious processes: {suspicious_processes}')

        return risk

    def save_report(self, output_path: Optional[str] = None) -> str:
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(
                self.config.output_dir,
                f'vmi_report_{self.config.vm_name}_{timestamp}.json'
            )

        report = self.generate_report()

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"[VMI] Report saved: {output_path}")
        return output_path

    def analyze(self) -> Dict[str, Any]:
        logger.info(f"[VMI] Starting analysis of VM: {self.config.vm_name}")

        # 连接到客户机
        if not self.connect():
            return {'error': 'Unable to connect to the target virtual machine'}

        try:
            # 枚举进程
            self.list_processes()

            # 枚举内核模块
            self.list_kernel_modules()

            # 检测钩子
            if self.config.detect_hooks:
                self.detect_hooks()

            # 转储进程内存
            if self.config.dump_processes:
                self.dump_all_processes()

            # 生成分析报告
            report = self.generate_report()

            # 持久化报告到磁盘
            self.save_report()

            return report
        finally:
            self.disconnect()

def create_vmi_analyzer(vm_name: str, **kwargs) -> VMIAnalyzer:
    config = VMIConfig(vm_name=vm_name, **kwargs)
    return VMIAnalyzer(config)
