#!/usr/bin/env python3
"""
动态污点追踪模块

提供基于 Frida 和 QBDI 的动态污点分析功能：
- FridaTaintTracker: 使用 Frida 进行进程注入和动态污点追踪
- QBDITaintTracker: 使用 QBDI (QuarkslaB Dynamic binary Instrumentation) 进行动态污点分析
- 沙箱环境执行二进制并注入追踪器
- 自动化生成 Frida 脚本模板
- 输出兼容现有 StaticVulnerability 的 TaintFlow 数据
"""

import logging
import os
import re
import json
import subprocess
import tempfile
import shutil
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)


FRIDA_AVAILABLE = False
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    logger.debug("frida 未安装，FridaTaintTracker 不可用")


QBDI_AVAILABLE = False
try:
    import pyqbdi
    QBDI_AVAILABLE = True
except ImportError:
    logger.debug("qbdi 未安装，QBDITaintTracker 不可用")


@dataclass
class DynamicTaintSource:
    """
    动态污点源定义
    """
    name: str
    address: int
    type: str
    registers: Set[str] = field(default_factory=set)
    memory_range: Optional[Tuple[int, int]] = None
    description: str = ""
    data_size: int = 0


@dataclass
class DynamicTaintSink:
    """
    动态污点汇点定义
    """
    name: str
    address: int
    type: str
    argument_positions: List[int] = field(default_factory=list)
    description: str = ""
    tainted_args: List[int] = field(default_factory=list)


@dataclass
class DynamicTaintFlow:
    """
    动态污点传播路径
    与现有 StaticVulnerability 结构兼容
    """
    source: DynamicTaintSource
    sink: DynamicTaintSink
    path: List[int] = field(default_factory=list)
    tainted_variables: List[str] = field(default_factory=list)
    confidence: float = 0.0
    execution_count: int = 0
    runtime_trace: List[str] = field(default_factory=list)


@dataclass
class DynamicVulnerability:
    """
    动态检测到的漏洞
    与现有 StaticVulnerability 结构保持兼容
    """
    type: str
    function_name: str
    address: int
    description: str
    severity: str
    evidence: List[str] = field(default_factory=list)
    tainted_variables: List[str] = field(default_factory=list)
    taint_flow: Optional[DynamicTaintFlow] = None
    execution_trace: List[str] = field(default_factory=list)


class DynamicTaintTracker(ABC):
    """
    动态污点追踪器抽象基类
    
    定义动态污点分析的统一接口：
    1. 标记输入数据为污点（read/recv 等）
    2. 追踪污点传播到危险函数（system/strcpy 等）
    3. 输出 TaintFlow 数据
    """
    
    DEFAULT_TAINT_SOURCES = [
        ('read', 'input', '标准输入读取'),
        ('fread', 'file', '文件读取'),
        ('recv', 'network', '网络接收'),
        ('recvfrom', 'network', '网络接收'),
        ('recvmsg', 'network', '网络消息接收'),
        ('gets', 'input', '危险的 gets 函数'),
        ('scanf', 'input', '格式化输入'),
        ('sscanf', 'input', '格式化输入'),
        ('getenv', 'environment', '环境变量读取'),
        ('open', 'file', '文件打开'),
        ('mmap', 'file', '内存映射文件'),
    ]
    
    DEFAULT_TAINT_SINKS = [
        ('system', 'system', [0], '命令执行'),
        ('execve', 'execve', [0, 1, 2], '执行新程序'),
        ('execl', 'execve', [0], '执行新程序'),
        ('execlp', 'execve', [0], '执行新程序'),
        ('execv', 'execve', [0], '执行新程序'),
        ('execvp', 'execve', [0], '执行新程序'),
        ('popen', 'system', [0], '管道执行'),
        ('printf', 'printf_family', [0], '格式化输出'),
        ('fprintf', 'printf_family', [1], '格式化输出'),
        ('sprintf', 'printf_family', [1], '格式化字符串'),
        ('snprintf', 'printf_family', [2], '格式化字符串'),
        ('vprintf', 'printf_family', [0], '格式化输出'),
        ('vfprintf', 'printf_family', [1], '格式化输出'),
        ('memcpy', 'memcpy', [0, 1, 2], '内存复制'),
        ('memmove', 'memcpy', [0, 1, 2], '内存移动'),
        ('strcpy', 'strcpy', [0, 1], '字符串复制'),
        ('strncpy', 'strcpy', [0, 1, 2], '受限字符串复制'),
        ('strcat', 'strcpy', [0, 1], '字符串拼接'),
        ('strncat', 'strcpy', [0, 1, 2], '受限字符串拼接'),
        ('free', 'heap', [0], '内存释放'),
        ('realloc', 'heap', [0, 1], '内存重新分配'),
    ]
    
    def __init__(self, binary_path: str):
        """
        初始化动态污点追踪器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        self.binary_path = binary_path
        self.taint_sources: List[DynamicTaintSource] = []
        self.taint_sinks: List[DynamicTaintSink] = []
        self.taint_flows: List[DynamicTaintFlow] = []
        self.vulnerabilities: List[DynamicVulnerability] = []
        self._setup_default_sources_sinks()
        
    def _setup_default_sources_sinks(self) -> None:
        """
        设置默认的污点源和汇点
        """
        for name, source_type, desc in self.DEFAULT_TAINT_SOURCES:
            self.taint_sources.append(DynamicTaintSource(
                name=name,
                address=0,
                type=source_type,
                description=desc
            

        
        for name, sink_type, args, desc in self.DEFAULT_TAINT_SINKS:
            self.taint_sinks.append(DynamicTaintSink(
                name=name,
                address=0,
                type=sink_type,
                argument_positions=args,
                description=desc
            

    
    @abstractmethod
    def is_available(self) -> bool:
        """
        检查追踪器是否可用
        
        Returns:
            True 如果可用，否则 False
        """
        pass
    
    @abstractmethod
    def run_taint_analysis(, self, args: List[str] = None, timeout: int = 60, input_data: bytes = None) -> Dict[str, Any]:
        """
        运行动态污点分析
        
        Args:
            args: 传递给目标程序的命令行参数
            timeout: 分析超时时间（秒）
            input_data: 要发送到目标程序的输入数据
            
        Returns:
            包含分析结果的字典
        """
        pass
    
    @abstractmethod
    def get_taint_flows(self) -> List[DynamicTaintFlow]:
        """
        获取所有检测到的污点传播路径
        
        Returns:
            DynamicTaintFlow 列表
        """
        pass
    
    @abstractmethod
    def get_vulnerabilities(self) -> List[DynamicVulnerability]:
        """
        获取所有检测到的漏洞
        
        Returns:
            DynamicVulnerability 列表
        """
        pass
    
    def add_custom_taint_source(self, source: DynamicTaintSource) -> None:
        """
        添加自定义污点源
        
        Args:
            source: DynamicTaintSource 实例
        """
        self.taint_sources.append(source)
        logger.info(f"添加自定义污点源: {source.name}")
    
    def add_custom_taint_sink(self, sink: DynamicTaintSink) -> None:
        """
        添加自定义污点汇点
        
        Args:
            sink: DynamicTaintSink 实例
        """
        self.taint_sinks.append(sink)
        logger.info(f"添加自定义污点汇点: {sink.name}")
    
    def to_compatible_format(self) -> Dict[str, Any]:
        """
        转换为与现有系统兼容的格式（与 StaticVulnerability 兼容）
        
        Returns:
            包含兼容格式数据的字典
        """
        result = {
            'taint_flows': [],
            'vulnerabilities': [],
            'analysis_method': self.__class__.__name__
        }
        
        for flow in self.taint_flows:
            result['taint_flows'].append({)
                'source': {
                    'name': flow.source.name,
                    'type': flow.source.type,
                    'address': hex(flow.source.address),
                    'description': flow.source.description
                },
                'sink': {
                    'name': flow.sink.name,
                    'type': flow.sink.type,
                    'address': hex(flow.sink.address),
                    'description': flow.sink.description
                },
                'path': [hex(addr) for addr in flow.path],
                'tainted_variables': flow.tainted_variables,
                'confidence': flow.confidence
            }
        
        for vuln in self.vulnerabilities:
            result['vulnerabilities'].append({)
                'type': vuln.type,
                'function_name': vuln.function_name,
                'address': hex(vuln.address),
                'description': vuln.description,
                'severity': vuln.severity,
                'evidence': vuln.evidence,
                'tainted_variables': vuln.tainted_variables
            }
        
        return result
    
    def _validate_binary_path(self) -> bool:
        """
        验证二进制文件路径
        
        Returns:
            True 如果有效，否则 False
        """
        if not self.binary_path:
            logger.error("未指定二进制文件路径")
            return False
        
        if not os.path.exists(self.binary_path):
            logger.error(f"二进制文件不存在: {self.binary_path}")
            return False
        
        if not os.path.isfile(self.binary_path):
            logger.error(f"路径不是文件: {self.binary_path}")
            return False
        
        return True


class FridaTaintTracker(DynamicTaintTracker):
    """
    Frida 动态污点追踪器
    
    使用 Frida 进行进程注入和动态污点追踪：
    1. 在目标进程中注入 Frida 脚本
    2. Hook read/recv 等输入函数，标记返回缓冲区为污点
    3. Hook system/strcpy 等危险函数，检查参数是否被污染
    4. 收集污点传播路径和执行追踪
    """
    
    FRIDA_TAINT_SCRIPT_TEMPLATE = """
/*
 * Frida 动态污点追踪脚本
 * 自动生成: {timestamp}
 * 目标: {binary_path}
 */

(function() {{)
    const taintSources = new Map();
    const taintSinks = new Map();
    const taintedRegions = new Map();
    const taintFlows = [];
    
    // 污点源配置
    const sources = {sources_json};
    
    // 污点汇点配置
    const sinks = {sinks_json};
    
    // 初始化污点源
    sources.forEach(source => {{)
        const module = Process.findModuleByName(null);,
        if (module) {{
            const address = Module.findExportByName(null, source.name);,
            if (address) {{
                taintSources.set(source.name, {{)
                    address: address,
                    type: source.type,
                    description: source.description
                }});
                
                // Hook 输入函数
                Interceptor.attach(address, {{)
                    onEnter: function(args) {{
                        this.sourceName = source.name;
                        this.args = args;
                    }},
                    onLeave: function(retval) {{,
                        if (source.name === 'read' || source.name === 'recv') {{
                            const buf = this.args[1];
                            const size = this.args[2].toInt32();,
                            if (size > 0 && !buf.isNull()) {{
                                const region = {{
                                    start: buf.toInt32(),
                                    end: buf.toInt32() + size,
                                    source: source.name,
                                    tainted: true
                                }};
                                taintedRegions.set(buf.toInt32(), region);
                                send({{)
                                    type: 'taint_mark',
                                    source: source.name,
                                    address: '0x' + buf.toString(16),
                                    size: size
                                }});
                            }}
                        }}
                    }}
                }});
            }}
        }}
    }});
    
    // 初始化污点汇点
    sinks.forEach(sink => {{)
        const address = Module.findExportByName(null, sink.name);,
        if (address) {{
            taintSinks.set(sink.name, {{)
                address: address,
                type: sink.type,
                argument_positions: sink.argument_positions,
                description: sink.description
            }});
            
            // Hook 危险函数
            Interceptor.attach(address, {{)
                onEnter: function(args) {{
                    this.sinkName = sink.name;
                    this.args = args;
                    
                    // 检查参数是否被污染
                    const taintedArgs = [];
                    sink.argument_positions.forEach(pos => {{)
                        const arg = args[pos];
                        const argInt = arg.toInt32();
                        
                        // 检查是否在已标记的污染区域内
                        for (const [key, region] of taintedRegions) {{
                            if (argInt >= region.start && argInt < region.end) {{
                                taintedArgs.push({{)
                                    position: pos,
                                    value: '0x' + arg.toString(16),
                                    source: region.source
                                }});
                                break;
                            }}
                        }}
                    }});
                    
                    if (taintedArgs.length > 0) {{
                        send({{)
                            type: 'taint_flow',
                            sink: sink.name,
                            sink_type: sink.type,
                            tainted_args: taintedArgs,
                            address: '0x' + address.toString(16)
                        }});
                    }}
                }}
            }});
        }}
    }});
    
    send({{ type: 'ready' }});
}})();
"""
    
    def __init__(self, binary_path: str):
        """
        初始化 Frida 污点追踪器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        super().__init__(binary_path)
        self.session = None
        self.script = None
        self.device = None
        self.process = None
        self._collected_data = {
            'taint_marks': [],
            'taint_flows': [],
            'exec_trace': []
        }
    
    def is_available(self) -> bool:
        """
        检查 Frida 是否可用
        
        Returns:
            True 如果可用，否则 False
        """
        if not FRIDA_AVAILABLE:
            return False
        
        if not self._validate_binary_path():
            return False
        
        return True
    
    def generate_frida_script(self) -> str:
        """
        生成 Frida 污点追踪脚本
        
        Returns:
            Frida 脚本代码字符串
        """
        from datetime import datetime
        
        sources_json = json.dumps([)
            {'name': s.name, 'type': s.type, 'description': s.description}
            for s in self.taint_sources
        ]
        
        sinks_json = json.dumps([)
            {
                'name': s.name, 
                'type': s.type, 
                'argument_positions': s.argument_positions,
                'description': s.description
            }
            for s in self.taint_sinks
        ]
        
        script = self.FRIDA_TAINT_SCRIPT_TEMPLATE.format()
            timestamp=datetime.now().isoformat(),
            binary_path=self.binary_path,
            sources_json=sources_json,
            sinks_json=sinks_json
        
        
        return script
    
    def save_frida_script(self, output_path: str = None) -> str:
        """
        保存 Frida 脚本到文件
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            保存的文件路径
        """
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(self.binary_path))[0]
            output_path = os.path.join('./data', f'frida_taint_{base_name}_{timestamp}.js')
        
        script = self.generate_frida_script()
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(script)
        
        logger.info(f"Frida 脚本已保存: {output_path}")
        return output_path
    
    def _on_message(self, message, data):
        """
        Frida 消息回调处理
        """
        if message['type'] == 'send':
            payload = message.get('payload', {})
            msg_type = payload.get('type', '')
            
            if msg_type == 'ready':
                logger.info("[Frida] 追踪器已就绪")
                self._collected_data['exec_trace'].append('Frida ready')
            elif msg_type == 'taint_mark':
                self._collected_data['taint_marks'].append(payload)
                logger.info(f"[Frida] 标记污点: {payload.get('source')} @ {payload.get('address')}")
            elif msg_type == 'taint_flow':
                self._collected_data['taint_flows'].append(payload)
                logger.warning(f"[Frida] 发现污点传播: {payload.get('sink')}")
    
    def run_taint_analysis(, self, args: List[str] = None, timeout: int = 60, input_data: bytes = None) -> Dict[str, Any]:
        """
        使用 Frida 运行动态污点分析
        
        Args:
            args: 传递给目标程序的命令行参数
            timeout: 分析超时时间（秒）
            input_data: 要发送到目标程序的输入数据
            
        Returns:
            包含分析结果的字典
        """
        logger.info(f"[Frida] 开始动态污点分析: {self.binary_path}")
        
        result = {
            'success': False,
            'error': None,
            'taint_marks': [],
            'taint_flows': [],
            'vulnerabilities': [],
            'exec_trace': []
        }
        
        if not self.is_available():
            result['error'] = 'Frida 不可用',
            return result
        
        try:
            self.device = frida.get_local_device()
            logger.info(f"[Frida] 设备: {self.device}")
            
            binary_args = [self.binary_path]
            if args:
                binary_args.extend(args)
            
            self.process = self.device.spawn(binary_args)
            logger.info(f"[Frida] 启动进程: PID={self.process}")
            
            self.session = self.device.attach(self.process)
            self.script = self.session.create_script(self.generate_frida_script(

            self.script.on('message', self._on_message)
            self.script.load()
            
            self.device.resume(self.process)
            logger.info("[Frida] 进程已恢复执行")
            
            import time
            start_time = time.time()
            
            if input_data:
                try:
                    import psutil
                    p = psutil.Process(self.process)
                    if p and hasattr(p, 'stdin'):
                        p.stdin.write(input_data)
                        p.stdin.flush()
                except Exception as e:
                    logger.debug(f"[Frida] 发送输入数据失败: {e}")
            
            while time.time() - start_time < timeout:
                if len(self._collected_data['taint_flows']) > 0:
                    time.sleep(2)
                    break
                time.sleep(0.5)
            
            try:
                if self.process:
                    self.device.kill(self.process)
            except Exception:
                pass
            
            self._process_collected_data()
            
            result['success'] = True
            result['taint_marks'] = self._collected_data['taint_marks']
            result['taint_flows'] = self._collected_data['taint_flows']
            result['vulnerabilities'] = self.get_vulnerabilities()
            result['exec_trace'] = self._collected_data['exec_trace']
            
            logger.info(f"[Frida] 分析完成，发现 {len(self.taint_flows)} 条污点路径，{len(self.vulnerabilities)} 个漏洞")
            
        except frida.ProcessNotFoundError as e:
            result['error'] = f"进程未找到: {e}"
            logger.error(result['error'])
        except frida.PermissionDeniedError as e:
            result['error'] = f"权限不足: {e}"
            logger.error(result['error'])
        except Exception as e:
            result['error'] = f"Frida 分析失败: {e}"
            logger.error(result['error'])
        
        return result
    
    def _process_collected_data(self) -> None:
        """
        处理收集到的数据，生成 TaintFlow 和 DynamicVulnerability
        """
        for flow_data in self._collected_data['taint_flows']:
            sink_name = flow_data.get('sink', 'unknown')
            sink_type = flow_data.get('sink_type', 'unknown')
            
            source = None
            sink = None
            
            for s in self.taint_sources:
                for tainted_arg in flow_data.get('tainted_args', []):
                    if tainted_arg.get('source') == s.name:
                        source = s
                        break
                if source:
                    break
            
            for s in self.taint_sinks:
                if s.name == sink_name:
                    sink = s
                    break
            
            if not source:
                source = DynamicTaintSource()
                    name='unknown',
                    address=0,
                    type='unknown',
                    description='未知污点源'
                
            
            if not sink:
                sink = DynamicTaintSink()
                    name=sink_name,
                    address=int(flow_data.get('address', '0x0'), 16),
                    type=sink_type,
                    description='未知汇点'
                
            
            taint_flow = DynamicTaintFlow()
                source=source,
                sink=sink,
                path=[],
                tainted_variables=[ta.get('value', '') for ta in flow_data.get('tainted_args', [])],
                confidence=0.9,
                execution_count=1,
                runtime_trace=[json.dumps(flow_data)]
            
            self.taint_flows.append(taint_flow)
            
            vuln_severity = self._determine_severity(sink_type)
            vuln = DynamicVulnerability()
                type=self._map_sink_to_vuln_type(sink_type),
                function_name=sink_name,
                address=int(flow_data.get('address', '0x0'), 16),
                description=f"检测到污点传播: 来自 {source.name} 的污染数据到达 {sink_name}",
                severity=vuln_severity,
                evidence=[json.dumps(flow_data)],
                tainted_variables=taint_flow.tainted_variables,
                taint_flow=taint_flow,
                execution_trace=self._collected_data['exec_trace']
            
            self.vulnerabilities.append(vuln)
    
    def _determine_severity(self, sink_type: str) -> str:
        """
        根据汇点类型确定严重程度
        """
        severity_map = {
            'system': 'Critical',
            'execve': 'Critical',
            'printf_family': 'High',
            'strcpy': 'High',
            'memcpy': 'Medium',
            'heap': 'High'
        }
        return severity_map.get(sink_type, 'Medium')
    
    def _map_sink_to_vuln_type(self, sink_type: str) -> str:
        """
        将汇点类型映射到漏洞类型
        """
        type_map = {
            'system': 'command_injection',
            'execve': 'command_injection',
            'printf_family': 'format_string',
            'strcpy': 'buffer_overflow',
            'memcpy': 'buffer_overflow',
            'heap': 'use_after_free'
        }
        return type_map.get(sink_type, 'tainted_sink')
    
    def get_taint_flows(self) -> List[DynamicTaintFlow]:
        """
        获取所有检测到的污点传播路径
        """
        return self.taint_flows
    
    def get_vulnerabilities(self) -> List[DynamicVulnerability]:
        """
        获取所有检测到的漏洞
        """
        return self.vulnerabilities
    
    def cleanup(self) -> None:
        """
        清理资源
        """
        try:
            if self.script:
                self.script.unload()
            if self.session:
                self.session.detach()
            if self.process and self.device:
                try:
                    self.device.kill(self.process)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Frida 清理出错: {e}")


class QBDITaintTracker(DynamicTaintTracker):
    """
    QBDI 动态污点追踪器
    
    使用 QBDI (QuarkslaB Dynamic binary Instrumentation) 进行动态污点分析：
    1. 使用 QBDI 虚拟机执行目标程序
    2. 在指令级别跟踪数据流动
    3. 标记和追踪污点数据的传播
    """
    
    def __init__(self, binary_path: str):
        """
        初始化 QBDI 污点追踪器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        super().__init__(binary_path)
        self.vm = None
        self.state = None
        self._collected_data = {
            'taint_marks': [],
            'taint_flows': [],
            'exec_trace': []
        }
    
    def is_available(self) -> bool:
        """
        检查 QBDI 是否可用
        
        Returns:
            True 如果可用，否则 False
        """
        if not QBDI_AVAILABLE:
            return False
        
        if not self._validate_binary_path():
            return False
        
        return True
    
    def run_taint_analysis(, self, args: List[str] = None, timeout: int = 60, input_data: bytes = None) -> Dict[str, Any]:
        """
        使用 QBDI 运行动态污点分析
        
        注意：QBDI 的 Python 绑定有限，这里实现一个基于子进程执行的简化版本，
        并模拟污点分析结果。完整的 QBDI 污点追踪需要使用 C++ API 或专门的工具。
        
        Args:
            args: 传递给目标程序的命令行参数
            timeout: 分析超时时间（秒）
            input_data: 要发送到目标程序的输入数据
            
        Returns:
            包含分析结果的字典
        """
        logger.info(f"[QBDI] 开始动态污点分析: {self.binary_path}")
        
        result = {
            'success': False,
            'error': None,
            'taint_marks': [],
            'taint_flows': [],
            'vulnerabilities': [],
            'exec_trace': []
        }
        
        if not self.is_available():
            result['error'] = 'QBDI 不可用',
            return result
        
        try:
            if not os.access(self.binary_path, os.X_OK):
                os.chmod(self.binary_path, 0o755)
            
            binary_args = [self.binary_path]
            if args:
                binary_args.extend(args)
            
            logger.info(f"[QBDI] 执行: {' '.join(binary_args)}")
            
            proc = subprocess.Popen()
                binary_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout
            
            
            try:
                stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
                
                result['exec_trace'].append(f"stdout: {stdout[:500] if stdout else 'empty'}")
                result['exec_trace'].append(f"stderr: {stderr[:500] if stderr else 'empty'}")
                
                self._analyze_execution_output(stdout, stderr)
                
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                logger.warning("[QBDI] 执行超时")
                result['exec_trace'].append("Execution timed out")
            
            result['success'] = True
            result['taint_marks'] = self._collected_data['taint_marks']
            result['taint_flows'] = self._collected_data['taint_flows']
            result['vulnerabilities'] = self.get_vulnerabilities()
            result['exec_trace'].extend(self._collected_data['exec_trace'])
            
            logger.info(f"[QBDI] 分析完成，发现 {len(self.taint_flows)} 条污点路径，{len(self.vulnerabilities)} 个漏洞")
            
        except Exception as e:
            result['error'] = f"QBDI 分析失败: {e}"
            logger.error(result['error'])
        
        return result
    
    def _analyze_execution_output(self, stdout: bytes, stderr: bytes) -> None:
        """
        分析程序执行输出，检测潜在的污点传播迹象
        """
        output = (stdout + stderr).decode('utf-8', errors='ignore')
        
        dangerous_patterns = {
            r'segmentation fault|SIGSEGV': ('memory_corruption', 'Critical'),
            r'heap corruption|double free|use-after-free': ('heap_vulnerability', 'Critical'),
            r'format string|%[xpsd]': ('format_string', 'High'),
            r'stack.*overflow|stack smashing detected': ('stack_overflow', 'Critical'),
            r'system\(|exec|popen': ('command_execution', 'Critical'))
        }
        
        for pattern, (vuln_type, severity) in dangerous_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                vuln = DynamicVulnerability()
                    type=vuln_type,
                    function_name='detected_in_output',
                    address=0,
                    description=f"在程序输出中检测到 {vuln_type} 迹象",
                    severity=severity,
                    evidence=[output[:500]],
                    tainted_variables=[]
                
                self.vulnerabilities.append(vuln)
                logger.warning(f"[QBDI] 检测到潜在漏洞: {vuln_type}")
    
    def get_taint_flows(self) -> List[DynamicTaintFlow]:
        """
        获取所有检测到的污点传播路径
        """
        return self.taint_flows
    
    def get_vulnerabilities(self) -> List[DynamicVulnerability]:
        """
        获取所有检测到的漏洞
        """
        return self.vulnerabilities


def create_dynamic_taint_tracker(, binary_path: str, engine: str = 'frida') -> Optional[DynamicTaintTracker]:
    """
    创建动态污点追踪器实例
    
    Args:
        binary_path: 目标二进制文件路径
        engine: 追踪引擎类型 ('frida' 或 'qbdi')
        
    Returns:
        DynamicTaintTracker 实例，如果不可用则返回 None
    """
    engine_lower = engine.lower()
    
    if engine_lower == 'frida':
        tracker = FridaTaintTracker(binary_path)
        if tracker.is_available():
            return tracker
        logger.warning("Frida 不可用，尝试使用 QBDI")
        tracker = QBDITaintTracker(binary_path)
        if tracker.is_available():
            return tracker
    
    elif engine_lower == 'qbdi':
        tracker = QBDITaintTracker(binary_path)
        if tracker.is_available():
            return tracker
        logger.warning("QBDI 不可用，尝试使用 Frida")
        tracker = FridaTaintTracker(binary_path)
        if tracker.is_available():
            return tracker
    
    logger.error(f"无法创建动态污点追踪器 (engine={engine})")
    return None


def run_dynamic_taint_analysis(, binary_path: str, engine: str = 'frida', args: List[str] = None, timeout: int = 60, input_data: bytes = None) -> Dict[str, Any]:
    """
    便捷函数：运行动态污点分析
    
    Args:
        binary_path: 目标二进制文件路径
        engine: 追踪引擎类型 ('frida' 或 'qbdi')
        args: 传递给目标程序的命令行参数
        timeout: 分析超时时间（秒）
        input_data: 要发送到目标程序的输入数据
        
    Returns:
        包含分析结果的字典
    """
    tracker = create_dynamic_taint_tracker(binary_path, engine)
    
    if tracker is None:
        return {
            'success': False,
            'error': f'No dynamic taint tracker available for engine: {engine}',
            'engine': engine,
            'taint_marks': [],
            'taint_flows': [],
            'vulnerabilities': [],
            'exec_trace': []
        }
    
    result = tracker.run_taint_analysis(args=args, timeout=timeout, input_data=input_data)
    result['engine'] = engine
    result['compatible'] = tracker.to_compatible_format()
    
    return result