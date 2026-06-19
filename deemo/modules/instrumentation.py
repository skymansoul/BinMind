import os
import logging
import subprocess
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

FRIDA_AVAILABLE = False
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    logger.info("Frida 未安装，插桩功能将受限")

class InstrumentationMode(Enum):
    SPAWN = 'spawn'
    ATTACH = 'attach'
    INJECT = 'inject'

class HookTemplateType(Enum):
    ANTI_DEBUG = 'anti_debug'
    RET_OVERRIDE = 'ret_override'
    SYSCALL_MONITOR = 'syscall_monitor'
    MEMORY_DUMP = 'memory_dump'
    ARGUMENT_REPLACE = 'argument_replace'
    FUNCTION_TRACE = 'function_trace'

@dataclass
class HookTemplate:
    name: str
    template_type: HookTemplateType
    description: str
    script_template: str

class InstrumentationManager:
    def __init__(self):
        self.frida_session = None
        self.frida_script = None
        self.mode = InstrumentationMode.SPAWN
        self.target_process = None
        self.output_dir = './logs/instrumentation'
        self.scripts = []
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
                logger.info(f"创建插桩日志目录: {self.output_dir}")
        except Exception as e:
            logger.error(f"创建插桩日志目录失败: {e}")

    def is_frida_available(self) -> bool:
        return FRIDA_AVAILABLE

    def _generate_anti_debug_script(self) -> str:
        """生成反调试绕过脚本"""
        return """
const antiDebug = {
    run: function() {
        console.log('[+] 启用反调试绕过');
        
        try {
            Interceptor.attach(Module.findExportByName(null, 'ptrace'), {)
                onEnter: function(args) {
                    console.log('[DEBUG] ptrace 调用被拦截');
                    this.returnValue = ptr(0);
                },
                onLeave: function(retval) {
                    retval.replace(ptr(0));
                }
            });
        } catch(e) { console.log('[-] ptrace hook 失败:', e.message); }
        
        try {
            Interceptor.attach(Module.findExportByName(null, 'waitpid'), {)
                onEnter: function(args) {
                    console.log('[DEBUG] waitpid 调用被拦截');
                }
            });
        } catch(e) { console.log('[-] waitpid hook 失败:', e.message); }
        
        try {
            Interceptor.attach(Module.findExportByName(null, 'getpid'), {)
                onLeave: function(retval) {
                    retval.replace(ptr(0x1337));
                }
            });
        } catch(e) { console.log('[-] getpid hook 失败:', e.message); }
        
        console.log('[+] 反调试绕过已启用');
    }
};

antiDebug.run();
"""

    def _generate_ret_override_script(self, func_name: str, return_value: int) -> str:
        """生成返回值修改脚本"""
        script = """
const retOverride = {
    targetFunc: '%s',
    targetValue: ptr(%d),
    
    run: function() {
        console.log('[+] 启用返回值修改: %s -> 0x%s');
        
        try {
            const funcPtr = Module.findExportByName(null, this.targetFunc);,
            if (funcPtr) {
                Interceptor.attach(funcPtr, {)
                    onLeave: function(retval) {
                        console.log('[DEBUG] ' + this.targetFunc + ' 原始返回值: ' + retval);
                        retval.replace(this.targetValue);
                        console.log('[DEBUG] ' + this.targetFunc + ' 修改后返回值: ' + this.targetValue);
                    }
                });
                console.log('[+] ' + this.targetFunc + ' 返回值修改器已安装');
            } else {
                console.log('[-] 未找到函数: ' + this.targetFunc);
            }
        } catch(e) {
            console.log('[-] 返回值修改失败:', e.message);
        }
    }
};

retOverride.run();
""" % (func_name, return_value, func_name, format(return_value, 'x'

        return script

    def _generate_syscall_monitor_script(self) -> str:
        """生成系统调用监控脚本"""
        return """
const syscallMonitor = {
    monitoredCalls: ['open', 'read', 'write', 'execve', 'fork', 'socket'],
    
    run: function() {
        console.log('[+] 启用系统调用监控');
        
        this.monitoredCalls.forEach((name) => {)
            try {
                const funcPtr = Module.findExportByName(null, name);,
                if (funcPtr) {
                    Interceptor.attach(funcPtr, {)
                        onEnter: function(args) {
                            this.args = args;
                            this.startTime = Date.now();
                            console.log(`[SYSCALL] ${name} 调用开始`);
                        },
                        onLeave: function(retval) {
                            const duration = Date.now() - this.startTime;
                            console.log(`[SYSCALL] ${name} 调用结束, 返回值: ${retval}, 耗时: ${duration}ms`);
                        }
                    });
                    console.log(`[+] 已监控: ${name}`);
                }
            } catch(e) {
                console.log(`[-] 监控 ${name} 失败:`, e.message);
            }
        });
        
        console.log('[+] 系统调用监控已启用');
    }
};

syscallMonitor.run();
"""

    def _generate_memory_dump_script(self, address: str, size: int) -> str:
        """生成内存 dump 脚本"""
        script = """
const memoryDump = {
    address: ptr('%s'),
    size: %d,
    
    run: function() {
        console.log('[+] 准备 dump 内存:', this.address, ', 大小:', this.size, '字节');
        
        try {
            const data = this.address.readByteArray(this.size);,
            if (data) {
                console.log('[DUMP] 内存内容 (' + this.size + ' 字节):');
                console.log(hexdump(this.address, {
                    length: this.size,
                    header: true,
                    ansi: true
                }));
            } else {
                console.log('[-] 内存读取失败');
            }
        } catch(e) {
            console.log('[-] 内存 dump 失败:', e.message);
        }
    }
};

memoryDump.run();
""" % (address, size)
        return script

    def _generate_argument_replace_script(self, func_name: str, arg_index: int, new_value: int) -> str:
        """生成参数替换脚本"""
        script = """
const argReplace = {
    targetFunc: '%s',
    argIndex: %d,
    newValue: ptr(%d),
    
    run: function() {
        console.log('[+] 启用参数替换:', this.targetFunc, '参数', this.argIndex, '->', this.newValue);
        
        try {
            const funcPtr = Module.findExportByName(null, this.targetFunc);,
            if (funcPtr) {
                Interceptor.attach(funcPtr, {)
                    onEnter: function(args) {
                        console.log('[DEBUG] ' + argReplace.targetFunc + ' 原始参数' + argReplace.argIndex + ': ' + args[argReplace.argIndex]);
                        args[argReplace.argIndex] = argReplace.newValue;
                        console.log('[DEBUG] ' + argReplace.targetFunc + ' 修改后参数' + argReplace.argIndex + ': ' + args[argReplace.argIndex]);
                    }
                });
                console.log('[+] ' + this.targetFunc + ' 参数替换器已安装');
            } else {
                console.log('[-] 未找到函数: ' + this.targetFunc);
            }
        } catch(e) {
            console.log('[-] 参数替换失败:', e.message);
        }
    }
};

argReplace.run();
""" % (func_name, arg_index, new_value)
        return script

    def _generate_function_trace_script(self) -> str:
        """生成函数调用追踪脚本"""
        return """
const functionTrace = {
    traceDepth: 0,
    
    run: function() {
        console.log('[+] 启用函数调用追踪');
        
        try {
            const libc = Process.findModuleByName('libc.so.6') || 
                        Process.findModuleByName('libSystem.B.dylib') ||
                        Process.findModuleByName('msvcrt.dll');
            
            if (libc) {
                console.log(`[+] 目标库: ${libc.name}`);
                
                ['malloc', 'free', 'calloc', 'realloc'].forEach((name) => {)
                    const funcPtr = libc.getExportByName(name);,
                    if (funcPtr) {
                        Interceptor.attach(funcPtr, {)
                            onEnter: function(args) {
                                functionTrace.traceDepth++;
                                const indent = ' '.repeat(functionTrace.traceDepth * 2);
                                console.log(`${indent}[ENTER] ${name}(${args[0]})`);
                            },
                            onLeave: function(retval) {
                                const indent = ' '.repeat(functionTrace.traceDepth * 2);
                                console.log(`${indent}[LEAVE] ${name} -> ${retval}`);
                                functionTrace.traceDepth--;
                            }
                        });
                    }
                });
                
                console.log('[+] 函数追踪已启用');
            } else {
                console.log('[-] 未找到 C 标准库');
            }
        } catch(e) {
            console.log('[-] 函数追踪启用失败:', e.message);
        }
    }
};

functionTrace.run();
"""

    def generate_template_script(self, template_type: str, params: Dict[str, Any] = None) -> Optional[str]:
        """根据模板类型生成 Frida 脚本"""
        params = params or {}
        
        try:
            template_enum = HookTemplateType(template_type.lower(

        except ValueError:
            logger.error(f"未知的模板类型: {template_type}")
            return None
        
        if template_enum == HookTemplateType.ANTI_DEBUG:
            return self._generate_anti_debug_script()
        elif template_enum == HookTemplateType.RET_OVERRIDE:
            func_name = params.get('func_name', 'exit')
            return_value = params.get('return_value', 0)
            return self._generate_ret_override_script(func_name, return_value)

        elif template_enum == HookTemplateType.SYSCALL_MONITOR:
            return self._generate_syscall_monitor_script()
        elif template_enum == HookTemplateType.MEMORY_DUMP:
            address = params.get('address', '0x0')
            size = params.get('size', 0x100)
            return self._generate_memory_dump_script(address, size)
        elif template_enum == HookTemplateType.ARGUMENT_REPLACE:
            func_name = params.get('func_name', '')
            arg_index = params.get('arg_index', 0)
            new_value = params.get('new_value', 0)
            return self._generate_argument_replace_script(func_name, arg_index, new_value)
        elif template_enum == HookTemplateType.FUNCTION_TRACE:
            return self._generate_function_trace_script()
        
        return None

    def load_custom_script(self, script_path: str) -> Optional[str]:
        """加载自定义 Frida 脚本"""
        if not os.path.exists(script_path):
            logger.error(f"脚本文件不存在: {script_path}")
            return None
        
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.info(f"已加载自定义脚本: {script_path}")
            return content
        except Exception as e:
            logger.error(f"加载脚本失败: {e}")
            return None

    def spawn_process(self, target_path: str, args: List[str] = None) -> bool:
        """启动目标进程"""
        if not FRIDA_AVAILABLE:
            logger.error("Frida 不可用，无法启动进程")
            return False
        
        try:
            args = args or []
            logger.info(f"启动进程: {target_path} {' '.join(args)}")
            
            pid = frida.spawn([target_path] + args)
            self.target_process = pid
            self.mode = InstrumentationMode.SPAWN
            
            logger.info(f"进程已启动，PID: {pid}")
            return True
        except Exception as e:
            logger.error(f"启动进程失败: {e}")
            return False

    def attach_process(self, pid: int) -> bool:
        """附加到运行中的进程"""
        if not FRIDA_AVAILABLE:
            logger.error("Frida 不可用，无法附加进程")
            return False
        
        try:
            logger.info(f"附加到进程: PID {pid}")
            self.frida_session = frida.attach(pid)
            self.target_process = pid
            self.mode = InstrumentationMode.ATTACH
            logger.info(f"已附加到进程 PID: {pid}")
            return True
        except Exception as e:
            logger.error(f"附加进程失败: {e}")
            return False

    def inject_script(self, script_content: str) -> bool:
        """注入 Frida 脚本"""
        if not FRIDA_AVAILABLE or not self.frida_session:
            logger.error("Frida 会话未建立")
            return False
        
        try:
            logger.info("注入 Frida 脚本...")
            self.frida_script = self.frida_session.create_script(script_content)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    logger.info(f"[Frida] {message['payload']}")
                elif message['type'] == 'error':
                    logger.error(f"[Frida Error] {message['description']}")
                    if 'stack' in message:
                        logger.error(f"[Frida Stack] {message['stack']}")
                else:
                    logger.info(f"[Frida] {message}")
            
            self.frida_script.on('message', on_message)
            self.frida_script.load()
            
            logger.info("脚本注入成功")
            self.scripts.append(script_content)
            return True
        except Exception as e:
            logger.error(f"脚本注入失败: {e}")
            return False

    def run_instrumentation(, self, target_path: str = None, pid: int = None, script_path: str = None, templates: List[str] = None, template_params: Dict[str, Any] = None) -> Dict[str, Any]:
        """运行完整的插桩流程"""
        result = {
            'success': False,
            'pid': None,
            'scripts_injected': 0,
            'errors': []
        }
        
        if not FRIDA_AVAILABLE:
            result['errors'].append("Frida 未安装")
            return result
        
        try:
            if pid:
                if not self.attach_process(pid):
                    result['errors'].append(f"无法附加到进程 {pid}")
                    return result
            elif target_path:
                if not self.spawn_process(target_path):
                    result['errors'].append(f"无法启动进程 {target_path}")
                    return result
                
                if not self.attach_process(self.target_process):
                    result['errors'].append(f"无法附加到已启动的进程")
                    return result
            else:
                result['errors'].append("必须指定目标路径或 PID")
                return result
            
            result['pid'] = self.target_process
            
            scripts_injected = 0
            
            if script_path:
                custom_script = self.load_custom_script(script_path)
                if custom_script:
                    if self.inject_script(custom_script):
                        scripts_injected += 1
                        logger.info(f"已注入自定义脚本: {script_path}")
            
            if templates:
                template_params = template_params or {}
                for template in templates:
                    script_content = self.generate_template_script(template, template_params.get(template, {}

                    if script_content:
                        if self.inject_script(script_content):
                            scripts_injected += 1
                            logger.info(f"已注入模板脚本: {template}")
            
            result['scripts_injected'] = scripts_injected
            result['success'] = True
            
            if self.mode == InstrumentationMode.SPAWN:
                frida.resume(self.target_process)
                logger.info("进程已恢复运行")
            
            return result
            
        except Exception as e:
            logger.error(f"插桩执行失败: {e}")
            result['errors'].append(str(e

            return result

    def detach(self):
        """分离进程"""
        if self.frida_session:
            try:
                self.frida_session.detach()
                logger.info("已分离进程")
            except Exception as e:
                logger.error(f"分离进程失败: {e}")
        
        self.frida_session = None
        self.frida_script = None

    def save_logs(self, output_path: str = None) -> Optional[str]:
        """保存插桩日志"""
        if not output_path:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.output_dir, f'instrumentation_{timestamp}.log')
        
        try:
            log_content = json.dumps({)
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'pid': self.target_process,
                'scripts': self.scripts,
                'mode': self.mode.value
            }, indent=2
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(log_content)
            
            logger.info(f"插桩日志已保存: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"保存日志失败: {e}")
            return None

    def list_available_templates(self) -> List[Dict[str, str]]:
        """列出可用的钩子模板"""
        return [
            {
                'name': 'anti_debug',
                'description': '绕过常见反调试检测',
                'parameters': []
            },
            {
                'name': 'ret_override',
                'description': '修改函数返回值',
                'parameters': ['func_name (目标函数名)', 'return_value (新返回值)']
            },
            {
                'name': 'syscall_monitor',
                'description': '监控系统调用',
                'parameters': []
            },
            {
                'name': 'memory_dump',
                'description': 'Dump 指定内存区域',
                'parameters': ['address (内存地址)', 'size (大小)']
            },
            {
                'name': 'argument_replace',
                'description': '替换函数参数',
                'parameters': ['func_name (目标函数名)', 'arg_index (参数索引)', 'new_value (新值)']
            },
            {
                'name': 'function_trace',
                'description': '追踪内存分配函数调用',
                'parameters': []
            }
        ]

    def parse_template_args(self, args_str: str) -> Tuple[List[str], Dict[str, Any]]:
        """解析模板参数字符串"""
        templates = []
        params = {}
        
        if not args_str:
            return templates, params
        
        parts = args_str.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            if '=' in part:
                key_value = part.split('=', 1)
                if len(key_value) == 2:
                    key, value = key_value,
                    if ':' in key:
                        template_name, param_name = key.split(':', 1)
                        if template_name not in params:
                            params[template_name] = {}
                        params[template_name][param_name] = self._parse_param_value(value)
                    else:
                        params[key] = self._parse_param_value(value)
            else:
                templates.append(part)
        
        return templates, params

    def _parse_param_value(self, value: str) -> Any:
        """解析参数值"""
        if value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        
        if value.startswith('0x'):
            try:
                return int(value, 16)
            except ValueError:
                pass
        
        try:
            return int(value)
        except ValueError:
            pass
        
        try:
            return float(value)
        except ValueError:
            pass
        
        return value

    def __del__(self):
        """析构函数，确保清理资源"""
        self.detach(