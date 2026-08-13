import os
import logging
import subprocess
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

FRIDA_AVAILABLE = False
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    logger.info("Frida not installed. Instrumentation features disabled.")

class InstrumentationMode:
    SPAWN = 'spawn'
    ATTACH = 'attach'
    INJECT = 'inject'


class HookTemplateType:
    ANTI_DEBUG = 'anti_debug'
    RET_OVERRIDE = 'ret_override'
    SYSCALL_MONITOR = 'syscall_monitor'
    MEMORY_DUMP = 'memory_dump'
    ARGUMENT_REPLACE = 'argument_replace'
    FUNCTION_TRACE = 'function_trace'


@dataclass
class HookTemplate:
    name: str = ""
    template_type: Any = None
    description: str = ""
    script_template: Any = None
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
                logger.info(f"Instrumentation log directory created: {self.output_dir}")
        except Exception as e:
            logger.error(f"Failed to create instrumentation log directory: {e}")

    def is_frida_available(self) -> bool:
        return FRIDA_AVAILABLE

    def _generate_anti_debug_script(self) -> str:
        return """
const antiDebug = {
    run: function() {
        console.log('[+] Anti-debug bypass activated');

        try {
            Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
                onEnter: function(args) {
                    console.log('[DEBUG] ptrace call intercepted');
                    this.returnValue = ptr(0);
                },
                onLeave: function(retval) {
                    retval.replace(ptr(0));
                }
            });
        } catch(e) { console.log('[-] ptrace hook failed:', e.message); }

        try {
            Interceptor.attach(Module.findExportByName(null, 'waitpid'), {
                onEnter: function(args) {
                    console.log('[DEBUG] waitpid call intercepted');
                }
            });
        } catch(e) { console.log('[-] waitpid hook failed:', e.message); }

        try {
            Interceptor.attach(Module.findExportByName(null, 'getpid'), {
                onLeave: function(retval) {
                    retval.replace(ptr(0x1337));
                }
            });
        } catch(e) { console.log('[-] getpid hook failed:', e.message); }

        console.log('[+] Anti-debug bypass engaged');
    }
};

antiDebug.run();
"""

    def _generate_ret_override_script(self, func_name: str, return_value: int) -> str:
        """Generate return value override script"""
        script = """
const retOverride = {
    targetFunc: '%s',
    targetValue: ptr(%d),

    run: function() {
        console.log('[+] Return value override active: %s -> 0x%s');

        try {
            const funcPtr = Module.findExportByName(null, this.targetFunc);
            if (funcPtr) {
                Interceptor.attach(funcPtr, {
                    onLeave: function(retval) {
                        console.log('[DEBUG] ' + this.targetFunc + ' original return: ' + retval);
                        retval.replace(this.targetValue);
                        console.log('[DEBUG] ' + this.targetFunc + ' override applied: ' + this.targetValue);
                    }
                });
                console.log('[+] ' + this.targetFunc + ' return override installed');
            } else {
                console.log('[-] Function not found: ' + this.targetFunc);
            }
        } catch(e) {
            console.log('[-] Return override failed:', e.message);
        }
    }
};

retOverride.run();
""" % (func_name, return_value, func_name, format(return_value, 'x'))

        return script

    def _generate_syscall_monitor_script(self) -> str:
        """Generate system call monitor script"""
        return """
const syscallMonitor = {
    monitoredCalls: ['open', 'read', 'write', 'execve', 'fork', 'socket'],

    run: function() {
        console.log('[+] System call monitor active');

        this.monitoredCalls.forEach((name) => {
            try {
                const funcPtr = Module.findExportByName(null, name);
                if (funcPtr) {
                    Interceptor.attach(funcPtr, {
                        onEnter: function(args) {
                            this.args = args;
                            this.startTime = Date.now();
                            console.log(`[SYSCALL] ${name} called`);
                        },
                        onLeave: function(retval) {
                            const duration = Date.now() - this.startTime;
                            console.log(`[SYSCALL] ${name} returned: ${retval}, elapsed: ${duration}ms`);
                        }
                    });
                    console.log(`[+] Monitoring: ${name}`);
                }
            } catch(e) {
                console.log(`[-] Monitor failed for ${name}:`, e.message);
            }
        });

        console.log('[+] System call monitor engaged');
    }
};

syscallMonitor.run();
"""

    def _generate_memory_dump_script(self, address: str, size: int) -> str:
        """Generate memory dump script"""
        script = """
const memoryDump = {
    address: ptr('%s'),
    size: %d,

    run: function() {
        console.log('[+] Dumping memory at:', this.address, ', size:', this.size, 'bytes');

        try {
            const data = this.address.readByteArray(this.size);
            if (data) {
                console.log('[DUMP] Memory contents (' + this.size + ' bytes):');
                console.log(hexdump(this.address, {
                    length: this.size,
                    header: true,
                    ansi: true
                }));
            } else {
                console.log('[-] Memory read failed');
            }
        } catch(e) {
            console.log('[-] Memory dump failed:', e.message);
        }
    }
};

memoryDump.run();
""" % (address, size)
        return script

    def _generate_argument_replace_script(self, func_name: str, arg_index: int, new_value: int) -> str:
        """Generate argument replacement script"""
        script = """
const argReplace = {
    targetFunc: '%s',
    argIndex: %d,
    newValue: ptr(%d),

    run: function() {
        console.log('[+] Argument replace active:', this.targetFunc, 'arg[', this.argIndex, '] ->', this.newValue);

        try {
            const funcPtr = Module.findExportByName(null, this.targetFunc);
            if (funcPtr) {
                Interceptor.attach(funcPtr, {
                    onEnter: function(args) {
                        console.log('[DEBUG] ' + argReplace.targetFunc + ' original arg[' + argReplace.argIndex + ']: ' + args[argReplace.argIndex]);
                        args[argReplace.argIndex] = argReplace.newValue;
                        console.log('[DEBUG] ' + argReplace.targetFunc + ' modified arg[' + argReplace.argIndex + ']: ' + args[argReplace.argIndex]);
                    }
                });
                console.log('[+] ' + this.targetFunc + ' argument replacer installed');
            } else {
                console.log('[-] Function not found: ' + this.targetFunc);
            }
        } catch(e) {
            console.log('[-] Argument replacement failed:', e.message);
        }
    }
};

argReplace.run();
""" % (func_name, arg_index, new_value)
        return script

    def _generate_function_trace_script(self) -> str:
        """Generate function call trace script"""
        return """
const functionTrace = {
    traceDepth: 0,

    run: function() {
        console.log('[+] Function trace active');

        try {
            const libc = Process.findModuleByName('libc.so.6') ||
                        Process.findModuleByName('libSystem.B.dylib') ||
                        Process.findModuleByName('msvcrt.dll');

            if (libc) {
                console.log(`[+] Target library: ${libc.name}`);

                ['malloc', 'free', 'calloc', 'realloc'].forEach((name) => {
                    const funcPtr = libc.getExportByName(name);
                    if (funcPtr) {
                        Interceptor.attach(funcPtr, {
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

                console.log('[+] Function trace engaged');
            } else {
                console.log('[-] C standard library not found');
            }
        } catch(e) {
            console.log('[-] Function trace activation failed:', e.message);
        }
    }
};

functionTrace.run();
"""

    def generate_template_script(self, template_type: str, params: Dict[str, Any] = None) -> Optional[str]:
        """Generate Frida script for a given template type"""
        params = params or {}

        try:
            template_enum = HookTemplateType(template_type.lower())
        except ValueError:
            logger.error(f"Unknown template type: {template_type}")
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
        if not os.path.exists(script_path):
            logger.error(f"Script file not found: {script_path}")
            return None

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.info(f"Custom script loaded: {script_path}")
            return content
        except Exception as e:
            logger.error(f"Failed to load script: {e}")
            return None

    def spawn_process(self, target_path: str, args: List[str] = None) -> bool:
        """Spawn target process"""
        if not FRIDA_AVAILABLE:
            logger.error("Frida unavailable. Cannot spawn process.")
            return False

        try:
            args = args or []
            logger.info(f"Spawning process: {target_path} {' '.join(args)}")

            pid = frida.spawn([target_path] + args)
            self.target_process = pid
            self.mode = InstrumentationMode.SPAWN

            logger.info(f"Process spawned, PID: {pid}")
            return True
        except Exception as e:
            logger.error(f"Failed to spawn process: {e}")
            return False

    def attach_process(self, pid: int) -> bool:
        if not FRIDA_AVAILABLE:
            logger.error("Frida unavailable. Cannot attach to process.")
            return False

        try:
            logger.info(f"Attaching to process: PID {pid}")
            self.frida_session = frida.attach(pid)
            self.target_process = pid
            self.mode = InstrumentationMode.ATTACH
            logger.info(f"Attached to process PID: {pid}")
            return True
        except Exception as e:
            logger.error(f"Failed to attach to process: {e}")
            return False

    def inject_script(self, script_content: str) -> bool:
        if not FRIDA_AVAILABLE or not self.frida_session:
            logger.error("Frida session not established")
            return False

        try:
            logger.info("Injecting Frida script...")
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

            logger.info("Script injected successfully")
            self.scripts.append(script_content)
            return True
        except Exception as e:
            logger.error(f"Script injection failed: {e}")
            return False

    def run_instrumentation(self,
        target_path: str = None,
        pid: int = None,
        script_path: str = None,
        templates: List[str] = None,
        template_params: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        result = {
            'success': False,
            'pid': None,
            'scripts_injected': 0,
            'errors': []
        }

        if not FRIDA_AVAILABLE:
            result['errors'].append("Frida not installed")
            return result

        try:
            if pid:
                if not self.attach_process(pid):
                    result['errors'].append(f"Failed to attach to process {pid}")
                    return result
            elif target_path:
                if not self.spawn_process(target_path):
                    result['errors'].append(f"Failed to spawn process {target_path}")
                    return result

                if not self.attach_process(self.target_process):
                    result['errors'].append(f"Failed to attach to spawned process")
                    return result
            else:
                result['errors'].append("Must specify target_path or PID")
                return result

            result['pid'] = self.target_process

            scripts_injected = 0

            if script_path:
                custom_script = self.load_custom_script(script_path)
                if custom_script:
                    if self.inject_script(custom_script):
                        scripts_injected += 1
                        logger.info(f"Custom script injected: {script_path}")

            if templates:
                template_params = template_params or {}
                for template in templates:
                    script_content = self.generate_template_script(template, template_params.get(template, {}))
                    if script_content:
                        if self.inject_script(script_content):
                            scripts_injected += 1
                            logger.info(f"Template script injected: {template}")

            result['scripts_injected'] = scripts_injected
            result['success'] = True

            if self.mode == InstrumentationMode.SPAWN:
                frida.resume(self.target_process)
                logger.info("Process resumed")

            return result

        except Exception as e:
            logger.error(f"Instrumentation execution failed: {e}")
            result['errors'].append(str(e))
            return result

    def detach(self):
        """Detach from process"""
        if self.frida_session:
            try:
                self.frida_session.detach()
                logger.info("Detached from process")
            except Exception as e:
                logger.error(f"Failed to detach: {e}")

        self.frida_session = None
        self.frida_script = None

    def save_logs(self, output_path: str = None) -> Optional[str]:
        if not output_path:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.output_dir, f'instrumentation_{timestamp}.log')

        try:
            log_content = json.dumps({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'pid': self.target_process,
                'scripts': self.scripts,
                'mode': self.mode.value
            }, indent=2)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(log_content)

            logger.info(f"Instrumentation log saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save log: {e}")
            return None

    def list_available_templates(self) -> List[Dict[str, str]]:
        return [
            {
                'name': 'anti_debug',
                'description': 'Bypass common anti-debug checks',
                'parameters': []
            },
            {
                'name': 'ret_override',
                'description': 'Override function return value',
                'parameters': ['func_name (target function name)', 'return_value (new return value)']
            },
            {
                'name': 'syscall_monitor',
                'description': 'Monitor system calls',
                'parameters': []
            },
            {
                'name': 'memory_dump',
                'description': 'Dump specified memory region',
                'parameters': ['address (memory address)', 'size (bytes)']
            },
            {
                'name': 'argument_replace',
                'description': 'Replace function arguments',
                'parameters': ['func_name (target function name)', 'arg_index (argument index)', 'new_value (new value)']
            },
            {
                'name': 'function_trace',
                'description': 'Trace memory allocation function calls',
                'parameters': []
            }
        ]

    def parse_template_args(self, args_str: str) -> Tuple[List[str], Dict[str, Any]]:
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
                    key, value = key_value
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
        self.detach()


class InstrumentationMode:
    SPAWN = "spawn"
    ATTACH = "attach"
    INJECT = "inject"
