import os, logging, subprocess, json, time, sys as _sys
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

FRIDA_AVAILABLE = False
try:
    import frida; FRIDA_AVAILABLE = True
except ImportError:
    logger.info("Frida not installed. Instrumentation features disabled.")


def _frida_env():
    """读取 Frida 运行环境标记。

    扁平命名空间导入会为 modules.instrumentation 建立包装模块,
    测试通过该名称打补丁; 此处优先从 modules 包的属性读取,
    与 sys.modules 中的注册对象合并, 保证补丁可见。
    """
    candidate = None
    try:
        import modules as _modules_pkg
        candidate = getattr(_modules_pkg, 'instrumentation', None)
    except Exception:
        candidate = None
    if candidate is None:
        candidate = _sys.modules.get('modules.instrumentation')
    if candidate is not None:
        wrapper_frida = getattr(candidate, 'frida', None)
        wrapper_flag = getattr(candidate, 'FRIDA_AVAILABLE', None)
        if wrapper_frida is not None:
            return bool(wrapper_flag if wrapper_flag is not None else FRIDA_AVAILABLE), wrapper_frida
        if wrapper_flag is not None:
            return bool(wrapper_flag), globals().get('frida')
    return FRIDA_AVAILABLE, globals().get('frida')

class InstrumentationMode:
    SPAWN='spawn'; ATTACH='attach'; INJECT='inject'
    STALKER='stalker'; HYBRID='hybrid'

class HookTemplateType:
    ANTI_DEBUG='anti_debug'; RET_OVERRIDE='ret_override'; SYSCALL_MONITOR='syscall_monitor'
    MEMORY_DUMP='memory_dump'; ARGUMENT_REPLACE='argument_replace'; FUNCTION_TRACE='function_trace'
    NETWORK_MONITOR='network_monitor'; STALKER_TRACE='stalker_trace'

@dataclass
class HookTemplate:
    name: str=""; template_type: Any=None; description: str=""; script_template: Any=None

class InstrumentationManager:
    """Frida 插桩 manager Stalker fast-追踪 template-based 钩子 injection"""

    def __init__(self):
        self.frida_session=None; self.frida_script=None
        self.mode=InstrumentationMode.SPAWN; self.target_process=None
        self.output_dir='./logs/instrumentation'; self.scripts=[]
        self._ensure_output_dir()
        self._preloaded_hooks: Dict[str, str] = {}

    def _ensure_output_dir(self):
        try:
            if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)
        except Exception as e: logger.error(f"Failed to create instrumentation log directory: {e}")

    def is_frida_available(self)->bool:
        avail, _ = _frida_env()
        return avail

# 舍入 2: 预编译钩子缓存
    # 将常用的Frida脚本模板预编译为JavaScript字符串并缓存
    # 避免重复的字符串拼接开销，在高频hook场景下减少GC压力
    def preload_templates(self):
        """预加载所有hook模板到内存缓存。首次调用后，后续inject_script直接从缓存读取"""
        templates = {
            'anti_debug': self._generate_anti_debug_script(),
            'syscall_monitor': self._generate_syscall_monitor_script(),
            'function_trace': self._generate_function_trace_script(),
            'network_monitor': self._generate_network_monitor_script(),
            'stalker': self._generate_stalker_script(),
        }
        for name, code in templates.items():
            if code:
                self._preloaded_hooks[name] = code
        logger.info(f"Preloaded {len(self._preloaded_hooks)} hook templates")

# 舍入 2: Stalker快速追踪集成
    # Frida Stalker是代码级追踪引擎，在每条指令执行时触发回调
    # 相比Interceptor（仅函数级），Stalker可捕获所有间接跳转和ROP gadget
    def _generate_stalker_script(self) -> str:
        return """
        let traceBuffer = [];
        const MAX_BUFFER = 5000;
        const FLUSH_INTERVAL = 200; // ms between batch sends

        function flushTrace() {
            if (traceBuffer.length === 0) return;
            const batch = traceBuffer.splice(0, traceBuffer.length);
            send({type: 'stalker_batch', events: batch, count: batch.length});
        }

        Stalker.follow(Process.getCurrentThreadId(), {
            events: { call: true, ret: false, exec: false },
            onReceive(events) {
                const buf = traceBuffer;
                for (let ev of events) {
                    const addr = ev[0], loc = ev[1];
                    if (buf.length < MAX_BUFFER) {
                        buf.push({addr: ptr(addr).toString(), loc: ptr(loc).toString()});
                    }
                }
            }
        });
        setInterval(flushTrace, FLUSH_INTERVAL);
        """

    def _generate_anti_debug_script(self)->str:
        return """const antiDebug={run:function(){try{Interceptor.attach(Module.findExportByName(null,'ptrace'),{onEnter:function(args){this.returnValue=ptr(0)},onLeave:function(retval){retval.replace(ptr(0))}})}catch(e){}
try{Interceptor.attach(Module.findExportByName(null,'IsDebuggerPresent'),{onLeave:function(retval){retval.replace(ptr(0))}})}catch(e){}
try{Interceptor.attach(Module.findExportByName(null,'waitpid'),{onEnter:function(args){args[1]=ptr(0)}})}catch(e){}
try{Interceptor.attach(Module.findExportByName(null,'getpid'),{onLeave:function(retval){retval.replace(ptr(-1))}})}catch(e){}}};antiDebug.run();"""

    def _generate_ret_override_script(self,func_name:str,return_value:int)->str:
        return f"""const ro={{targetFunc:'{func_name}',targetValue:ptr({hex(return_value)}),run:function(){{try{{const fp=Module.findExportByName(null,this.targetFunc);if(fp)Interceptor.attach(fp,{{onLeave:function(retval){{retval.replace(this.targetValue)}}}})}}catch(e){{}}}}}};ro.run();"""

    def _generate_syscall_monitor_script(self)->str:
        return """const sm={monitoredCalls:['open','read','write','execve','fork','socket'],run:function(){this.monitoredCalls.forEach((n)=>{try{const fp=Module.findExportByName(null,n);if(fp)Interceptor.attach(fp,{onEnter(args){send({type:'syscall',name:n,args:[a.toInt32() for(a of args)]})},onLeave(retval){send({type:'syscall_ret',name:n,ret:retval.toInt32()})}})}catch(e){}})}}};sm.run();"""

    def _generate_memory_dump_script(self,address:str,size:int)->str:
        return f"""const md={{address:ptr('{address}'),size:{size},run:function(){{try{{const data=this.address.readByteArray(this.size);if(data){{const bytes=Array.from(new Uint8Array(data));send({{type:'memdump',addr:this.address.toString(),data:bytes,hexdump:this.address.readByteArray(this.size).hexdump()}})}}}}catch(e){{}}}}}};md.run();"""

    def _generate_argument_replace_script(self,func_name:str,arg_index:int,new_value:int)->str:
        return f"""const ar={{tf:'{func_name}',ai:{arg_index},nv:ptr({new_value}),run:function(){{try{{const fp=Module.findExportByName(null,this.tf);if(fp)Interceptor.attach(fp,{{onEnter(args){{args[this.ai]=this.nv}}}})}}catch(e){{}}}}}};ar.run();"""

    def _generate_function_trace_script(self)->str:
        return """const ft={td:0,functionTrace:true,run:function(){try{const lc=Process.findModuleByName('libc.so.6')||Process.findModuleByName('libSystem.B.dylib')||Process.findModuleByName('msvcrt.dll');if(lc){['malloc','free','calloc','realloc'].forEach((n)=>{const fp=lc.getExportByName(n);if(fp)Interceptor.attach(fp,{onEnter(args){ft.td++;send({type:'trace',fn:n,sz:args[0].toInt32(),depth:ft.td})},onLeave(rv){ft.td--}})});}}}}};ft.run();"""

    def parse_template_args(self, arg_str: Optional[str]) -> Tuple[List[str], Dict[str, Any]]:
        """解析模板参数串: 'a,b,a:key=val' → (['a','b'], {'a': {'key': val}})."""
        if not arg_str:
            return [], {}
        templates: List[str] = []
        params: Dict[str, Any] = {}
        for token in str(arg_str).split(','):
            token = token.strip()
            if not token:
                continue
            if ':' in token:
                tname, spec = token.split(':', 1)
                if '=' in spec:
                    key, val = spec.split('=', 1)
                    params.setdefault(tname, {})[key] = self._parse_param_value(val)
            elif token not in templates:
                templates.append(token)
        return templates, params

    def _parse_param_value(self, raw: str) -> Any:
        """将参数字符串解析为 int/float/bool/str。"""
        low = raw.lower()
        if low == 'true':
            return True
        if low == 'false':
            return False
        try:
            return int(raw, 0)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            return raw

# Round 2: 网络监控模板
    def _generate_network_monitor_script(self)->str:
        """跨平台网络套接字 API监控。Linux/macOS/Windows自动适配"""
        return """
        function hookNetFunc(mod, name) {
            const fp = Module.findExportByName(mod, name);
            if (!fp) return;
            Interceptor.attach(fp, {
                onEnter(args) {
                    send({type: 'network', func: name,
                          args: [args[0].toInt32(), args[1].toInt32(), args[2].toInt32()]});
                }
            });
        }
        // Linux/macOS
        ['libc.so.6', 'libc.so', 'libSystem.B.dylib'].forEach(m => {
            ['connect', 'send', 'recv', 'sendto', 'recvfrom'].forEach(f => hookNetFunc(m, f));
        });
        // Windows
        ['ws2_32.dll'].forEach(m => {
            ['connect', 'send', 'recv', 'WSASend', 'WSARecv'].forEach(f => hookNetFunc(m, f));
        });
        """

    def generate_template_script(self,template_type:str,params:Dict[str,Any]=None)->Optional[str]:
        params=params or {}
        # 优先从缓存读取预编译模板
        cached = self._preloaded_hooks.get(template_type)
        if cached and not params:
            return cached

        try: te=getattr(HookTemplateType, template_type.upper())
        except AttributeError: logger.error(f"Unknown template type: {template_type}"); return None
        if not isinstance(te, str): logger.error(f"Unknown template type: {template_type}"); return None

        if te==HookTemplateType.ANTI_DEBUG: return self._generate_anti_debug_script()
        elif te==HookTemplateType.RET_OVERRIDE: return self._generate_ret_override_script(params.get('func_name','exit'),params.get('return_value',0))
        elif te==HookTemplateType.SYSCALL_MONITOR: return self._generate_syscall_monitor_script()
        elif te==HookTemplateType.MEMORY_DUMP: return self._generate_memory_dump_script(params.get('address','0x0'),params.get('size',0x100))
        elif te==HookTemplateType.ARGUMENT_REPLACE: return self._generate_argument_replace_script(params.get('func_name',''),params.get('arg_index',0),params.get('new_value',0))
        elif te==HookTemplateType.FUNCTION_TRACE: return self._generate_function_trace_script()
        elif te==HookTemplateType.NETWORK_MONITOR: return self._generate_network_monitor_script()
        elif te==HookTemplateType.STALKER_TRACE: return self._generate_stalker_script()
        return None

    def load_custom_script(self,script_path:str)->Optional[str]:
        if not os.path.exists(script_path): logger.error(f"Script file not found: {script_path}"); return None
        try:
            with open(script_path,'r',encoding='utf-8') as f: return f.read()
        except Exception as e: logger.error(f"Failed to load script: {e}"); return None

    def spawn_process(self,target_path:str,args:List[str]=None)->bool:
        avail, frida_mod = _frida_env()
        if not avail: logger.error("Frida unavailable."); return False
        try:
            self.target_process=frida_mod.spawn([target_path]+(args or [])); self.mode=InstrumentationMode.SPAWN
            logger.info(f"Process spawned, PID: {self.target_process}"); return True
        except Exception as e: logger.error(f"Failed to spawn process: {e}"); return False

    def attach_process(self,pid:int)->bool:
        avail, frida_mod = _frida_env()
        if not avail: logger.error("Frida unavailable."); return False
        try:
            self.frida_session=frida_mod.attach(pid); self.target_process=pid; self.mode=InstrumentationMode.ATTACH
            logger.info(f"Attached to process PID: {pid}"); return True
        except Exception as e: logger.error(f"Failed to attach to process: {e}"); return False

    def inject_script(self,script_content:str)->bool:
        avail, frida_mod = _frida_env()
        if not avail or not self.frida_session: logger.error("Frida session not established"); return False
        try:
            self.frida_script=self.frida_session.create_script(script_content)
            def on_message(message,data):
                if message['type']=='send': logger.info(f"[Frida] {message['payload']}")
                elif message['type']=='error': logger.error(f"[Frida Error] {message.get('description','')}")
            self.frida_script.on('message',on_message); self.frida_script.load()
            self.scripts.append(script_content); return True
        except Exception as e: logger.error(f"Script injection failed: {e}"); return False

    def run_instrumentation(self,target_path:str=None,pid:int=None,script_path:str=None,templates:List[str]=None,template_params:Dict[str,Any]=None)->Dict[str,Any]:
        result={'success':False,'pid':None,'scripts_injected':0,'errors':[]}
        avail, frida_mod = _frida_env()
        if not avail: result['errors'].append("Frida not installed"); return result
        try:
            if pid:
                if not self.attach_process(pid): result['errors'].append(f"Failed to attach to process {pid}"); return result
            elif target_path:
                if not self.spawn_process(target_path): result['errors'].append(f"Failed to spawn process {target_path}"); return result
                if not self.attach_process(self.target_process): result['errors'].append("Failed to attach to spawned process"); return result
            else: result['errors'].append("Must specify target_path or PID"); return result
            result['pid']=self.target_process; scripts_injected=0
            if script_path:
                cs=self.load_custom_script(script_path)
                if cs and self.inject_script(cs): scripts_injected+=1
            if templates:
                for t in templates:
                    sc=self.generate_template_script(t,(template_params or {}).get(t,{}))
                    if sc and self.inject_script(sc): scripts_injected+=1
            result['scripts_injected']=scripts_injected; result['success']=True
            if self.mode==InstrumentationMode.SPAWN: frida_mod.resume(self.target_process)
            return result
        except Exception as e: logger.error(f"Instrumentation execution failed: {e}"); result['errors'].append(str(e)); return result

# Round 2: 超时自动分离
    def run_with_timeout(self, target_path: str = None, pid: int = None,
                         timeout_sec: int = 30, **kwargs) -> Dict[str, Any]:
        """在指定超时后自动detach，防止长时间挂起
        启动独立线程计时，到期后调用frida_session.detach()"""
        import threading
        result = self.run_instrumentation(target_path=target_path, pid=pid, **kwargs)
        if not result['success']:
            return result

        def _timeout_guard():
            time.sleep(timeout_sec)
            if self.frida_session:
                try:
                    self.frida_session.detach()
                    logger.info(f"Auto-detached after {timeout_sec}s timeout")
                except Exception:
                    pass

        guard = threading.Thread(target=_timeout_guard, daemon=True)
        guard.start()
        result['timeout_seconds'] = timeout_sec
        return result

    def detach(self):
        if self.frida_session:
            try: self.frida_session.detach(); logger.info("Detached from process")
            except Exception as e: logger.error(f"Failed to detach: {e}")
        self.frida_session=None; self.frida_script=None

    def save_logs(self,output_path:str=None)->Optional[str]:
        if not output_path: output_path=os.path.join(self.output_dir,f'instrumentation_{time.strftime("%Y%m%d_%H%M%S")}.log')
        try:
            with open(output_path,'w',encoding='utf-8') as f:
                json.dump({'timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'pid':self.target_process,'scripts':len(self.scripts),'mode':self.mode},f,indent=2)
            logger.info(f"Instrumentation log saved: {output_path}"); return output_path
        except Exception as e: logger.error(f"Failed to save log: {e}"); return None

    def list_available_templates(self)->List[Dict[str,str]]:
        return [{'name':'anti_debug','description':'Bypass common anti-debug checks','parameters':[]},
                {'name':'ret_override','description':'Override function return value','parameters':['func_name','return_value']},
                {'name':'syscall_monitor','description':'Monitor system calls','parameters':[]},
                {'name':'memory_dump','description':'Dump specified memory region','parameters':['address','size']},
                {'name':'argument_replace','description':'Replace function arguments','parameters':['func_name','arg_index','new_value']},
                {'name':'function_trace','description':'Trace memory allocation function calls','parameters':[]},
                {'name':'network_monitor','description':'Monitor socket API calls','parameters':[]},
                {'name':'stalker_trace','description':'Stalker instruction-level tracing','parameters':[]}]

    def __del__(self): self.detach()
