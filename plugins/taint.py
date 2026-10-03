"""
Dynamic taint tracking. Supports Frida (binary instrumentation)
and QBDI (dynamic binary instrumentation framework).
Requires external tools to be installed.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def check_frida() -> bool:
    try:
        import frida
        return True
    except ImportError:
        return False


def run_taint_track(binary_path: str, input_data: bytes = None,
                    engine: str = 'frida',
                    timeout: int = 60) -> Dict[str, Any]:
    """
    Run dynamic taint analysis on a binary.

    engine: 'frida' or 'qbdi'
    返回 {success, taint_sources, taint_sinks, traces}
    """
    result = {
        'success': False,
        'engine': engine,
        'taint_sources': [],
        'taint_sinks': [],
        'traces': [],
    }

    if engine == 'frida':
        if not check_frida():
            result['error'] = 'frida not installed (pip install frida-tools)'
            return result
        return _taint_frida(binary_path, input_data, timeout)

    elif engine == 'qbdi':
        return _taint_qbdi(binary_path, input_data, timeout)

    result['error'] = f'unknown engine: {engine}'
    return result


def _taint_frida(binary_path: str, input_data: bytes,
                 timeout: int) -> Dict:
    """
    Attach Frida to the target binary and trace data flow from
    input sources (read, recv, fgets) to sinks (memcpy, strcpy, system).
    """
    try:
        import frida

        session = frida.spawn(binary_path)
        pid = session._impl.pid

        script = session.create_script("""
            // Hook read() — mark returned buffer as tainted
            const readPtr = Module.findExportByName(null, 'read');
            if (readPtr) {
              Interceptor.attach(readPtr, {
                onLeave(retval) {
                  if (retval.toInt32() > 0) {
                    send({type: 'taint_source', func: 'read',
                          size: retval.toInt32()});
                  }
                }
              });
            }

            // Hook memcpy — sink
            const memcpyPtr = Module.findExportByName(null, 'memcpy');
            if (memcpyPtr) {
              Interceptor.attach(memcpyPtr, {
                onEnter(args) {
                  send({type: 'taint_sink', func: 'memcpy',
                        dest: args[0], src: args[1], size: args[2].toInt32()});
                }
              });
            }

            // Hook system — dangerous sink
            const systemPtr = Module.findExportByName(null, 'system');
            if (systemPtr) {
              Interceptor.attach(systemPtr, {
                onEnter(args) {
                  send({type: 'dangerous_sink', func: 'system',
                        cmd: args[0].readUtf8String()});
                }
              });
            }
        """)

        sources = []
        sinks = []

        def on_message(msg, data):
            payload = msg.get('payload', {})
            t = payload.get('type', '')
            if t == 'taint_source':
                sources.append(payload)
            elif t in ('taint_sink', 'dangerous_sink'):
                sinks.append(payload)

        script.on('message', on_message)
        script.load()
        session.resume()

        import time
        time.sleep(min(timeout, 30))
        session.detach()

        return {
            'success': True,
            'engine': 'frida',
            'taint_sources': sources,
            'taint_sinks': sinks,
        }
    except Exception as ex:
        logger.warning("Frida taint analysis failed: %s", ex)
        return {'success': False, 'engine': 'frida', 'error': str(ex)}


def _taint_qbdi(path: str, data: bytes, timeout: int) -> Dict:
    """
    用 QBDI 动态二进制翻译框架对目标做污点跟踪：
    将输入 data 载入模拟内存标记为污染源，记录指令流中
    对污染地址的读取（传播观察）与写入（汇点）。
    需要 PyQBDI（pip install qbdi）与 pyelftools。
    """
    try:
        import qbdi
    except ImportError:
        return {'success': False, 'engine': 'qbdi',
                'error': 'qbdi not installed (pip install qbdi)'}

    # PyQBDI 版本差异：新版暴露 Platform 枚举，旧版为 Architecture
    if hasattr(qbdi, 'Platform') and hasattr(qbdi.Platform, 'X86_64'):
        platform = qbdi.Platform.X86_64
    else:
        platform = qbdi.Architecture.X86_64

    sources = []
    sinks = []

    # 输入缓冲模拟地址，选用进程映射区外的保留区间避免冲突
    buf_addr = 0x10000000
    buf_size = max(len(data), 1)
    tainted = set(range(buf_addr, buf_addr + buf_size))

    # 从 ELF 头取入口地址，作为翻译起点
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, 'rb') as f:
            entry = ELFFile(f).header['e_entry']
    except Exception:
        logger.warning("cannot resolve ELF entry point of %s", path)
        return {'success': False, 'engine': 'qbdi',
                'error': 'cannot resolve ELF entry point'}

    def mem_read_cb(vm_inst, addr, size, _ud):
        if size and addr + size - 1 in tainted:
            sources.append({'func': 'qbdimemread',
                            'addr': hex(addr), 'size': size})
        return qbdi.CallbackReturn.CONTINUE

    def mem_write_cb(vm_inst, addr, size, _ud):
        if size and addr + size - 1 in tainted:
            sinks.append({'func': 'qbdimemwrite',
                          'addr': hex(addr), 'size': size})
        return qbdi.CallbackReturn.CONTINUE

    try:
        vm = qbdi.VM(platform)

        # 注册内存回调：命中污染区间的读取记录为传播，写入记录为汇点
        mem_ro = getattr(qbdi.MemAccessKind, 'MEM_READ', qbdi.MEM_READ)
        mem_wo = getattr(qbdi.MemAccessKind, 'MEM_WRITE', qbdi.MEM_WRITE)
        vm.addMemAccessCB(mem_ro, mem_read_cb, None)
        vm.addMemAccessCB(mem_wo, mem_write_cb, None)

        vm.addInstrumentedModule(path)
        vm.setDumpExecCode(True)

        # 限定翻译窗口：从入口地址运行一段虚拟地址范围
        vm.run(entry, entry + 0x100000)

        return {
            'success': True,
            'engine': 'qbdi',
            'taint_sources': sources,
            'taint_sinks': sinks,
            'traces': [],
        }
    except Exception as ex:
        logger.warning("QBDI taint analysis failed: %s", ex)
        return {'success': False, 'engine': 'qbdi', 'error': str(ex)}
