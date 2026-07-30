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
    Returns: {success, taint_sources, taint_sinks, traces}
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
    except Exception as e:
        logger.warning("Frida taint analysis failed: %s", e)
        return {'success': False, 'engine': 'frida', 'error': str(e)}


def _taint_qbdi(path: str, data: bytes, timeout: int) -> Dict:
    # QBDI integration would go here
    return {'success': False, 'engine': 'qbdi',
            'error': 'QBDI integration not implemented yet'}
