#!/usr/bin/env python3
import logging
import os
import json
import time
import threading
import traceback
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

_MAX_EVENTS = 10000
_MAX_TRACE_EVENTS = 200
_MAX_STACK_FRAMES = -3
_MAX_RETVAL = 200
_MAX_ARGS = 200
_MAX_TRACEBACK = 2000


@dataclass
class TraceEvent:
    timestamp: float
    event_type: str
    thread_id: int
    details: Dict[str, Any] = field(default_factory=dict)
    stack_trace: str = ""


@dataclass
class DiagnosticSession:
    session_id: str
    binary_path: str
    events: List[TraceEvent] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    exit_code: int = 0


class DiagnosticTracer:
    def __init__(self, binary_path=""):
        path = binary_path if binary_path is not None else ""
        self.binary_path = os.path.abspath(path) if path else ""
        self.events = deque(maxlen=_MAX_EVENTS)
        self._hooks = []
        self._running = False

    def trace_func_call(self, func_name, args=None):
        event_args = args if args is not None else {}
        stack = ""
        try:
            stack = traceback.format_stack()[_MAX_STACK_FRAMES].strip()
        except Exception:
            logger.debug("suppressed", exc_info=True)
        self.events.append(TraceEvent(
            timestamp=time.time(), event_type="func_call",
            thread_id=threading.get_ident(),
            details={'function': func_name, 'args': event_args},
            stack_trace=stack
        ))

    def trace_func_return(self, func_name, retval=None):
        ret = str(retval)[:_MAX_RETVAL] if retval is not None else "None"
        self.events.append(TraceEvent(
            timestamp=time.time(), event_type="func_return",
            thread_id=threading.get_ident(),
            details={'function': func_name, 'retval': ret}
        ))

    def trace_error(self, error, context=""):
        err = str(error) if error is not None else "unknown"
        err_type = type(error).__name__ if error is not None else "Unknown"
        ctx = context if context is not None else ""
        tb = ""
        try:
            tb = traceback.format_exc()[:_MAX_TRACEBACK]
        except Exception:
            logger.debug("suppressed", exc_info=True)
        self.events.append(TraceEvent(
            timestamp=time.time(), event_type="error",
            thread_id=threading.get_ident(),
            details={'error': err, 'type': err_type, 'context': ctx},
            stack_trace=tb
        ))

    def trace_syscall(self, syscall_name, args=None, result=0):
        name = syscall_name if syscall_name is not None else "unknown"
        args_str = str(args)[:_MAX_ARGS] if args is not None else "[]"
        self.events.append(TraceEvent(
            timestamp=time.time(), event_type="syscall",
            thread_id=threading.get_ident(),
            details={'syscall': name, 'args': args_str, 'result': result}
        ))

    def start_session(self):
        self._running = True
        session = DiagnosticSession(
            session_id=f"diag_{int(time.time())}",
            binary_path=self.binary_path,
            events=[], start_time=time.time()
        )
        return session

    def stop_session(self, session, exit_code=0):
        self._running = False
        session.end_time = time.time()
        session.exit_code = exit_code
        session.events = list(self.events)
        return session

    def generate_report(self, session):
        if session is None:
            return {'success': False, 'error': 'session is None'}
        events = session.events
        if events is None:
            events = []

        func_calls = 0
        errors = 0
        syscalls = 0

        for e in events:
            if e is None:
                continue
            if e.event_type == "func_call":
                func_calls += 1
            elif e.event_type == "error":
                errors += 1
            elif e.event_type == "syscall":
                syscalls += 1

        duration = session.end_time - session.start_time

        timeline = []
        event_limit = min(max(len(events), 0), 50)
        for j in range(event_limit):
            e = events[j]
            if e is not None:
                timeline.append({
                    'ts': round(e.timestamp - session.start_time, 4),
                    'type': e.event_type,
                    'details': e.details
                })

        return {
            'success': True, 'session_id': session.session_id,
            'duration_sec': round(duration, 3), 'total_events': len(events),
            'func_calls': func_calls, 'syscalls': syscalls, 'errors': errors,
            'timeline': timeline
        }

    def export_to_chrome_trace(self, session):
        if session is None:
            return "[]"
        events = session.events
        if events is None:
            events = []
        trace_events = []
        event_limit = min(max(len(events), 0), _MAX_TRACE_EVENTS)
        for i in range(event_limit):
            e = events[i]
            if e is None:
                continue
            name = e.event_type
            details = e.details if e.details is not None else {}
            func = details.get('function', details.get('syscall', '?'))
            trace_events.append({
                'name': f"{name}: {func}",
                'cat': name, 'ph': 'X',
                'ts': int((e.timestamp - session.start_time) * 1_000_000),
                'dur': 1000, 'pid': 1, 'tid': e.thread_id,
                'args': {str(k): str(v)[:100] for k, v in details.items()}
            })
        return json.dumps(trace_events, indent=2)


def create_diagnostic_tracer(binary_path=""):
    return DiagnosticTracer(binary_path)
