"""JSON-RPC 2.0 agent channel — TCP/UDS transport, heartbeat keepalive, reconnection backoff."""
import json, logging, random, socket, ssl, struct, threading, time, abc, os as _os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple
from contextlib import suppress

_log = logging.getLogger(__name__)
HEADER_FMT, HEADER_SZ = "!I", struct.calcsize("!I")
DEFAULT_TO = 30.0; HB_INT = 15.0; RECON_DELAY = 3.0; MAX_RECON = 10; MAX_BACKOFF = 120.0

class AgentStatus(Enum): DISCONNECTED = auto(); CONNECTING = auto(); CONNECTED = auto(); SHUTDOWN = auto()
class AgentType(Enum): CLIENT = "client"; SERVER = "server"
@dataclass class AgentInfo: host: str; port: int; agent_type: AgentType; status: AgentStatus = AgentStatus.DISCONNECTED
@dataclass class Task: task_id: str; method: str; params: Dict[str, Any] = field(default_factory=dict)
@dataclass class TaskResult: task_id: str; success: bool; data: Any = None; error: str = ""

# ABC for transport layer
class _Transport(abc.ABC):
    @abc.abstractmethod
    def send(self, data: bytes) -> None: ...
    @abc.abstractmethod
    def recv(self, n: int, timeout: float) -> Optional[bytes]: ...
    @abc.abstractmethod
    def close(self) -> None: ...

class _TCPTransport(_Transport):
    def __init__(self, sock): self._sock = sock
    def send(self, data): self._sock.sendall(data)
    def recv(self, n, to): self._sock.settimeout(to); return self._sock.recv(n)
    def close(self): suppress(OSError)(self._sock.close())

def _pack(p: dict) -> bytes:
    body = json.dumps(p, ensure_ascii=False).encode("utf-8"); return struct.pack(HEADER_FMT, len(body)) + body

def _recv_msg(sock, to=DEFAULT_TO):
    sock.settimeout(to); buf = b""
    while len(buf) < HEADER_SZ:
        with suppress(socket.timeout):
            if not (c := sock.recv(HEADER_SZ - len(buf))): return None
            buf += c
    pl: int = struct.unpack(HEADER_FMT, buf)[0]
    if pl > 64 * 1024 * 1024: _log.warning("Oversized: %d bytes", pl); return None
    body = b""
    while len(body) < pl:
        with suppress(socket.timeout):
            if not (c := sock.recv(pl - len(body))): return None
            body += c
    with suppress(json.JSONDecodeError): return json.loads(body.decode("utf-8"))
    return None

class RemoteAgent:
    def __init__(self, host="127.0.0.1", port=9100, ssl_ctx=None, uds=None):
        self.host = host; self.port = port; self._ssl = ssl_ctx; self._uds = uds
        self._sock: Optional[socket.socket] = None; self._status = AgentStatus.DISCONNECTED
        self._lock = threading.Lock(); self._ctr = 0
        self._hbstop: Optional[threading.Event] = None; self._hbthr: Optional[threading.Thread] = None
        self._pending: Dict[str, Tuple[threading.Event, Optional[TaskResult]]] = {}
        self._rsthr: Optional[threading.Thread] = None; self._rsstop: Optional[threading.Event] = None

    def connect(self, host=None, port=None):
        if host: self.host = host
        if port: self.port = port
        self._status = AgentStatus.CONNECTING
        try:
            if self._uds:
                raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); raw.settimeout(5.0); raw.connect(self._uds); self._sock = raw
            else:
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM); raw.settimeout(5.0); raw.connect((self.host, self.port))
                self._sock = self._ssl.wrap_socket(raw, server_hostname=self.host) if self._ssl else raw
            self._status = AgentStatus.CONNECTED; _log.info("Connected to %s", self._uds or f"{self.host}:{self.port}")
            self._start_hb(); self._start_rs(); return True
        except (socket.error, OSError, ssl.SSLError) as e: _log.error("Connect failed: %s", e); self._status = AgentStatus.DISCONNECTED; return False

    def disconnect(self):
        self._stop_rs(); self._stop_hb()
        if self._sock:
            with suppress(OSError): self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close(); self._sock = None
        self._status = AgentStatus.DISCONNECTED
        if self._uds and _os.path.exists(self._uds): suppress(OSError)(_os.unlink(self._uds))

    def send_task(self, method, params=None, to=DEFAULT_TO):
        with self._lock: self._ctr += 1; tid = f"t-{self._ctr}"
        req = {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": tid}
        ev = threading.Event()
        with self._lock: self._pending[tid] = (ev, None)
        try: self._sock.sendall(_pack(req))
        except OSError as e: self._status = AgentStatus.DISCONNECTED; self._pending.pop(tid, None); return TaskResult(tid, False, error=str(e))
        if not ev.wait(to): self._pending.pop(tid, None); return TaskResult(tid, False, error="timeout")
        with self._lock: _, r = self._pending.pop(tid, (None, None))
        return r if r else TaskResult(tid, False, error="lost")

    def send_notification(self, method, params=None):
        try: self._sock.sendall(_pack({"jsonrpc": "2.0", "method": method, "params": params or {}})); return True
        except OSError: self._status = AgentStatus.DISCONNECTED; return False

    def _start_rs(self): self._rsstop = threading.Event(); self._rsthr = threading.Thread(target=self._rsloop, daemon=True); self._rsthr.start()
    def _stop_rs(self): self._rsstop and self._rsstop.set(); self._rsthr and self._rsthr.join(timeout=2.0); self._rsthr = None; self._rsstop = None
    def _rsloop(self):
        while not self._rsstop.wait(0.05):
            resp = None
            with suppress(OSError): resp = _recv_msg(self._sock, 1.0)
            if resp is None or (rid := resp.get("id")) is None: continue
            with self._lock: entry = self._pending.get(rid)
            if entry is None: continue
            ev, _ = entry; err = resp.get("error")
            r = TaskResult(rid, False, error=err.get("message", str(err))) if err else TaskResult(rid, True, data=resp.get("result"))
            with self._lock: self._pending[rid] = (ev, r); ev.set()

    def _start_hb(self): self._hbstop = threading.Event(); self._hbthr = threading.Thread(target=self._hbloop, daemon=True); self._hbthr.start()
    def _stop_hb(self): self._hbstop and self._hbstop.set(); self._hbthr and self._hbthr.join(timeout=2.0); self._hbthr = None; self._hbstop = None
    def _hbloop(self):
        while not self._hbstop.wait(HB_INT):
            try:
                self._sock.sendall(_pack({"jsonrpc": "2.0", "method": "ping", "id": None}))
                if _recv_msg(self._sock, 5.0) is None: _log.warning("HB timeout"); self._reconnect()
            except OSError: _log.warning("HB failed"); self._reconnect()

    def _reconnect(self):
        self.disconnect(); base = RECON_DELAY
        for a in range(1, MAX_RECON + 1):
            delay = min(base * (2 ** (a - 1)), MAX_BACKOFF) * (0.5 + 0.5 * random.random())
            _log.info("Reconnect %d/%d in %.1fs", a, MAX_RECON, delay); time.sleep(delay)
            if self.connect(): return
        _log.error("Reconnect exhausted")

    @property
    def connected(self): return self._status == AgentStatus.CONNECTED


class AgentServer:
    def __init__(self, host="0.0.0.0", port=9100, ssl_ctx=None, uds=None):
        self.host = host; self.port = port; self._ssl = ssl_ctx; self._uds = uds
        self._sock: Optional[socket.socket] = None; self._usock: Optional[socket.socket] = None
        self._handlers: Dict[str, Callable] = {}; self._running = False; self._clients: List[socket.socket] = []
        self._lock = threading.Lock(); self._rc: int = 0; self._ec: int = 0

    def register(self, m, h): self._handlers[m] = h
    def unregister(self, m): self._handlers.pop(m, None)

    def start(self):
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1); self._sock.bind((self.host, self.port)); self._sock.listen(5); self._sock.settimeout(1.0)
        _log.info("AgentServer %s:%d", self.host, self.port)
        if self._uds:
            if _os.path.exists(self._uds): _os.unlink(self._uds)
            self._usock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self._usock.bind(self._uds); self._usock.listen(5); self._usock.settimeout(1.0); _os.chmod(self._uds, 0o600)
            _log.info("UDS: %s", self._uds)
        while self._running:
            self._accept(self._sock, False)
            if self._usock: self._accept(self._usock, True)

    def _accept(self, sock, is_uds):
        try:
            client, addr = sock.accept(); lbl = addr if not is_uds else "uds"; _log.info("Client: %s", lbl)
            if self._ssl and not is_uds:
                try: client = self._ssl.wrap_socket(client, server_side=True)
                except ssl.SSLError: _log.warning("TLS fail %s", addr); client.close(); return
            with self._lock: self._clients.append(client)
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()
        except socket.timeout: pass
        except OSError as e:
            if self._running: _log.error("Accept: %s", e)

    def stop(self):
        self._running = False
        with self._lock:
            for c in self._clients: suppress(OSError)(c.close())
            self._clients.clear()
        for s in (self._sock, self._usock):
            if s: suppress(OSError)(s.close())
        self._sock = None; self._usock = None
        if self._uds and _os.path.exists(self._uds): suppress(OSError)(_os.unlink(self._uds))

    @property
    def stats(self): return {"requests": self._rc, "errors": self._ec}

    def _handle(self, client, addr):
        try:
            while self._running:
                if (req := _recv_msg(client)) is None: break
                self._rc += 1
                if resp := self._dispatch(req): client.sendall(_pack(resp))
        except OSError: pass
        finally:
            with self._lock:
                if client in self._clients: self._clients.remove(client)
            suppress(OSError)(client.close())

    def _dispatch(self, req):
        rid, method, params = req.get("id"), req.get("method", ""), req.get("params", {})
        if method == "ping": return {"jsonrpc": "2.0", "result": "pong", "id": rid}
        if (h := self._handlers.get(method)) is None:
            self._ec += 1
            return {"jsonrpc": "2.0", "error": {"code": -32601, "message": f"Not found: {method}"}, "id": rid} if rid is not None else None
        try: r = h(params); return {"jsonrpc": "2.0", "result": r, "id": rid} if rid is not None else None
        except Exception as e: self._ec += 1; _log.exception("Handler '%s'", method); return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": rid} if rid is not None else None

def create_agent(host="127.0.0.1", port=9100, ssl_ctx=None, uds=None): return RemoteAgent(host, port, ssl_ctx=ssl_ctx, uds=uds)
def create_server(host="0.0.0.0", port=9100, ssl_ctx=None, uds=None): return AgentServer(host, port, ssl_ctx=ssl_ctx, uds=uds)
def run_server(host="0.0.0.0", port=9100): AgentServer(host, port).start()
def run_agent():
    agent = RemoteAgent()
    if not agent.connect(): return
    try:
        import sys
        for line in sys.stdin:
            if not (line := line.strip()): continue
            with suppress(json.JSONDecodeError):
                t = json.loads(line); r = agent.send_task(t.get("method", "analyze"), t.get("params", {}))
                print(json.dumps({"task_id": r.task_id, "success": r.success, "data": r.data, "error": r.error}))
    finally: agent.disconnect()

import sys
