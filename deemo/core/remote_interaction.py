"""远程交互管理器 — 纯 Python socket 实现，无 pwntools 依赖。

提供 TCP 连接目标、发送/接收载荷、交互式通信能力。
替代 pwntools remote() 的最小功能集，供 exploit 执行与 PoC 验证使用。
设计参考: pwntools tube 接口、pwntools remote() 行为。
"""

import logging
import socket
import time
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# 默认超时（秒）
_DEFAULT_TIMEOUT = 10.0
# 接收缓冲区大小
_RECV_BUF = 4096


class RemoteInteraction:
    """TCP 远程交互管理器 — 连接目标后支持 send/recv/interactive 操作。

    用法:
        ri = RemoteInteraction('127.0.0.1', 1337)
        ri.connect()
        ri.send(b'A' * 1000)
        data = ri.recv(timeout=5)
        ri.close()

    不依赖 pwntools，仅用标准库 socket。
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 1337,
                 timeout: float = _DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._connected = False
        # 累计接收缓冲，支持 recvline 语义
        self._buf = b''

    def connect(self) -> bool:
        """建立 TCP 连接，成功返回 True。"""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            self._connected = True
            _log.info("RemoteInteraction connected to %s:%d", self.host, self.port)
            return True
        except (socket.error, OSError) as e:
            _log.error("RemoteInteraction connect failed %s:%d: %s",
                        self.host, self.port, e)
            self._connected = False
            self._sock = None
            return False

    def send(self, data: bytes) -> int:
        """发送数据，返回已发送字节数；未连接时返回 0。"""
        if not self._connected or self._sock is None:
            _log.warning("RemoteInteraction: send before connect")
            return 0
        try:
            self._sock.sendall(data)
            return len(data)
        except (socket.error, OSError) as e:
            _log.error("RemoteInteraction send error: %s", e)
            self._connected = False
            return 0

    def sendline(self, data: bytes) -> int:
        """发送数据并追加换行符。"""
        return self.send(data + b'\n')

    def recv(self, size: int = _RECV_BUF,
             timeout: Optional[float] = None) -> bytes:
        """接收最多 size 字节数据；先消费缓冲区。

        timeout=None 时使用实例默认超时。
        超时或断连时返回已缓冲的数据（可能为空）。
        """
        if not self._connected or self._sock is None:
            return self._buf[:size]

        # 先消费已缓冲的数据
        if self._buf:
            chunk = self._buf[:size]
            self._buf = self._buf[size:]
            if len(chunk) >= size:
                return chunk

        eff_timeout = timeout if timeout is not None else self.timeout
        self._sock.settimeout(eff_timeout)
        remaining = size - len(chunk) if self._buf else size

        try:
            data = self._sock.recv(remaining)
            if not data:
                # 对端关闭连接
                self._connected = False
                _log.debug("RemoteInteraction: peer closed connection")
            return chunk + data
        except socket.timeout:
            _log.debug("RemoteInteraction recv timeout after %.1fs", eff_timeout)
            return chunk
        except (socket.error, OSError) as e:
            _log.error("RemoteInteraction recv error: %s", e)
            self._connected = False
            return chunk

    def recvline(self, timeout: Optional[float] = None) -> bytes:
        """接收一行（以 \\n 结尾）；缓冲未命中时阻塞等待。

        返回含换行符的行，超时返回已缓冲内容。
        """
        if not self._connected or self._sock is None:
            return self._buf

        eff_timeout = timeout if timeout is not None else self.timeout

        # 检查缓冲区中是否已有换行符
        idx = self._buf.find(b'\n')
        while idx < 0:
            self._sock.settimeout(eff_timeout)
            try:
                data = self._sock.recv(_RECV_BUF)
                if not data:
                    # 对端关闭，返回已缓冲内容
                    line, self._buf = self._buf, b''
                    return line
                self._buf += data
                idx = self._buf.find(b'\n')
            except socket.timeout:
                # 超时返回已缓冲内容
                line, self._buf = self._buf, b''
                return line
            except (socket.error, OSError) as e:
                _log.error("RemoteInteraction recvline error: %s", e)
                self._connected = False
                line, self._buf = self._buf, b''
                return line

        line = self._buf[:idx + 1]
        self._buf = self._buf[idx + 1:]
        return line

    def recvuntil(self, marker: bytes,
                  timeout: Optional[float] = None) -> bytes:
        """接收直到遇到 marker 为止；超时返回已缓冲内容。"""
        if not self._connected or self._sock is None:
            return self._buf

        eff_timeout = timeout if timeout is not None else self.timeout
        idx = self._buf.find(marker)
        while idx < 0:
            self._sock.settimeout(eff_timeout)
            try:
                data = self._sock.recv(_RECV_BUF)
                if not data:
                    result, self._buf = self._buf, b''
                    return result
                self._buf += data
                idx = self._buf.find(marker)
            except socket.timeout:
                result, self._buf = self._buf, b''
                return result
            except (socket.error, OSError) as e:
                _log.error("RemoteInteraction recvuntil error: %s", e)
                self._connected = False
                result, self._buf = self._buf, b''
                return result

        end = idx + len(marker)
        result = self._buf[:end]
        self._buf = self._buf[end:]
        return result

    def interactive(self, duration: float = 30.0) -> bytes:
        """被动接收模式 — 在 duration 秒内持续接收数据并返回。

        用于 CTF flag 读取或 shell 交互确认。
        """
        if not self._connected or self._sock is None:
            return b''

        collected = b''
        deadline = time.time() + duration
        while time.time() < deadline:
            self._sock.settimeout(1.0)
            try:
                data = self._sock.recv(_RECV_BUF)
                if not data:
                    break
                collected += data
            except socket.timeout:
                continue
            except (socket.error, OSError):
                break
        return collected

    def close(self) -> None:
        """关闭连接并释放资源。"""
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError):
                pass
            try:
                self._sock.close()
            except (socket.error, OSError):
                pass
            self._sock = None
        self._connected = False
        self._buf = b''
        _log.debug("RemoteInteraction closed")

    @property
    def connected(self) -> bool:
        return self._connected

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def probe_remote_target(host: str, port: int,
                        timeout: float = 3.0) -> Dict[str, Any]:
    """探测远程目标可达性 — 返回 {reachable, latency_ms, error}。

    供 pipeline 启动时判断远程交互目标是否可用。
    """
    result = {'reachable': False, 'latency_ms': 0, 'error': ''}
    t0 = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        result['reachable'] = True
        result['latency_ms'] = round((time.time() - t0) * 1000, 1)
    except (socket.error, OSError) as e:
        result['error'] = str(e)
    return result


def execute_remote_payload(host: str, port: int, payload: bytes,
                           timeout: float = 10.0) -> Dict[str, Any]:
    """向远程目标发送载荷并收集响应 — 一次性交互。

    返回 {success, response_data, error}。
    供 pipeline PoC 执行路径调用，替代本地 subprocess 执行。
    """
    result = {'success': False, 'response_data': b'', 'error': ''}
    ri = RemoteInteraction(host, port, timeout=timeout)
    if not ri.connect():
        result['error'] = f'connect failed: {ri.host}:{ri.port}'
        return result
    try:
        ri.send(payload)
        # 等待短暂时间收集响应
        response = ri.interactive(duration=timeout)
        result['success'] = True
        result['response_data'] = response
    except Exception as e:
        result['error'] = str(e)
    finally:
        ri.close()
    return result
