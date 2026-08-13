"""远程代理通道 —— 消息模型、任务分发与代理生命周期。

定义代理类型/状态/消息枚举，提供 RemoteAgent 与 AgentServer 的
基础实现，以及 create_agent / create_server 便捷工厂。
"""

import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class AgentStatus(Enum):
    """代理运行状态。"""
    OFFLINE = "offline"
    ONLINE = "online"
    BUSY = "busy"
    ERROR = "error"


class AgentType(Enum):
    """代理角色类型。"""
    SENSOR = "sensor"
    PROXY = "proxy"
    SCANNER = "scanner"
    COLLECTOR = "collector"


class MessageType(Enum):
    """代理间消息类型。"""
    PING = "ping"
    PONG = "pong"
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"


@dataclass
class Message:
    """代理间传输消息。"""
    msg_type: MessageType = MessageType.PING
    sender: str = ""
    recipient: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class AgentInfo:
    """代理注册信息。"""
    agent_id: str = ""
    agent_type: AgentType = AgentType.SENSOR
    status: AgentStatus = AgentStatus.OFFLINE
    hostname: str = ""
    ip_address: str = ""
    os_type: str = ""
    architecture: str = ""
    capabilities: List[str] = field(default_factory=list)
    tasks_completed: int = 0
    tasks_failed: int = 0


@dataclass
class Task:
    """可分发到代理的分析任务。"""
    task_id: str = ""
    task_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    timeout: int = 300
    status: str = "pending"


@dataclass
class TaskResult:
    """任务执行结果回执。"""
    task_id: str = ""
    success: bool = False
    data: Any = None
    error: str = ""


class RemoteAgent:
    """远程代理客户端 —— 连接管理、任务处理注册。"""

    def __init__(self, agent_id: str, agent_type: Any = AgentType.SENSOR):
        self.agent_id = agent_id
        if isinstance(agent_type, str):
            self.agent_type = AgentType(agent_type)
        else:
            self.agent_type = agent_type
        self.status = AgentStatus.OFFLINE
        self.capabilities: List[str] = []
        self._task_handlers: Dict[str, Callable] = {}
        self._socket: Optional[socket.socket] = None

    def get_info(self) -> AgentInfo:
        """返回当前代理信息快照。"""
        return AgentInfo(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            status=self.status,
            capabilities=list(self.capabilities),
        )

    def register_task_handler(self, task_type: str, handler: Callable) -> None:
        """注册指定任务类型的处理函数。"""
        self._task_handlers[task_type] = handler

    def connect(self, host: str, port: int) -> bool:
        """建立到控制端的连接。"""
        try:
            sock = socket.socket()
            sock.connect((host, port))
            self._socket = sock
            self.status = AgentStatus.ONLINE
            return True
        except OSError:
            self.status = AgentStatus.ERROR
            return False

    def disconnect(self) -> None:
        """断开连接并复位状态。"""
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self.status = AgentStatus.OFFLINE


class AgentServer:
    """代理注册与任务分配服务器。"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.agents: List[RemoteAgent] = []

    def get_agents(self) -> List[RemoteAgent]:
        """返回已注册代理列表。"""
        return list(self.agents)

    def assign_task(self, task: Task) -> bool:
        """向在线代理分配任务; 无可用代理时返回 False。"""
        online = [a for a in self.agents if a.status == AgentStatus.ONLINE]
        if not online:
            return False
        task.status = 'assigned'
        return True


def create_agent(agent_id: str, agent_type: Any = 'sensor') -> RemoteAgent:
    """便捷入口: 创建代理实例。"""
    return RemoteAgent(agent_id, agent_type)


def create_server(host: str, port: int) -> AgentServer:
    """便捷入口: 创建代理服务器。"""
    return AgentServer(host, port)


def run_agent(agent_id: str, host: str, port: int) -> RemoteAgent:
    """便捷入口: 创建并连接代理。"""
    agent = RemoteAgent(agent_id, AgentType.SENSOR)
    agent.connect(host, port)
    return agent


def run_server(host: str, port: int) -> AgentServer:
    """便捷入口: 创建代理服务器。"""
    return AgentServer(host, port)
