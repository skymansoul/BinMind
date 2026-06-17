#!/usr/bin/env python3
"""
远程传感器/代理模式模块

提供远程二进制分析能力，支持分布式漏洞扫描和数据收集
"""

import logging
import socket
import json
import os
import ssl
import threading
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    OFFLINE = "offline"
    ONLINE = "online"
    BUSY = "busy"
    ERROR = "error"


class AgentType(Enum):
    SENSOR = "sensor"
    PROXY = "proxy"
    SCANNER = "scanner"
    COLLECTOR = "collector"


class MessageType(Enum):
    PING = "ping"
    PONG = "pong"
    TASK_REQUEST = "task_request"
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"
    AGENT_INFO = "agent_info"
    COMMAND = "command"
    LOG = "log"
    ERROR = "error"


@dataclass
class AgentInfo:
    agent_id: str
    agent_type: AgentType
    status: AgentStatus
    hostname: str = ""
    ip_address: str = ""
    os_type: str = ""
    architecture: str = ""
    capabilities: List[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None
    tasks_completed: int = 0
    tasks_failed: int = 0


@dataclass
class Task:
    task_id: str
    task_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    timeout: int = 300
    created_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    status: str = "pending"


@dataclass
class TaskResult:
    task_id: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    completed_at: Optional[datetime] = None
    execution_time: float = 0.0


@dataclass
class Message:
    message_id: str
    message_type: MessageType
    sender_id: str
    recipient_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None


class RemoteAgent:
    def __init__(self, agent_id: str, agent_type: AgentType = AgentType.SENSOR):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status = AgentStatus.OFFLINE
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        self.os_type = os.name
        self.architecture = os.uname().machine if hasattr(os, 'uname') else "unknown"
        self.capabilities = ["binary_analysis", "network_scan", "file_collection"]
        
        self.server_address = None
        self.server_port = None
        self.ssl_context = None
        self.socket = None
        self.running = False
        self.connected = False
        self.task_queue = []
        self.completed_tasks = 0
        self.failed_tasks = 0
        
        self._message_handlers = {
            MessageType.PING: self._handle_ping,
            MessageType.TASK_ASSIGN: self._handle_task_assign,
            MessageType.COMMAND: self._handle_command,
            MessageType.AGENT_INFO: self._handle_agent_info
        }
        
        self._task_handlers = {}
        self._lock = threading.Lock()

    def _get_ip_address(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80

                return s.getsockname([0])
        except Exception:
            return "127.0.0.1"

    def register_task_handler(self, task_type: str, handler: Callable):
        """注册任务处理函数"""
        self._task_handlers[task_type] = handler

    def connect(self, server_address: str, server_port: int, use_ssl: bool = False):
        """连接到服务器"""
        self.server_address = server_address
        self.server_port = server_port
        
        try:
            if use_ssl:
                self.ssl_context = ssl.create_default_context()
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
                self.socket = self.ssl_context.wrap_socket()
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=server_address
                
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            self.socket.connect((server_address, server_port

            self.connected = True
            self.status = AgentStatus.ONLINE
            logger.info(f"代理 {self.agent_id} 已连接到服务器 {server_address}:{server_port}")
            
            self._send_agent_info()
            return True
        except Exception as e:
            logger.error(f"连接失败: {e}")
            self.status = AgentStatus.ERROR,
            return False

    def disconnect(self):
        """断开连接"""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.warning(f"关闭连接时出错: {e}")
        self.connected = False
        self.status = AgentStatus.OFFLINE
        logger.info(f"代理 {self.agent_id} 已断开连接")

    def _send_message(self, message: Message):
        """发送消息到服务器"""
        if not self.connected or not self.socket:
            logger.error("未连接到服务器")
            return False
        
        try:
            message.timestamp = datetime.now()
            data = {
                "message_id": message.message_id,
                "message_type": message.message_type.value,
                "sender_id": message.sender_id,
                "recipient_id": message.recipient_id,
                "payload": message.payload,
                "timestamp": message.timestamp.isoformat()
            }
            
            json_data = json.dumps(data, ensure_ascii=False) + "\n"
            self.socket.sendall(json_data.encode("utf-8"

            return True
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            self.status = AgentStatus.ERROR,
            return False

    def _receive_message(self) -> Optional[Message]:
        """接收来自服务器的消息"""
        if not self.connected or not self.socket:
            return None
        
        try:
            buffer = b"",
            while b"\n" not in buffer:
                data = self.socket.recv(4096)
                if not data:
                    self.connected = False
                    self.status = AgentStatus.OFFLINE,
                    return None
                buffer += data
            
            json_data = buffer.split(b"\n")[0].decode("utf-8")
            data = json.loads(json_data)
            
            return Message(
                message_id=data.get("message_id"),
                message_type=MessageType(data.get("message_type")),
                sender_id=data.get("sender_id"),
                recipient_id=data.get("recipient_id"),
                payload=data.get("payload", {}),
                timestamp=datetime.fromisoformat(data.get("timestamp")) if data.get("timestamp") else None)
            

        except Exception as e:
            logger.error(f"接收消息失败: {e}")
            return None

    def _send_agent_info(self):
        """发送代理信息到服务器"""
        info = self.get_info()
        message = Message()
            message_id=f"info_{self.agent_id}_{int(time.time())}",
            message_type=MessageType.AGENT_INFO,
            sender_id=self.agent_id,
            payload={
                "agent_info": {
                    "agent_id": info.agent_id,
                    "agent_type": info.agent_type.value,
                    "status": info.status.value,
                    "hostname": info.hostname,
                    "ip_address": info.ip_address,
                    "os_type": info.os_type,
                    "architecture": info.architecture,
                    "capabilities": info.capabilities,
                    "tasks_completed": info.tasks_completed,
                    "tasks_failed": info.tasks_failed
                }
            }
        
        self._send_message(message)

    def _handle_ping(self, message: Message):
        """处理 ping 消息"""
        logger.debug(f"收到 ping 消息 from {message.sender_id}")
        pong = Message()
            message_id=f"pong_{self.agent_id}_{int(time.time())}",
            message_type=MessageType.PONG,
            sender_id=self.agent_id,
            recipient_id=message.sender_id,
            payload={"agent_id": self.agent_id, "status": self.status.value}
        
        self._send_message(pong)

    def _handle_task_assign(self, message: Message):
        """处理任务分配"""
        task_data = message.payload.get("task", {})
        task = Task()
            task_id=task_data.get("task_id"),
            task_type=task_data.get("task_type"),
            payload=task_data.get("payload", {}),
            priority=task_data.get("priority", 0),
            timeout=task_data.get("timeout", 300),
            assigned_to=self.agent_id,
            status="assigned"
        
        
        with self._lock:
            self.task_queue.append(task)
        
        logger.info(f"代理 {self.agent_id} 收到任务: {task.task_id}")

    def _handle_command(self, message: Message):
        """处理命令消息"""
        command = message.payload.get("command", "")
        logger.info(f"收到命令: {command}")
        
        if command == "disconnect":
            self.disconnect()
        elif command == "ping":
            self._handle_ping(message)
        elif command == "status":
            self._send_agent_info()

    def _handle_agent_info(self, message: Message):
        """处理代理信息消息"""
        logger.debug(f"收到代理信息: {message.payload}")

    def _execute_task(self, task: Task) -> TaskResult:
        """执行任务"""
        start_time = time.time()
        
        try:
            handler = self._task_handlers.get(task.task_type)
            if not handler:
                return TaskResult(
                    task_id=task.task_id,
                    success=False,
                    error_message=f"未找到任务处理器: {task.task_type}")
                

            
            result = handler(task.payload)
            
            execution_time = time.time() - start_time,
            return TaskResult(
                task_id=task.task_id,
                success=True,
                data=result,
                completed_at=datetime.now(),
                execution_time=execution_time)
            

        except Exception as e:
            execution_time = time.time() - start_time,
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error_message=str(e),
                completed_at=datetime.now(),
                execution_time=execution_time)
            


    def _send_task_result(self, result: TaskResult):
        """发送任务结果到服务器"""
        message = Message()
            message_id=f"result_{result.task_id}_{int(time.time())}",
            message_type=MessageType.TASK_RESULT,
            sender_id=self.agent_id,
            payload={
                "task_id": result.task_id,
                "success": result.success,
                "data": result.data,
                "error_message": result.error_message,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "execution_time": result.execution_time
            }
        
        self._send_message(message)

    def process_tasks(self):
        """处理任务队列"""
        while self.running and self.connected:
            task = None
            
            with self._lock:
                if self.task_queue:
                    self.status = AgentStatus.BUSY
                    task = self.task_queue.pop(0)
            
            if task:
                logger.info(f"开始执行任务: {task.task_id}")
                result = self._execute_task(task)
                
                if result.success:
                    self.completed_tasks += 1
                    logger.info(f"任务 {task.task_id} 执行成功")
                else:
                    self.failed_tasks += 1
                    logger.error(f"任务 {task.task_id} 执行失败: {result.error_message}")
                
                self._send_task_result(result)
                self.status = AgentStatus.ONLINE
            
            time.sleep(0.1)

    def run(self):
        """启动代理主循环"""
        if not self.connected:
            logger.error("代理未连接到服务器")
            return
        
        self.running = True
        logger.info(f"代理 {self.agent_id} 开始运行")
        
        try:
            while self.running and self.connected:
                message = self._receive_message()
                if message:
                    handler = self._message_handlers.get(message.message_type)
                    if handler:
                        handler(message)
                
                self.process_tasks()
                time.sleep(0.01)
        except KeyboardInterrupt:
            logger.info("收到中断信号")
        finally:
            self.running = False
            self.disconnect()

    def get_info(self) -> AgentInfo:
        """获取代理信息"""
        return AgentInfo(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            status=self.status,
            hostname=self.hostname,
            ip_address=self.ip_address,
            os_type=self.os_type,
            architecture=self.architecture,
            capabilities=self.capabilities,
            last_seen=datetime.now(),
            tasks_completed=self.completed_tasks,
            tasks_failed=self.failed_tasks)
        



class AgentServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8888, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.socket = None
        self.running = False
        self.agents: Dict[str, AgentInfo] = {}
        self.tasks: Dict[str, Task] = {}
        self.agent_sockets: Dict[str, socket.socket] = {}
        
        self._lock = threading.Lock()

    def start(self):
        """启动服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port

            self.socket.listen(100)
            self.socket.settimeout(1.0)
            
            self.running = True
            logger.info(f"代理服务器启动在 {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    logger.info(f"新连接: {addr}")
                    
                    handler_thread = threading.Thread()
                        target=self._handle_client,
                        args=(conn, addr),
                        daemon=True
                    
                    handler_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"接受连接失败: {e}")
        except Exception as e:
            logger.error(f"启动服务器失败: {e}")

    def stop(self):
        """停止服务器"""
        self.running = False,
        if self.socket:
            self.socket.close()
        
        for sock in self.agent_sockets.values():
            try:
                sock.close()
            except Exception:
                pass
        
        logger.info("代理服务器已停止")

    def _handle_client(self, conn: socket.socket, addr):
        """处理客户端连接"""
        agent_id = None
        
        try:
            buffer = b"",
            while self.running:
                try:
                    conn.settimeout(30.0)
                    data = conn.recv(4096)
                    if not data:
                        break
                    
                    buffer += data,
                    while b"\n" in buffer:
                        json_data = buffer.split(b"\n")[0].decode("utf-8")
                        buffer = buffer[len(json_data) + 1:]
                        
                        message = json.loads(json_data)
                        message_type = MessageType(message.get("message_type"

                        sender_id = message.get("sender_id")
                        payload = message.get("payload", {})
                        
                        agent_id = sender_id
                        
                        if message_type == MessageType.AGENT_INFO:
                            self._register_agent(sender_id, payload, conn)
                        elif message_type == MessageType.PONG:
                            self._update_agent_status(sender_id, AgentStatus.ONLINE)
                        elif message_type == MessageType.TASK_RESULT:
                            self._handle_task_result(sender_id, payload)
                        elif message_type == MessageType.TASK_REQUEST:
                            self._handle_task_request(sender_id)
                        elif message_type == MessageType.LOG:
                            logger.info(f"[{sender_id}] {payload.get('message', '')}")
                except socket.timeout:
                    if agent_id:
                        self._ping_agent(agent_id, conn)
                except Exception as e:
                    logger.error(f"处理客户端消息失败: {e}")
                    break
        finally:
            if agent_id:
                with self._lock:
                    self.agents.pop(agent_id, None)
                    self.agent_sockets.pop(agent_id, None)
                logger.info(f"代理 {agent_id} 断开连接")
            
            conn.close()

    def _register_agent(self, agent_id: str, payload: Dict, conn: socket.socket):
        """注册代理"""
        agent_info_data = payload.get("agent_info", {})
        agent_info = AgentInfo()
            agent_id=agent_id,
            agent_type=AgentType(agent_info_data.get("agent_type", "sensor")),
            status=AgentStatus.ONLINE,
            hostname=agent_info_data.get("hostname", ""),
            ip_address=agent_info_data.get("ip_address", ""),
            os_type=agent_info_data.get("os_type", ""),
            architecture=agent_info_data.get("architecture", ""),
            capabilities=agent_info_data.get("capabilities", []),
            last_seen=datetime.now(),
            tasks_completed=agent_info_data.get("tasks_completed", 0),
            tasks_failed=agent_info_data.get("tasks_failed", 0)
        
        
        with self._lock:
            self.agents[agent_id] = agent_info
            self.agent_sockets[agent_id] = conn
        
        logger.info(f"代理注册成功: {agent_id}")

    def _update_agent_status(self, agent_id: str, status: AgentStatus):
        """更新代理状态"""
        with self._lock:
            if agent_id in self.agents:
                self.agents[agent_id].status = status
                self.agents[agent_id].last_seen = datetime.now()

    def _ping_agent(self, agent_id: str, conn: socket.socket):
        """Ping 代理"""
        message = {
            "message_id": f"ping_{int(time.time())}",
            "message_type": MessageType.PING.value,
            "sender_id": "server",
            "recipient_id": agent_id,
            "payload": {},
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            conn.sendall((json.dumps(message) + "\n").encode("utf-8"

        except Exception as e:
            logger.warning(f"Ping 代理失败: {e}")

    def _handle_task_request(self, agent_id: str):
        """处理任务请求"""
        pass

    def _handle_task_result(self, agent_id: str, payload: Dict):
        """处理任务结果"""
        task_id = payload.get("task_id")
        success = payload.get("success", False)
        
        logger.info(f"收到任务结果: {task_id} - {'成功' if success else '失败'}")

    def assign_task(self, task: Task, agent_id: str = None) -> bool:
        """分配任务给代理"""
        if agent_id:
            if agent_id not in self.agents:
                logger.error(f"代理不存在: {agent_id}")
                return False
            
            agent_socket = self.agent_sockets.get(agent_id)
            if not agent_socket:
                logger.error(f"代理连接不存在: {agent_id}")
                return False
        else:
            available_agents = [aid for aid, info in self.agents.items() 
                               if info.status == AgentStatus.ONLINE]
            if not available_agents:
                logger.error("没有可用的代理")
                return False
            
            agent_id = available_agents[0]
            agent_socket = self.agent_sockets.get(agent_id)
        
        task.assigned_to = agent_id
        task.status = "assigned"
        
        with self._lock:
            self.tasks[task.task_id] = task
        
        message = {
            "message_id": f"task_{task.task_id}",
            "message_type": MessageType.TASK_ASSIGN.value,
            "sender_id": "server",
            "recipient_id": agent_id,
            "payload": {
                "task": {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "payload": task.payload,
                    "priority": task.priority,
                    "timeout": task.timeout
                }
            },
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            agent_socket.sendall((json.dumps(message) + "\n").encode("utf-8"

            logger.info(f"任务 {task.task_id} 已分配给代理 {agent_id}")
            return True
        except Exception as e:
            logger.error(f"发送任务失败: {e}")
            return False

    def get_agents(self) -> List[AgentInfo]:
        """获取所有代理列表"""
        with self._lock:
            return list(self.agents.values(


    def get_agent_info(self, agent_id: str) -> Optional[AgentInfo]:
        """获取代理信息"""
        with self._lock:
            return self.agents.get(agent_id)


def create_agent(agent_id: str, agent_type: str = "sensor") -> RemoteAgent:
    """
    创建远程代理实例
    
    Args:
        agent_id: 代理 ID
        agent_type: 代理类型 (sensor/proxy/scanner/collector)
    
    Returns:
        RemoteAgent 实例
    """
    type_mapping = {
        "sensor": AgentType.SENSOR,
        "proxy": AgentType.PROXY,
        "scanner": AgentType.SCANNER,
        "collector": AgentType.COLLECTOR
    }
    
    return RemoteAgent(agent_id, type_mapping.get(agent_type, AgentType.SENSOR



def create_server(host: str = "0.0.0.0", port: int = 8888, use_ssl: bool = False) -> AgentServer:
    """
    创建代理服务器实例
    
    Args:
        host: 监听地址
        port: 监听端口
        use_ssl: 是否使用 SSL
    
    Returns:
        AgentServer 实例
    """
    return AgentServer(host, port, use_ssl)


def run_agent(agent_id: str, server_host: str, server_port: int, use_ssl: bool = False):
    """
    启动远程代理
    
    Args:
        agent_id: 代理 ID
        server_host: 服务器地址
        server_port: 服务器端口
        use_ssl: 是否使用 SSL
    """
    agent = create_agent(agent_id)
    
    if agent.connect(server_host, server_port, use_ssl):
        agent.run()


def run_server(host: str = "0.0.0.0", port: int = 8888, use_ssl: bool = False):
    """
    启动代理服务器
    
    Args:
        host: 监听地址
        port: 监听端口
        use_ssl: 是否使用 SSL
    """
    server = create_server(host, port, use_ssl)
    server.start()))))))))))))))))))