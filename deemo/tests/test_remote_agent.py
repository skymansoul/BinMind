import unittest
import os
import sys
import json
import uuid
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.remote_agent import (
    RemoteAgent, 
    AgentServer, 
    AgentType, 
    AgentStatus, 
    MessageType,
    AgentInfo,
    Task,
    TaskResult,
    Message,
    create_agent,
    create_server,
    run_agent,
    run_server
)


class TestAgentStatus(unittest.TestCase):
    """测试代理状态枚举"""
    
    def test_status_values(self):
        """测试状态枚举值"""
        self.assertEqual(AgentStatus.OFFLINE.value, 'offline')
        self.assertEqual(AgentStatus.ONLINE.value, 'online')
        self.assertEqual(AgentStatus.BUSY.value, 'busy')
        self.assertEqual(AgentStatus.ERROR.value, 'error')


class TestAgentType(unittest.TestCase):
    """测试代理类型枚举"""
    
    def test_type_values(self):
        """测试类型枚举值"""
        self.assertEqual(AgentType.SENSOR.value, 'sensor')
        self.assertEqual(AgentType.PROXY.value, 'proxy')
        self.assertEqual(AgentType.SCANNER.value, 'scanner')
        self.assertEqual(AgentType.COLLECTOR.value, 'collector')


class TestMessageType(unittest.TestCase):
    """测试消息类型枚举"""
    
    def test_message_type_values(self):
        """测试消息类型枚举值"""
        self.assertEqual(MessageType.PING.value, 'ping')
        self.assertEqual(MessageType.PONG.value, 'pong')
        self.assertEqual(MessageType.TASK_ASSIGN.value, 'task_assign')
        self.assertEqual(MessageType.TASK_RESULT.value, 'task_result')


class TestAgentInfo(unittest.TestCase):
    """测试代理信息数据类"""
    
    def test_agent_info_init(self):
        """测试代理信息初始化"""
        info = AgentInfo(
            agent_id='test_agent',
            agent_type=AgentType.SENSOR,
            status=AgentStatus.ONLINE,
            hostname='test-host',
            ip_address='192.168.1.1',
            os_type='linux',
            architecture='x86_64',
            capabilities=['binary_analysis'],
            tasks_completed=10,
            tasks_failed=2
        )
        
        self.assertEqual(info.agent_id, 'test_agent')
        self.assertEqual(info.agent_type, AgentType.SENSOR)
        self.assertEqual(info.status, AgentStatus.ONLINE)
        self.assertEqual(info.hostname, 'test-host')
        self.assertEqual(info.tasks_completed, 10)


class TestTask(unittest.TestCase):
    """测试任务数据类"""
    
    def test_task_init(self):
        """测试任务初始化"""
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            task_type='analysis',
            payload={'binary_path': '/path/to/binary'},
            priority=1,
            timeout=300
        )
        
        self.assertEqual(task.task_id, task_id)
        self.assertEqual(task.task_type, 'analysis')
        self.assertEqual(task.priority, 1)
        self.assertEqual(task.status, 'pending')


class TestRemoteAgent(unittest.TestCase):
    """测试远程代理类"""
    
    def setUp(self):
        """设置测试环境"""
        self.agent = RemoteAgent('test_agent', AgentType.SENSOR)
    
    def test_agent_init(self):
        """测试代理初始化"""
        self.assertEqual(self.agent.agent_id, 'test_agent')
        self.assertEqual(self.agent.agent_type, AgentType.SENSOR)
        self.assertEqual(self.agent.status, AgentStatus.OFFLINE)
        self.assertIsNotNone(self.agent.capabilities)
    
    def test_get_info(self):
        """测试获取代理信息"""
        info = self.agent.get_info()
        
        self.assertIsInstance(info, AgentInfo)
        self.assertEqual(info.agent_id, 'test_agent')
        self.assertEqual(info.agent_type, AgentType.SENSOR)
    
    def test_register_task_handler(self):
        """测试注册任务处理器"""
        def test_handler(payload):
            return {'success': True}
        
        self.agent.register_task_handler('test_task', test_handler)
        self.assertIn('test_task', self.agent._task_handlers)
    
    def test_connect_disconnect(self):
        """测试连接和断开连接"""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect.return_value = None
            result = self.agent.connect('localhost', 8888)
            self.assertTrue(result)
            self.assertEqual(self.agent.status, AgentStatus.ONLINE)
            
            self.agent.disconnect()
            self.assertEqual(self.agent.status, AgentStatus.OFFLINE)


class TestAgentServer(unittest.TestCase):
    """测试代理服务器类"""
    
    def setUp(self):
        """设置测试环境"""
        self.server = AgentServer('127.0.0.1', 9999)
    
    def test_server_init(self):
        """测试服务器初始化"""
        self.assertEqual(self.server.host, '127.0.0.1')
        self.assertEqual(self.server.port, 9999)
        self.assertEqual(len(self.server.agents), 0)
    
    def test_get_agents(self):
        """测试获取代理列表"""
        agents = self.server.get_agents()
        self.assertIsInstance(agents, list)
    
    def test_assign_task(self):
        """测试分配任务"""
        task = Task(task_id='test_task', task_type='analysis')
        result = self.server.assign_task(task)
        self.assertFalse(result)


class TestCreateAgent(unittest.TestCase):
    """测试创建代理函数"""
    
    def test_create_agent(self):
        """测试创建代理实例"""
        agent = create_agent('test_agent', 'sensor')
        
        self.assertIsInstance(agent, RemoteAgent)
        self.assertEqual(agent.agent_id, 'test_agent')
        self.assertEqual(agent.agent_type, AgentType.SENSOR)
    
    def test_create_agent_default_type(self):
        """测试使用默认类型创建代理"""
        agent = create_agent('test_agent')
        self.assertEqual(agent.agent_type, AgentType.SENSOR)


class TestCreateServer(unittest.TestCase):
    """测试创建服务器函数"""
    
    def test_create_server(self):
        """测试创建服务器实例"""
        server = create_server('0.0.0.0', 8888)
        
        self.assertIsInstance(server, AgentServer)
        self.assertEqual(server.host, '0.0.0.0')
        self.assertEqual(server.port, 8888)


if __name__ == '__main__':
    unittest.main()
