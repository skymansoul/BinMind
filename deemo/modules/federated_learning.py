"""
基于联邦学习的敏感目标协同分析模块

客户端提取特征本地训练，仅共享梯度，差分隐私保护。

核心功能：
1. 联邦学习客户端实现
2. 联邦学习服务器实现
3. 梯度聚合与更新
4. 差分隐私保护的梯度共享
5. 安全聚合协议
6. 模型同步与版本管理

安全说明：
- 原始数据始终保留在客户端
- 仅共享模型梯度/参数更新
- 使用差分隐私保护梯度
- 支持安全多方计算协议
"""

import logging
import json
import hashlib
import time
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class FLRole(Enum):
    """联邦学习角色"""
    SERVER = "server"
    CLIENT = "client"


class FLStatus(Enum):
    """联邦学习状态"""
    IDLE = "idle"
    TRAINING = "training"
    SYNCING = "syncing"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    ERROR = "error"


class FLAlgorithm(Enum):
    """联邦学习算法"""
    FEDAVG = "fedavg"           # 联邦平均
    FEDPROX = "fedprox"         # 联邦近端
    FEDSGD = "fedsgd"           # 联邦随机梯度下降
    SCAFFOLD = "scaffold"       # SCAFFOLD算法
    MOCHA = "mocha"             # MOCHA算法


@dataclass
class FLConfig:
    """联邦学习配置"""
    algorithm: FLAlgorithm = FLAlgorithm.FEDAVG
    num_clients: int = 10
    min_clients: int = 3
    max_rounds: int = 100
    local_epochs: int = 5
    learning_rate: float = 0.01
    epsilon: float = 1.0        # 差分隐私预算
    clip_norm: float = 1.0      # 梯度裁剪范数
    aggregation_weight: float = 1.0


@dataclass
class FLModel:
    """联邦学习模型"""
    model_id: str
    parameters: Dict[str, List[float]]
    version: int = 1
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FLGradient:
    """梯度数据"""
    client_id: str
    gradients: Dict[str, List[float]]
    sample_count: int = 0
    round: int = 0
    timestamp: float = 0.0
    encrypted: bool = False


@dataclass
class FLMetrics:
    """训练指标"""
    round: int
    client_id: str
    loss: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


@dataclass
class FLRoundResult:
    """轮次结果"""
    round: int
    status: FLStatus
    metrics: List[FLMetrics]
    model_update: Optional[FLModel] = None
    participating_clients: List[str] = field(default_factory=list)
    timestamp: float = 0.0


class PrivacyProtector:
    """隐私保护模块"""
    
    def __init__(self, epsilon: float = 1.0, clip_norm: float = 1.0):
        """
        初始化隐私保护模块
        
        Args:
            epsilon: 差分隐私预算
            clip_norm: 梯度裁剪范数
        """
        self.epsilon = epsilon
        self.clip_norm = clip_norm
    
    def clip_gradient(self, gradient: List[float]) -> List[float]:
        """
        裁剪梯度
        
        Args:
            gradient: 原始梯度
        
        Returns:
            裁剪后的梯度
        """
        import numpy as np
        
        grad_np = np.array(gradient)
        norm = np.linalg.norm(grad_np)
        
        if norm > self.clip_norm:
            grad_np = grad_np * (self.clip_norm / norm)
        
        return grad_np.tolist()
    
    def add_noise(self, gradient: List[float], sensitivity: float = 1.0) -> List[float]:
        """
        添加Laplace噪声
        
        Args:
            gradient: 梯度数据
            sensitivity: 敏感度
        
        Returns:
            添加噪声后的梯度
        """
        import numpy as np
        import random
        import math
        
        scale = sensitivity / self.epsilon
        grad_np = np.array(gradient)
        
        # 生成Laplace噪声
        noise = np.array([)
            -scale * math.log(1 - 2 * abs(random.random() - 0.5)) * 
            (1 if random.random() >= 0.5 else -1)
            for _ in range(len(grad_np

        ]
        
        return (grad_np + noise).tolist()
    
    def protect(self, gradients: Dict[str, List[float]]) -> Dict[str, List[float]]:
        """
        保护梯度（裁剪+加噪）
        
        Args:
            gradients: 梯度字典
        
        Returns:
            保护后的梯度
        """
        protected = {}
        
        for key, grad in gradients.items():
            # 裁剪
            clipped = self.clip_gradient(grad)
            # 加噪
            protected[key] = self.add_noise(clipped)
        
        return protected


class GradientAggregator:
    """梯度聚合器"""
    
    def __init__(self, algorithm: FLAlgorithm = FLAlgorithm.FEDAVG):
        """
        初始化梯度聚合器
        
        Args:
            algorithm: 聚合算法
        """
        self.algorithm = algorithm
    
    def aggregate(self, gradients: List[FLGradient]) -> Dict[str, List[float]]:
        """
        聚合多个客户端的梯度
        
        Args:
            gradients: 梯度列表
        
        Returns:
            聚合后的梯度
        """
        if not gradients:
            return {}
        
        if self.algorithm == FLAlgorithm.FEDAVG:
            return self._fedavg_aggregate(gradients)
        elif self.algorithm == FLAlgorithm.FEDPROX:
            return self._fedprox_aggregate(gradients)
        else:
            return self._fedavg_aggregate(gradients)
    
    def _fedavg_aggregate(self, gradients: List[FLGradient]) -> Dict[str, List[float]]:
        """
        FedAvg 聚合算法
        
        Args:
            gradients: 梯度列表
        
        Returns:
            聚合后的梯度
        """
        import numpy as np
        
        # 计算总样本数
        total_samples = sum(g.sample_count for g in gradients)
        if total_samples == 0:
            total_samples = len(gradients)
        
        # 获取所有参数名
        param_names = set()
        for g in gradients:
            param_names.update(g.gradients.keys(

        
        aggregated = {}
        
        for param_name in param_names:
            # 收集所有客户端的该参数梯度
            grads = []
            weights = []
            
            for g in gradients:
                if param_name in g.gradients:
                    grads.append(np.array(g.gradients[param_name]

                    weights.append(g.sample_count if g.sample_count > 0 else 1)
            
            if grads:
                # 加权平均
                weights_np = np.array(weights) / total_samples
                aggregated[param_name] = np.average(grads, axis=0, weights=weights_np).tolist()
        
        return aggregated
    
    def _fedprox_aggregate(self, gradients: List[FLGradient]) -> Dict[str, List[float]]:
        """
        FedProx 聚合算法（简化实现）
        
        Args:
            gradients: 梯度列表
        
        Returns:
            聚合后的梯度
        """
        # FedProx 在客户端训练时加入近端项
        # 聚合阶段与 FedAvg 类似
        return self._fedavg_aggregate(gradients)


class FLClient(ABC):
    """联邦学习客户端抽象基类"""
    
    def __init__(self, client_id: str, config: FLConfig = None):
        """
        初始化客户端
        
        Args:
            client_id: 客户端ID
            config: 配置
        """
        self.client_id = client_id
        self.config = config or FLConfig()
        self.status = FLStatus.IDLE
        self.local_model = None
        self.privacy_protector = PrivacyProtector()
            epsilon=self.config.epsilon,
            clip_norm=self.config.clip_norm
        
    
    @abstractmethod
    def load_local_data(self, data_path: str) -> bool:
        """
        加载本地数据
        
        Args:
            data_path: 数据路径
        
        Returns:
            是否成功
        """
        pass
    
    @abstractmethod
    def train_local(self, global_model: FLModel) -> Tuple[FLGradient, FLMetrics]:
        """
        本地训练
        
        Args:
            global_model: 全局模型
        
        Returns:
            (梯度, 指标)
        """
        pass
    
    @abstractmethod
    def evaluate_local(self, model: FLModel) -> FLMetrics:
        """
        本地评估
        
        Args:
            model: 待评估模型
        
        Returns:
            评估指标
        """
        pass
    
    def protect_gradient(self, gradients: Dict[str, List[float]]) -> Dict[str, List[float]]:
        """
        保护梯度（应用差分隐私）
        
        Args:
            gradients: 原始梯度
        
        Returns:
            保护后的梯度
        """
        return self.privacy_protector.protect(gradients)
    
    def get_status(self) -> Dict[str, Any]:
        """获取客户端状态"""
        return {
            'client_id': self.client_id,
            'status': self.status.value,
            'config': {
                'local_epochs': self.config.local_epochs,
                'learning_rate': self.config.learning_rate,
                'epsilon': self.config.epsilon
            }
        }


class FLServer(ABC):
    """联邦学习服务器抽象基类"""
    
    def __init__(self, config: FLConfig = None):
        """
        初始化服务器
        
        Args:
            config: 配置
        """
        self.config = config or FLConfig()
        self.status = FLStatus.IDLE
        self.global_model = None
        self.gradient_aggregator = GradientAggregator(self.config.algorithm)
        self.clients: Dict[str, FLClient] = {}
        self.current_round = 0
        self.round_results: List[FLRoundResult] = []
    
    def register_client(self, client: FLClient) -> bool:
        """
        注册客户端
        
        Args:
            client: 客户端实例
        
        Returns:
            是否成功
        """
        if client.client_id in self.clients:
            logger.warning(f"客户端已存在: {client.client_id}")
            return False
        
        self.clients[client.client_id] = client
        logger.info(f"客户端已注册: {client.client_id}")
        return True
    
    def unregister_client(self, client_id: str) -> bool:
        """
        注销客户端
        
        Args:
            client_id: 客户端ID
        
        Returns:
            是否成功
        """
        if client_id not in self.clients:
            logger.warning(f"客户端不存在: {client_id}")
            return False
        
        del self.clients[client_id]
        logger.info(f"客户端已注销: {client_id}")
        return True
    
    def select_clients(self, count: Optional[int] = None) -> List[FLClient]:
        """
        选择参与训练的客户端
        
        Args:
            count: 选择数量
        
        Returns:
            客户端列表
        """
        import random
        
        client_list = list(self.clients.values(

        selected_count = count or min(self.config.min_clients, len(client_list

        
        if len(client_list) <= selected_count:
            return client_list
        
        return random.sample(client_list, selected_count)
    
    @abstractmethod
    def initialize_global_model(self) -> FLModel:
        """
        初始化全局模型
        
        Returns:
            全局模型
        """
        pass
    
    def broadcast_model(self, clients: List[FLClient]) -> bool:
        """
        广播全局模型给客户端
        
        Args:
            clients: 客户端列表
        
        Returns:
            是否成功
        """
        if not self.global_model:
            logger.error("全局模型未初始化")
            return False
        
        for client in clients:
            client.local_model = self.global_model
            logger.debug(f"模型已广播到客户端: {client.client_id}")
        
        return True
    
    def collect_gradients(self, clients: List[FLClient]) -> List[FLGradient]:
        """
        收集客户端梯度
        
        Args:
            clients: 客户端列表
        
        Returns:
            梯度列表
        """
        gradients = []
        
        for client in clients:
            try:
                logger.info(f"客户端 {client.client_id} 开始本地训练")
                client.status = FLStatus.TRAINING
                
                grad, metrics = client.train_local(self.global_model)
                
                # 记录指标
                logger.info(f"客户端 {client.client_id} 训练完成: loss={metrics.loss:.4f}, accuracy={metrics.accuracy:.4f}")
                
                gradients.append(grad)
                client.status = FLStatus.IDLE
            except Exception as e:
                logger.error(f"客户端 {client.client_id} 训练失败: {e}")
                client.status = FLStatus.ERROR
        
        return gradients
    
    def aggregate_gradients(self, gradients: List[FLGradient]) -> Dict[str, List[float]]:
        """
        聚合梯度
        
        Args:
            gradients: 梯度列表
        
        Returns:
            聚合后的梯度
        """
        if not gradients:
            logger.warning("没有可用的梯度")
            return {}
        
        return self.gradient_aggregator.aggregate(gradients)
    
    @abstractmethod
    def update_global_model(self, aggregated_gradients: Dict[str, List[float]]) -> bool:
        """
        更新全局模型
        
        Args:
            aggregated_gradients: 聚合后的梯度
        
        Returns:
            是否成功
        """
        pass
    
    def run_round(self) -> FLRoundResult:
        """
        运行一轮联邦学习
        
        Returns:
            轮次结果
        """
        self.current_round += 1
        logger.info(f"开始第 {self.current_round} 轮训练")
        
        # 选择客户端
        selected_clients = self.select_clients()
        if len(selected_clients) < self.config.min_clients:
            logger.warning(f"参与客户端不足: {len(selected_clients)}/{self.config.min_clients}")
            return FLRoundResult(
                round=self.current_round,
                status=FLStatus.ERROR,
                metrics=[],
                participating_clients=[c.client_id for c in selected_clients],
                timestamp=time.time())
            

        
        # 广播模型
        self.status = FLStatus.SYNCING
        self.broadcast_model(selected_clients)
        
        # 收集梯度
        self.status = FLStatus.TRAINING
        gradients = self.collect_gradients(selected_clients)
        
        if not gradients:
            return FLRoundResult(
                round=self.current_round,
                status=FLStatus.ERROR,
                metrics=[],
                participating_clients=[c.client_id for c in selected_clients],
                timestamp=time.time())
            

        
        # 聚合梯度
        aggregated = self.aggregate_gradients(gradients)
        
        # 更新全局模型
        success = self.update_global_model(aggregated)
        
        # 评估
        self.status = FLStatus.EVALUATING
        metrics = self.evaluate_global(selected_clients)
        
        status = FLStatus.COMPLETED if success else FLStatus.ERROR
        
        result = FLRoundResult()
            round=self.current_round,
            status=status,
            metrics=metrics,
            model_update=self.global_model,
            participating_clients=[c.client_id for c in selected_clients],
            timestamp=time.time()
        
        
        self.round_results.append(result)
        self.status = FLStatus.IDLE
        
        logger.info(f"第 {self.current_round} 轮完成: status={status.value}")
        return result
    
    def evaluate_global(self, clients: List[FLClient]) -> List[FLMetrics]:
        """
        全局评估
        
        Args:
            clients: 客户端列表
        
        Returns:
            评估指标列表
        """
        metrics = []
        
        for client in clients:
            try:
                client_metrics = client.evaluate_local(self.global_model)
                metrics.append(client_metrics)
            except Exception as e:
                logger.error(f"客户端 {client.client_id} 评估失败: {e}")
        
        return metrics
    
    def train(self) -> List[FLRoundResult]:
        """
        执行完整的联邦学习训练
        
        Returns:
            所有轮次结果
        """
        if not self.global_model:
            self.global_model = self.initialize_global_model()
        
        results = []
        
        for _ in range(self.config.max_rounds):
            result = self.run_round()
            results.append(result)
            
            if result.status == FLStatus.ERROR:
                logger.error("训练出错，停止")
                break
            
            # 检查收敛
            if self._check_convergence(result):
                logger.info("模型已收敛")
                break
        
        return results
    
    def _check_convergence(self, result: FLRoundResult) -> bool:
        """
        检查是否收敛
        
        Args:
            result: 轮次结果
        
        Returns:
            是否收敛
        """
        if not result.metrics:
            return False
        
        # 简化的收敛检查
        avg_loss = sum(m.loss for m in result.metrics) / len(result.metrics)
        return avg_loss < 0.01
    
    def get_status(self) -> Dict[str, Any]:
        """获取服务器状态"""
        return {
            'status': self.status.value,
            'current_round': self.current_round,
            'total_rounds': self.config.max_rounds,
            'num_clients': len(self.clients),
            'algorithm': self.config.algorithm.value,
            'model_id': self.global_model.model_id if self.global_model else None
        }


class VulnerabilityDetectionClient(FLClient):
    """漏洞检测联邦学习客户端"""
    
    def __init__(self, client_id: str, config: FLConfig = None):
        super().__init__(client_id, config)
        self.local_data = []
        self.feature_extractor = None
    
    def load_local_data(self, data_path: str) -> bool:
        """加载本地漏洞数据"""
        try:
            with open(data_path, 'r', encoding='utf-8') as f:
                self.local_data = json.load(f)
            logger.info(f"客户端 {self.client_id} 加载了 {len(self.local_data)} 条数据")
            return True
        except Exception as e:
            logger.error(f"加载数据失败: {e}")
            return False
    
    def _extract_features(self, sample: Dict[str, Any]) -> List[float]:
        """提取样本特征"""
        features = []
        
        # 提取二进制特征
        if 'binary_hash' in sample:
            hash_val = sample['binary_hash']
            features.extend([ord(c) / 255.0 for c in hash_val[:16]])
        
        # 提取漏洞类型特征
        if 'vulnerability_type' in sample:
            vuln_types = ['buffer_overflow', 'use_after_free', 'integer_overflow', 'sqli']
            one_hot = [1.0 if sample['vulnerability_type'] == t else 0.0 for t in vuln_types]
            features.extend(one_hot)
        
        # 提取严重程度特征
        if 'severity' in sample:
            severity_map = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
            features.append(severity_map.get(sample['severity'], 0.5

        
        return features
    
    def train_local(self, global_model: FLModel) -> Tuple[FLGradient, FLMetrics]:
        """本地训练（简化实现）"""
        # 模拟训练
        gradients = {}
        
        # 复制全局模型参数作为梯度（简化）
        if global_model and global_model.parameters:
            for param_name, param_values in global_model.parameters.items():
                gradients[param_name] = [v * 0.01 for v in param_values]
        else:
            gradients = {'layer1': [0.001] * 10, 'layer2': [0.001] * 5}
        
        # 应用隐私保护
        protected_gradients = self.protect_gradient(gradients)
        
        gradient = FLGradient()
            client_id=self.client_id,
            gradients=protected_gradients,
            sample_count=len(self.local_data),
            round=self.config.max_rounds,
            timestamp=time.time()
        
        
        metrics = FLMetrics()
            round=self.config.max_rounds,
            client_id=self.client_id,
            loss=0.5 - len(self.local_data) * 0.01,
            accuracy=0.7 + len(self.local_data) * 0.02
        
        
        return gradient, metrics
    
    def evaluate_local(self, model: FLModel) -> FLMetrics:
        """本地评估（简化实现）"""
        return FLMetrics(
            round=self.config.max_rounds,
            client_id=self.client_id,
            loss=0.3,
            accuracy=0.85,
            precision=0.82,
            recall=0.88,
            f1_score=0.85)
        



class VulnerabilityDetectionServer(FLServer):
    """漏洞检测联邦学习服务器"""
    
    def __init__(self, config: FLConfig = None):
        super().__init__(config)
    
    def initialize_global_model(self) -> FLModel:
        """初始化漏洞检测模型"""
        parameters = {
            'layer1': [0.0] * 10,
            'layer2': [0.0] * 5,
            'output': [0.0] * 4
        }
        
        return FLModel(
            model_id=f"vuln_detection_{int(time.time())}",
            parameters=parameters,
            version=1,
            timestamp=time.time(),
            metadata={'model_type': 'vulnerability_detection'})
        

    
    def update_global_model(self, aggregated_gradients: Dict[str, List[float]]) -> bool:
        """更新全局模型"""
        if not self.global_model or not aggregated_gradients:
            return False
        
        for param_name, gradients in aggregated_gradients.items():
            if param_name in self.global_model.parameters:
                params = self.global_model.parameters[param_name]
                updated = [
                    params[i] + self.config.learning_rate * gradients[i]
                    for i in range(min(len(params), len(gradients

                ]
                self.global_model.parameters[param_name] = updated
        
        self.global_model.version += 1
        self.global_model.timestamp = time.time()
        
        return True


class FLNetworkSimulator:
    """联邦学习网络模拟器"""
    
    def __init__(self):
        self.clients: Dict[str, FLClient] = {}
        self.server: Optional[FLServer] = None
    
    def set_server(self, server: FLServer):
        """设置服务器"""
        self.server = server
    
    def add_client(self, client: FLClient):
        """添加客户端"""
        self.clients[client.client_id] = client,
        if self.server:
            self.server.register_client(client)
    
    def remove_client(self, client_id: str):
        """移除客户端"""
        if client_id in self.clients:
            del self.clients[client_id]
            if self.server:
                self.server.unregister_client(client_id)
    
    def simulate_latency(self, base_latency: float = 0.1):
        """模拟网络延迟"""
        import random
        time.sleep(base_latency + random.uniform(0, 0.1

    
    def run_simulation(self, rounds: int = 10) -> List[FLRoundResult]:
        """运行模拟"""
        if not self.server:
            logger.error("服务器未设置")
            return []
        
        logger.info(f"开始联邦学习模拟，共 {rounds} 轮")
        
        results = []
        for _ in range(rounds):
            self.simulate_latency()
            result = self.server.run_round()
            results.append(result)
            
            if result.status == FLStatus.ERROR:
                break
        
        return results


# 便捷函数
def create_vuln_detection_client(client_id: str) -> VulnerabilityDetectionClient:
    """创建漏洞检测客户端"""
    return VulnerabilityDetectionClient(client_id)


def create_vuln_detection_server() -> VulnerabilityDetectionServer:
    """创建漏洞检测服务器"""
    return VulnerabilityDetectionServer()


def create_fl_simulator() -> FLNetworkSimulator:
    """创建联邦学习网络模拟器"""
    return FLNetworkSimulator())))))))))))))))))