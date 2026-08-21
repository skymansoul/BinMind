"""Federated-learning-driven collaborative analysis for sensitive targets

Capabilities:
1. Client-side FL agent
2. Server-side FL 调度器
3. Gradient aggregation / parameter synchronization
4. Differential-privacy gradient 混淆
5. Model versioning state synchronization

注: "Secure aggregation 协议" 和 "SMPC" 在当前版本中未实现。
基类 FLClient / FLServer 为抽象接口, 不可直接实例化。
具体实现参见 VulnerabilityDetectionClient / VulnerabilityDetectionServer。
"""

import logging, json, hashlib, time
from abc import ABC, abstractmethod
from abc import ABC, abstractmethod

_g_log = logging.getLogger(__name__)

class FLRole:
    SERVER = "server"; CLIENT = "client"
    _val = None
    def __init__(self, value): self._val = value
    @property
    def value(self): return self._val
    def __str__(self): return self._val

FLRole.SERVER = FLRole("server"); FLRole.CLIENT = FLRole("client")

class FLStatus:
    IDLE = "idle"; TRAINING = "training"; SYNCING = "syncing"; EVALUATING = "evaluating"; COMPLETED = "completed"; ERROR = "error"
    _val = None
    def __init__(self, value): self._val = value
    @property
    def value(self): return self._val
    def __str__(self): return self._val

FLStatus.IDLE = FLStatus("idle"); FLStatus.TRAINING = FLStatus("training"); FLStatus.SYNCING = FLStatus("syncing")
FLStatus.EVALUATING = FLStatus("evaluating"); FLStatus.COMPLETED = FLStatus("completed"); FLStatus.ERROR = FLStatus("error")

class FLAlgorithm:
    FEDAVG = "fedavg"; FEDPROX = "fedprox"; FEDSGD = "fedsgd"; SCAFFOLD = "scaffold"; MOCHA = "mocha"

class FLConfig:
    __slots__ = ('algorithm', 'num_clients', 'min_clients', 'max_rounds', 'local_epochs', 'learning_rate', 'epsilon', 'clip_norm', 'aggregation_weight')
    def __init__(self, algorithm=FLAlgorithm.FEDAVG, num_clients=10, min_clients=3, max_rounds=100, local_epochs=5, learning_rate=0.01, epsilon=1.0, clip_norm=1.0, aggregation_weight=1.0):
        self.algorithm = algorithm; self.num_clients = num_clients; self.min_clients = min_clients; self.max_rounds = max_rounds
        self.local_epochs = local_epochs; self.learning_rate = learning_rate; self.epsilon = epsilon; self.clip_norm = clip_norm; self.aggregation_weight = aggregation_weight

class FLModel:
    __slots__ = ('model_id', 'parameters', 'version', 'timestamp', 'metadata')
    def __init__(self, model_id, parameters, version=1, timestamp=0.0, metadata=None):
        self.model_id = model_id; self.parameters = parameters; self.version = version; self.timestamp = timestamp; self.metadata = metadata if metadata is not None else {}

class FLGradient:
    __slots__ = ('client_id', 'gradients', 'sample_count', 'round', 'timestamp', 'encrypted')
    def __init__(self, client_id, gradients, sample_count=0, round=0, timestamp=0.0, encrypted=False):
        self.client_id = client_id; self.gradients = gradients; self.sample_count = sample_count; self.round = round; self.timestamp = timestamp; self.encrypted = encrypted

class FLMetrics:
    __slots__ = ('round', 'client_id', 'loss', 'accuracy', 'precision', 'recall', 'f1_score')
    def __init__(self, round, client_id, loss=0.0, accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0):
        self.round = round; self.client_id = client_id; self.loss = loss; self.accuracy = accuracy; self.precision = precision; self.recall = recall; self.f1_score = f1_score

class FLRoundResult:
    __slots__ = ('round', 'status', 'metrics', 'model_update', 'participating_clients', 'timestamp')
    def __init__(self, round, status, metrics, model_update=None, participating_clients=None, timestamp=0.0):
        self.round = round; self.status = status; self.metrics = metrics; self.model_update = model_update
        self.participating_clients = participating_clients if participating_clients is not None else []; self.timestamp = timestamp

class PrivacyProtector:
    """Gradient privacy layer: clip norm, inject Laplace noise"""

    def __init__(self, epsilon=1.0, clip_norm=1.0):
        self.epsilon = epsilon; self.clip_norm = clip_norm

    def clip_gradient(self, gradient):
        if gradient is None: return []
        import numpy as np; grad_np = np.array(gradient); norm = np.linalg.norm(grad_np)
        if norm > self.clip_norm: grad_np = grad_np * (self.clip_norm / norm)
        return grad_np.tolist()

    def add_noise(self, gradient, sensitivity=1.0):
        if gradient is None: return []
        import numpy as np, random, math; scale = sensitivity / self.epsilon; grad_np = np.array(gradient)
        noise = np.array([(-scale * math.log(1 - 2 * abs(random.random() - 0.5)) * (1 if random.random() >= 0.5 else -1)) for _ in range(len(grad_np))])
        return (grad_np + noise).tolist()

    def protect(self, gradients):
        """Clip noise: full DP-SGD gradient protection 流水线"""
        if gradients is None: return {}
        protected = {}
        grad_keys = list(gradients.keys()); i = 0
        while i < len(grad_keys):
            key = grad_keys[i]; grad = gradients[key]; clipped = self.clip_gradient(grad); protected[key] = self.add_noise(clipped); i += 1
        return protected

    def compute_privacy_spent(self, steps: int, delta: float = 1e-5) -> float:
        """Rényi DP 会计, 基于 moments accountant 的隐私预算追踪
        返回 (ε, δ) 组合用于判断训练是否违反预设隐私上限
        简化实现：假设每次查询独立，使用高斯机制的组合定理
        """
        if steps <= 0 or self.epsilon <= 0:
            return 0.0
        import math as _m
        # 强组合定理：RDP 的 α 阶矩累加
        sigma = 1.0 / self.epsilon
        alpha = 2.0
        eps_alpha = alpha / (2.0 * sigma ** 2)
        return eps_alpha * steps  # 近似的 ε 累积

class GradientAggregator:
    """Strategy-pattern gradient aggregation: FedAvg, FedProx, FedSGD, etc"""

    def __init__(self, algorithm=FLAlgorithm.FEDAVG):
        self.algorithm = algorithm

    def aggregate(self, gradients):
        if gradients is None or len(gradients) == 0: return {}
        if self.algorithm == FLAlgorithm.FEDAVG: return self._fedavg_aggregate(gradients)
        elif self.algorithm == FLAlgorithm.FEDPROX: return self._fedprox_aggregate(gradients)
        else: return self._fedavg_aggregate(gradients)

    def _fedavg_aggregate(self, gradients):
        """Weighted average: client contribution scaled sample_count"""
        import numpy as np
        total_samples = 0; i = 0
        while i < len(gradients): total_samples += gradients[i].sample_count if gradients[i].sample_count > 0 else 1; i += 1
        if total_samples == 0: total_samples = len(gradients)
        param_names = set()
        i = 0
        while i < len(gradients): param_names.update(gradients[i].gradients.keys()); i += 1
        aggregated = {}; pn_list = list(param_names); i = 0
        while i < len(pn_list):
            param_name = pn_list[i]; grads = []; weights = []
            j = 0
            while j < len(gradients):
                g = gradients[j]
                if param_name in g.gradients: grads.append(np.array(g.gradients[param_name])); weights.append(g.sample_count if g.sample_count > 0 else 1)
                j += 1
            if grads: weights_np = np.array(weights) / total_samples; aggregated[param_name] = np.average(grads, axis=0, weights=weights_np).tolist()
            i += 1
        return aggregated

    def _fedprox_aggregate(self, gradients):
        """FedProx: proximal-term variant weighted average (simplified)"""
        return self._fedavg_aggregate(gradients)

class FLClient(ABC):
    """联邦学习客户端基类, 不可直接实例化, 子类必须实现 train_local 和 evaluate_local。
    具体实现: VulnerabilityDetectionClient。
    """

    def __init__(self, client_id, config=None):
        self.client_id = client_id; self.config = config or FLConfig(); self.status = FLStatus.IDLE; self.local_model = None
        self.privacy_protector = PrivacyProtector(epsilon=self.config.epsilon, clip_norm=self.config.clip_norm)

    @abstractmethod
    def load_local_data(self, data_path):
        """加载本地训练数据。子类必须覆盖, 数据格式取决于具体应用场景。"""
        ...

    @abstractmethod
    def train_local(self, global_model):
        """本地 SGD 训练。返回 (FLGradient, FLMetrics)。
        子类必须实现前向传播→损失计算→梯度计算。
        """
        ...

    @abstractmethod
    def evaluate_local(self, model):
        """本地模型评估。返回 FLMetrics (含 loss/accuracy)。"""
        ...

    def protect_gradient(self, gradients):
        """Apply DP perturbation local gradient uplink"""
        if gradients is None: return {}
        return self.privacy_protector.protect(gradients)

    def get_status(self):
        return {'client_id': self.client_id, 'status': self.status.value, 'config': {'local_epochs': self.config.local_epochs, 'learning_rate': self.config.learning_rate, 'epsilon': self.config.epsilon}}

class FLServer(ABC):
    """联邦学习服务端基类, 不可直接实例化。
    子类必须实现 initialize_global_model 和 update_global_model。
    具体实现: VulnerabilityDetectionServer。
    """

    def __init__(self, config=None):
        self.config = config or FLConfig(); self.status = FLStatus.IDLE; self.global_model = None
        self.gradient_aggregator = GradientAggregator(self.config.algorithm); self.clients = {}; self.current_round = 0; self.round_results = []

    def register_client(self, client):
        if client is None: return False
        if client.client_id in self.clients: _g_log.warning("client already registered: %s", client.client_id); return False
        self.clients[client.client_id] = client; _g_log.info("client registered: %s", client.client_id); return True

    def unregister_client(self, client_id):
        if client_id is None: return False
        if client_id not in self.clients: _g_log.warning("client not found: %s", client_id); return False
        del self.clients[client_id]; _g_log.info("client unregistered: %s", client_id); return True

    def select_clients(self, count=None):
        import random; client_list = list(self.clients.values()); selected_count = count or min(self.config.min_clients, len(client_list))
        if len(client_list) <= selected_count: return client_list
        return random.sample(client_list, selected_count)

    @abstractmethod
    def initialize_global_model(self):
        """初始化全局模型权重。子类必须返回 FLModel 实例。"""
        ...

    def broadcast_model(self, clients):
        if clients is None: return False
        if not self.global_model: _g_log.error("global model uninitialized"); return False
        i = 0
        while i < len(clients): clients[i].local_model = self.global_model; _g_log.debug("model broadcast to client: %s", clients[i].client_id); i += 1
        return True

    def collect_gradients(self, clients):
        if clients is None: return []
        gradients = []; i = 0
        while i < len(clients):
            client = clients[i]
            try:
                _g_log.info("client %s local training start", client.client_id); client.status = FLStatus.TRAINING
                grad, metrics = client.train_local(self.global_model)
                _g_log.info("client %s training complete loss=%.4f accuracy=%.4f", client.client_id, metrics.loss, metrics.accuracy)
                gradients.append(grad); client.status = FLStatus.IDLE
            except Exception as e: _g_log.error("client %s training failed: %s", client.client_id, e); client.status = FLStatus.ERROR
            i += 1
        return gradients

    def aggregate_gradients(self, gradients):
        if gradients is None or len(gradients) == 0: _g_log.warning("no gradients to aggregate"); return {}
        return self.gradient_aggregator.aggregate(gradients)

    @abstractmethod
    def update_global_model(self, aggregated_gradients):
        """应用聚合梯度更新全局模型。子类必须实现 SGD 步骤: W = W - lr * grad。
        返回 True 表示更新成功。
        """
        ...

    def run_round(self):
        """执行 one complete FL 舍入: select, broadcast, train, aggregate, evaluate"""
        self.current_round += 1; _g_log.info("round %d start", self.current_round)
        selected_clients = self.select_clients()
        if len(selected_clients) < self.config.min_clients:
            _g_log.warning("insufficient participants: %d/%d", len(selected_clients), self.config.min_clients)
            return FLRoundResult(round=self.current_round, status=FLStatus.ERROR, metrics=[], participating_clients=[c.client_id for c in selected_clients], timestamp=time.time())
        self.status = FLStatus.SYNCING; self.broadcast_model(selected_clients)
        self.status = FLStatus.TRAINING; gradients = self.collect_gradients(selected_clients)
        if not gradients:
            return FLRoundResult(round=self.current_round, status=FLStatus.ERROR, metrics=[], participating_clients=[c.client_id for c in selected_clients], timestamp=time.time())
        aggregated = self.aggregate_gradients(gradients); success = self.update_global_model(aggregated)
        self.status = FLStatus.EVALUATING; metrics = self.evaluate_global(selected_clients)
        status = FLStatus.COMPLETED if success else FLStatus.ERROR
        result = FLRoundResult(round=self.current_round, status=status, metrics=metrics, model_update=self.global_model, participating_clients=[c.client_id for c in selected_clients], timestamp=time.time())
        self.round_results.append(result); self.status = FLStatus.IDLE; _g_log.info("round %d complete status=%s", self.current_round, status.value)
        return result

    def evaluate_global(self, clients):
        if clients is None: return []
        metrics = []; i = 0
        while i < len(clients):
            client = clients[i]
            try:
                client_metrics = client.evaluate_local(self.global_model); metrics.append(client_metrics)
            except Exception as e: _g_log.error("client %s evaluation failed: %s", client.client_id, e)
            i += 1
        return metrics

    def train(self):
        """Full training lifecycle: 初始化, 迭代 舍入, 检查 convergence"""
        if not self.global_model: self.global_model = self.initialize_global_model()
        results = []; round_idx = 0
        while round_idx < self.config.max_rounds:
            result = self.run_round(); results.append(result)
            if result.status == FLStatus.ERROR: _g_log.error("training aborted due to error"); break
            if self._check_convergence(result): _g_log.info("model converged"); break
            round_idx += 1
        return results

    def _check_convergence(self, result):
        """Convergence criterion: mean loss across participating clients < 0.01"""
        if result is None or not result.metrics: return False
        total = 0.0; i = 0
        while i < len(result.metrics): total += result.metrics[i].loss; i += 1
        avg_loss = total / len(result.metrics); return avg_loss < 0.01

    def get_status(self):
        return {'status': self.status.value, 'current_round': self.current_round, 'total_rounds': self.config.max_rounds, 'num_clients': len(self.clients), 'algorithm': self.config.algorithm.value, 'model_id': self.global_model.model_id if self.global_model else None}

class VulnerabilityDetectionClient(FLClient):
    """FL client specialized for 漏洞检测 local binary corpora"""

    def __init__(self, client_id, config=None):
        super().__init__(client_id, config); self.local_data = []; self.feature_extractor = None

    def load_local_data(self, data_path):
        if data_path is None: return False
        try:
            with open(data_path, 'r', encoding='utf-8') as f: self.local_data = json.load(f)
            _g_log.info("client %s loaded %d samples", self.client_id, len(self.local_data)); return True
        except Exception as e: _g_log.error("data load failed: %s", e); return False

    def _extract_features(self, sample):
        if sample is None: return []
        features = []
        if 'binary_hash' in sample:
            hash_val = sample['binary_hash']
            i = 0
            while i < min(len(hash_val), 16): features.append(ord(hash_val[i]) / 255.0); i += 1
        if 'vulnerability_type' in sample:
            vuln_types = ['buffer_overflow', 'use_after_free', 'integer_overflow', 'sqli']; one_hot = [1.0 if sample['vulnerability_type'] == t else 0.0 for t in vuln_types]; features.extend(one_hot)
        if 'severity' in sample:
            severity_map = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}; features.append(severity_map.get(sample['severity'], 0.5))
        return features

    def train_local(self, global_model):
        """本地 SGD 训练, 前向传播 -> 交叉熵损失 -> 手动反向传播求梯度。
        模型为 2 层 MLP: input_dim -> 10(hidden,ReLU) -> 5(hidden,ReLU) -> 4(softmax).
        梯度通过链式法则逐层计算, 不含自动微分框架依赖。
        """
        if not self.local_data or not global_model or not global_model.parameters:
            gradients = {'layer1': [0.001] * 10, 'layer2': [0.001] * 5}
            protected = self.protect_gradient(gradients)
            return (FLGradient(client_id=self.client_id, gradients=protected,
                              sample_count=0, round=self.config.max_rounds,
                              timestamp=time.time()),
                    FLMetrics(round=self.config.max_rounds, client_id=self.client_id,
                              loss=999.0, accuracy=0.0, note='no local data'))

        lr = self.config.learning_rate
        total_loss = 0.0
        correct = 0
        grad_acc = {}

        for sample in self.local_data[:min(len(self.local_data), 50)]:
            features = self._extract_features(sample)
            if not features:
                continue
            x = (features + [0.0] * 10)[:10]
            label_map = {'buffer_overflow': 0, 'use_after_free': 1,
                         'integer_overflow': 2, 'none': 3}
            target_idx = label_map.get(sample.get('vulnerability_type', 'none'), 3)
            y_true = [1.0 if i == target_idx else 0.0 for i in range(4)]

            w1 = global_model.parameters.get('layer1', [0.0] * 10)
            w2 = global_model.parameters.get('layer2', [0.0] * 5)
            w3 = global_model.parameters.get('output', [0.0] * 4)

            h1 = [max(0.0, x[j] * w1[j]) for j in range(10)]
            h2 = [max(0.0, sum(h1[k * 2:(k + 1) * 2]) * w2[k]) for k in range(5)]
            logits = [sum(h2[k] * w3[min(k + i, 3)] for k in range(5)) for i in range(4)]
            max_logit = max(logits)
            probs = [max(0.001, l / max(max_logit, 0.001)) for l in logits]
            p_sum = sum(probs)
            probs = [p / p_sum for p in probs]

            eps = 1e-9
            loss = -sum(y_true[i] * max(-20.0, min(20.0, (probs[i] + eps))) for i in range(4))
            total_loss += loss
            pred_idx = max(range(4), key=lambda i: probs[i])
            if pred_idx == target_idx:
                correct += 1

            d_probs = [-y_true[i] / max(probs[i], eps) for i in range(4)]
            d_logits = [probs[i] * (d_probs[i] - sum(probs[j] * d_probs[j] for j in range(4)))
                        for i in range(4)]
            d_h2 = [sum(d_logits[min(i, 3)] * w3[j] for j in range(4)) for i in range(5)]
            d_h2 = [d_h2[k] if h2[k] > 0 else 0.0 for k in range(5)]
            d_h1 = [0.0] * 10
            for k in range(5):
                for j in range(k * 2, min((k + 1) * 2, 10)):
                    d_h1[j] += d_h2[k] * w2[k]
            d_h1 = [d_h1[j] if h1[j] > 0 else 0.0 for j in range(10)]

            grad_w1 = [d_h1[j] * x[j] for j in range(10)]
            grad_w2 = [d_h2[k] * sum(h1[k * 2:(k + 1) * 2]) for k in range(5)]
            grad_w3 = [d_logits[i] * sum(h2) for i in range(4)]

            for k, v in {'layer1': grad_w1, 'layer2': grad_w2, 'output': grad_w3}.items():
                if k not in grad_acc:
                    grad_acc[k] = [0.0] * len(v)
                for j in range(len(v)):
                    grad_acc[k][j] += v[j]

        n_samples = max(len(self.local_data), 1)
        final_grad = {}
        for k, v in grad_acc.items():
            final_grad[k] = [g / n_samples * lr for g in v]

        protected = self.protect_gradient(final_grad)
        avg_loss = total_loss / n_samples
        accuracy = correct / n_samples

        return (FLGradient(client_id=self.client_id, gradients=protected,
                          sample_count=n_samples, round=self.config.max_rounds,
                          timestamp=time.time()),
                FLMetrics(round=self.config.max_rounds, client_id=self.client_id,
                         loss=avg_loss, accuracy=accuracy))

    def evaluate_local(self, model):
        """本地评估, 在验证集上计算损失和准确率。"""
        if not self.local_data or not model or not model.parameters:
            return FLMetrics(round=self.config.max_rounds, client_id=self.client_id,
                           loss=999.0, accuracy=0.0, note='no validation data')

        total_loss = 0.0
        correct = 0
        n = 0
        label_map = {'buffer_overflow': 0, 'use_after_free': 1,
                     'integer_overflow': 2, 'none': 3}

        for sample in self.local_data[:min(len(self.local_data), 200)]:
            features = self._extract_features(sample)
            if not features:
                continue
            x = (features + [0.0] * 10)[:10]
            target_idx = label_map.get(sample.get('vulnerability_type', 'none'), 3)

            w1 = model.parameters.get('layer1', [0.0] * 10)
            w2 = model.parameters.get('layer2', [0.0] * 5)
            w3 = model.parameters.get('output', [0.0] * 4)

            h1 = [max(0.0, x[j] * w1[j]) for j in range(10)]
            h2 = [max(0.0, sum(h1[k * 2:(k + 1) * 2]) * w2[k]) for k in range(5)]
            logits = [sum(h2[k] * w3[min(k + i, 3)] for k in range(5)) for i in range(4)]
            max_logit = max(logits)
            probs = [max(0.001, l / max(max_logit, 0.001)) for l in logits]
            p_sum = sum(probs)
            probs = [p / p_sum for p in probs]

            y_true = [1.0 if i == target_idx else 0.0 for i in range(4)]
            eps = 1e-9
            loss = -sum(y_true[i] * max(-20.0, min(20.0, (probs[i] + eps))) for i in range(4))
            total_loss += loss
            pred_idx = max(range(4), key=lambda i: probs[i])
            if pred_idx == target_idx:
                correct += 1
            n += 1

        n = max(n, 1)
        return FLMetrics(round=self.config.max_rounds, client_id=self.client_id,
                        loss=total_loss / n, accuracy=correct / n)

class VulnerabilityDetectionServer(FLServer):
    """FL server specialized for 漏洞检测 model aggregation"""

    def __init__(self, config=None):
        super().__init__(config)

    def initialize_global_model(self):
        parameters = {'layer1': [0.0] * 10, 'layer2': [0.0] * 5, 'output': [0.0] * 4}
        return FLModel(model_id="vuln_detection_{}".format(int(time.time())), parameters=parameters, version=1, timestamp=time.time(), metadata={'model_type': 'vulnerability_detection'})

    def update_global_model(self, aggregated_gradients):
        if not self.global_model or aggregated_gradients is None or len(aggregated_gradients) == 0: return False
        ag_keys = list(aggregated_gradients.keys()); i = 0
        while i < len(ag_keys):
            param_name = ag_keys[i]; gradients = aggregated_gradients[param_name]
            if param_name in self.global_model.parameters:
                params = self.global_model.parameters[param_name]
                updated = [params[k] + self.config.learning_rate * gradients[k] for k in range(min(len(params), len(gradients)))]
                self.global_model.parameters[param_name] = updated
            i += 1
        self.global_model.version += 1; self.global_model.timestamp = time.time(); return True

class FLNetworkSimulator:
    """Simulated FL 网络: 延迟 model, client/server wiring, 舍入 loop"""

    def __init__(self): self.clients = {}; self.server = None

    def set_server(self, server):
        if server is None: return; self.server = server

    def add_client(self, client):
        if client is None: return; self.clients[client.client_id] = client
        if self.server: self.server.register_client(client)

    def remove_client(self, client_id):
        if client_id is None: return
        if client_id in self.clients: del self.clients[client_id]
        if self.server: self.server.unregister_client(client_id)

    def simulate_latency(self, base_latency=0.1):
        """Inject synthetic 网络 延迟 per communication 舍入"""
        import random; time.sleep(base_latency + random.uniform(0, 0.1))

    def run_simulation(self, rounds=10):
        if not self.server: _g_log.error("server not configured"); return []
        _g_log.info("FL simulation start, %d rounds", rounds)
        results = []; r = 0
        while r < rounds:
            self.simulate_latency()
            result = self.server.run_round()
            results.append(result)
            if result.status == FLStatus.ERROR:
                break
            r += 1
        return results

def create_vuln_detection_client(client_id):
    return VulnerabilityDetectionClient(client_id)

def create_vuln_detection_server():
    return VulnerabilityDetectionServer()

def create_fl_simulator():
    return FLNetworkSimulator()
