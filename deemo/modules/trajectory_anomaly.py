import logging
import os
import pickle
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    Dataset = None

logger = logging.getLogger(__name__)


@dataclass
class ExecutionTrace:
    """执行轨迹"""
    trace_id: str
    basic_blocks: List[int]
    timestamp: Optional[float] = None
    process_id: Optional[int] = None
    thread_id: Optional[int] = None


@dataclass
class AnomalyResult:
    """异常检测结果"""
    trace_id: str
    is_anomalous: bool
    perplexity: float
    threshold: float
    anomaly_type: Optional[str]
    suspicious_regions: List[Tuple[int, int]]
    explanation: Optional[str] = None


@dataclass
class ModelConfig:
    """模型配置"""
    vocab_size: int = 10000
    embedding_dim: int = 256
    hidden_dim: int = 512
    num_layers: int = 4
    num_heads: int = 8
    max_seq_length: int = 512
    dropout: float = 0.1
    learning_rate: float = 1e-4
    batch_size: int = 32
    epochs: int = 10


class BasicBlockTokenizer:
    """基本块tokenizer"""
    
    def __init__(self):
        self.special_tokens = {
            '<sos>': 0,
            '<eos>': 1,
            '<pad>': 2,
            '<unk>': 3
        }
        self.block_to_id: Dict[int, int] = {}
        self.next_id = 4
    
    def fit(self, traces: List[ExecutionTrace]) -> None:
        """
        从轨迹中学习基本块到token的映射
        
        Args:
            traces: 执行轨迹列表
        """
        for trace in traces:
            for block in trace.basic_blocks:
                if block not in self.block_to_id:
                    self.block_to_id[block] = self.next_id
                    self.next_id += 1
        
        logger.info(f"Tokenizer训练完成，共识别 {self.next_id} 个基本块")
    
    def encode(self, trace: ExecutionTrace) -> List[int]:
        """
        将轨迹编码为token序列
        
        Args:
            trace: 执行轨迹
        
        Returns:
            token序列
        """
        tokens = [self.special_tokens['<sos>']]
        
        for block in trace.basic_blocks:
            tokens.append(self.block_to_id.get(block, self.special_tokens['<unk>']

        
        tokens.append(self.special_tokens['<eos>'])
        
        return tokens
    
    def decode(self, tokens: List[int]) -> List[int]:
        """
        将token序列解码为基本块序列
        
        Args:
            tokens: token序列
        
        Returns:
            基本块地址列表
        """
        id_to_block = {v: k for k, v in self.block_to_id.items()}
        blocks = []
        
        for token in tokens:
            if token in self.special_tokens.values():
                continue
            blocks.append(id_to_block.get(token, -1

        
        return blocks
    
    def save(self, path: str) -> bool:
        """
        保存tokenizer
        
        Args:
            path: 保存路径
        
        Returns:
            是否成功
        """
        try:
            with open(path, 'wb') as f:
                pickle.dump({)
                    'special_tokens': self.special_tokens,
                    'block_to_id': self.block_to_id,
                    'next_id': self.next_id
                }, f
            logger.info(f"Tokenizer已保存到: {path}")
            return True
        except Exception as e:
            logger.error(f"保存tokenizer失败: {e}")
            return False
    
    def load(self, path: str) -> bool:
        """
        加载tokenizer
        
        Args:
            path: 文件路径
        
        Returns:
            是否成功
        """
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
            
            self.special_tokens = data['special_tokens']
            self.block_to_id = data['block_to_id']
            self.next_id = data['next_id']
            
            logger.info(f"Tokenizer已从 {path} 加载")
            return True
        except Exception as e:
            logger.error(f"加载tokenizer失败: {e}")
            return False


if HAS_TORCH:
    class GPTStyleModel(nn.Module):
        """GPT风格的自回归模型"""
        
        def __init__(self, config: ModelConfig):
            super().__init__()
            self.config = config
            
            self.embedding = nn.Embedding(config.vocab_size, config.embedding_dim)
            
            self.position_encoding = nn.Parameter()
                torch.randn(1, config.max_seq_length, config.embedding_dim)
            
            
            encoder_layer = nn.TransformerEncoderLayer()
                d_model=config.embedding_dim,
                nhead=config.num_heads,
                dim_feedforward=config.hidden_dim,
                dropout=config.dropout,
                batch_first=True
            
            self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=config.num_layers)
            
            self.output_layer = nn.Linear(config.embedding_dim, config.vocab_size)
        
        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """
            前向传播
            
            Args:
                x: 输入token序列 [batch_size, seq_len]
            
            Returns:
                预测logits [batch_size, seq_len, vocab_size]
            """
            batch_size, seq_len = x.size()
            
            emb = self.embedding(x)
            
            pos_emb = self.position_encoding[:, :seq_len, :]
            emb = emb + pos_emb
            
            output = self.transformer(emb)
            
            logits = self.output_layer(output)
            
            return logits
        
        def compute_perplexity(self, x: torch.Tensor) -> float:
            """
            计算序列的困惑度
            
            Args:
                x: 输入token序列 [seq_len]
            
            Returns:
                困惑度值
            """
            self.eval()
            
            with torch.no_grad():
                x = x.unsqueeze(0)
                logits = self.forward(x)
                
                shift_logits = logits[:, :-1, :].contiguous()
                shift_labels = x[:, 1:].contiguous()
                
                loss = F.cross_entropy()
                    shift_logits.view(-1, self.config.vocab_size),
                    shift_labels.view(-1),
                    reduction='mean'
                
                
                perplexity = torch.exp(loss).item()
            
            return perplexity
    
    class TraceDataset(Dataset):
        """执行轨迹数据集"""
        
        def __init__(self, traces: List[ExecutionTrace], tokenizer: BasicBlockTokenizer, max_seq_length: int = 512):
            self.traces = traces
            self.tokenizer = tokenizer
            self.max_seq_length = max_seq_length
        
        def __len__(self) -> int:
            return len(self.traces)
        
        def __getitem__(self, idx: int) -> torch.Tensor:
            trace = self.traces[idx]
            tokens = self.tokenizer.encode(trace)
            
            if len(tokens) > self.max_seq_length:
                tokens = tokens[:self.max_seq_length]
            else:
                tokens += [self.tokenizer.special_tokens['<pad>']] * (self.max_seq_length - len(tokens

            
            return torch.tensor(tokens, dtype=torch.long)
    
    class TrajectoryAnomalyDetector:
        """执行轨迹异常检测器"""
        
        def __init__(self, config: Optional[ModelConfig] = None):
            """
            初始化检测器
            
            Args:
                config: 模型配置
            """
            self.config = config or ModelConfig()
            self.tokenizer = BasicBlockTokenizer()
            self.model = None
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.threshold = 100.0
        
        def train(self, traces: List[ExecutionTrace], val_traces: Optional[List[ExecutionTrace]] = None) -> None:
            """
            训练模型
            
            Args:
                traces: 训练轨迹
                val_traces: 验证轨迹
            """
            self.tokenizer.fit(traces)
            
            self.config.vocab_size = self.tokenizer.next_id
            
            self.model = GPTStyleModel(self.config).to(self.device)
            
            train_dataset = TraceDataset(traces, self.tokenizer, self.config.max_seq_length)
            train_loader = DataLoader(train_dataset, batch_size=self.config.batch_size, shuffle=True)
            
            optimizer = torch.optim.Adam(self.model.parameters(), lr=self.config.learning_rate)
            
            logger.info("开始训练轨迹异常检测模型...")
            
            for epoch in range(self.config.epochs):
                self.model.train()
                total_loss = 0.0
                
                for batch in train_loader:
                    batch = batch.to(self.device)
                    
                    optimizer.zero_grad()
                    
                    logits = self.model(batch)
                    
                    shift_logits = logits[:, :-1, :].contiguous()
                    shift_labels = batch[:, 1:].contiguous()
                    
                    loss = F.cross_entropy()
                        shift_logits.view(-1, self.config.vocab_size),
                        shift_labels.view(-1),
                        ignore_index=self.tokenizer.special_tokens['<pad>']
                    
                    
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(train_loader)
                logger.info(f"Epoch {epoch+1}/{self.config.epochs}, Loss: {avg_loss:.4f}")
            
            if val_traces:
                self._set_threshold(val_traces)
            
            logger.info("训练完成")
        
        def _set_threshold(self, traces: List[ExecutionTrace]) -> None:
            """
            根据验证集设置异常检测阈值
            
            Args:
                traces: 验证轨迹
            """
            perplexities = []
            
            for trace in traces:
                tokens = self.tokenizer.encode(trace)
                if len(tokens) > 1:
                    tokens_tensor = torch.tensor(tokens, dtype=torch.long).to(self.device)
                    perplexity = self.model.compute_perplexity(tokens_tensor)
                    perplexities.append(perplexity)
            
            if perplexities:
                self.threshold = max(perplexities) * 1.5
                logger.info(f"异常检测阈值设置为: {self.threshold:.2f}")
        
        def detect_anomaly(self, trace: ExecutionTrace) -> AnomalyResult:
            """
            检测轨迹中的异常
            
            Args:
                trace: 待检测的执行轨迹
            
            Returns:
                检测结果
            """
            if not self.model:
                logger.error("模型未训练")
                return AnomalyResult(
                    trace_id=trace.trace_id,
                    is_anomalous=False,
                    perplexity=0.0,
                    threshold=self.threshold,
                    anomaly_type=None,
                    suspicious_regions=[],
                    explanation="模型未训练")
                

            
            try:
                tokens = self.tokenizer.encode(trace)
                
                if len(tokens) <= 2:
                    return AnomalyResult(
                        trace_id=trace.trace_id,
                        is_anomalous=False,
                        perplexity=0.0,
                        threshold=self.threshold,
                        anomaly_type="normal",
                        suspicious_regions=[],
                        explanation="轨迹过短")
                    

                
                tokens_tensor = torch.tensor(tokens, dtype=torch.long).to(self.device)
                perplexity = self.model.compute_perplexity(tokens_tensor)
                
                is_anomalous = perplexity > self.threshold
                
                anomaly_type = self._classify_anomaly_type(trace, tokens)
                
                suspicious_regions = self._find_suspicious_regions(tokens)
                
                explanation = f"困惑度: {perplexity:.2f}, 阈值: {self.threshold:.2f}"
                
                return AnomalyResult(
                    trace_id=trace.trace_id,
                    is_anomalous=is_anomalous,
                    perplexity=perplexity,
                    threshold=self.threshold,
                    anomaly_type=anomaly_type,
                    suspicious_regions=suspicious_regions,
                    explanation=explanation)
                

            
            except Exception as e:
                logger.error(f"检测异常失败: {e}")
                return AnomalyResult(
                    trace_id=trace.trace_id,
                    is_anomalous=False,
                    perplexity=0.0,
                    threshold=self.threshold,
                    anomaly_type=None,
                    suspicious_regions=[],
                    explanation=str(e))
                

        
        def _classify_anomaly_type(self, trace: ExecutionTrace, tokens: List[int]) -> str:
            """
            分类异常类型
            
            Args:
                trace: 执行轨迹
                tokens: 编码后的token序列
            
            Returns:
                异常类型
            """
            blocks = trace.basic_blocks
            
            if len(blocks) > 10:
                if self._detect_stack_pivot(blocks):
                    return "stack_pivot"
                
                if self._detect_rop_chain(blocks):
                    return "ROP"
                
                if self._detect_jop_chain(blocks):
                    return "JOP"
            
            if not self.model:
                return "normal"
            
            perplexity = self.model.compute_perplexity()
                torch.tensor(tokens, dtype=torch.long).to(self.device)
            
            return "normal" if perplexity <= self.threshold else "unknown_anomaly"
        
        def _detect_stack_pivot(self, blocks: List[int]) -> bool:
            """
            检测栈pivot特征
            
            Args:
                blocks: 基本块地址列表
            
            Returns:
                是否检测到栈pivot
            """
            if len(blocks) < 3:
                return False
            
            for i in range(len(blocks) - 2):
                diff1 = abs(blocks[i+1] - blocks[i])
                diff2 = abs(blocks[i+2] - blocks[i+1])
                if diff1 < 100 and diff2 < 100 and diff1 != diff2:
                    return True
            
            return False
        
        def _detect_rop_chain(self, blocks: List[int]) -> bool:
            """
            检测ROP链特征
            
            Args:
                blocks: 基本块地址列表
            
            Returns:
                是否检测到ROP链
            """
            if len(blocks) < 5:
                return False
            
            diffs = [abs(blocks[i+1] - blocks[i]) for i in range(len(blocks)-1)]
            if len(diffs) < 2:
                return False
            
            variance = np.var(diffs)
            
            return variance > 1e8
        
        def _detect_jop_chain(self, blocks: List[int]) -> bool:
            """
            检测JOP链特征
            
            Args:
                blocks: 基本块地址列表
            
            Returns:
                是否检测到JOP链
            """
            if len(blocks) < 3:
                return False
            
            unique_blocks = set(blocks)
            if len(unique_blocks) / len(blocks) < 0.5:
                return True
            
            return False
        
        def _find_suspicious_regions(self, tokens: List[int]) -> List[Tuple[int, int]]:
            """
            定位可疑区域
            
            Args:
                tokens: token序列
            
            Returns:
                可疑区域列表
            """
            if not self.model:
                return []
            
            self.model.eval()
            
            with torch.no_grad():
                tokens_tensor = torch.tensor(tokens, dtype=torch.long).unsqueeze(0).to(self.device)
                logits = self.model(tokens_tensor)
                
                probs = F.softmax(logits, dim=-1)
                
                suspicious_regions = []
                in_suspicious = False
                start_idx = 0
                
                for i in range(1, len(tokens)):
                    true_token = tokens[i]
                    prob = probs[0, i-1, true_token].item()
                    
                    if prob < 0.1:
                        if not in_suspicious:
                            in_suspicious = True
                            start_idx = i
                    else:
                        if in_suspicious:
                            in_suspicious = False
                            suspicious_regions.append((start_idx, i

                
                if in_suspicious:
                    suspicious_regions.append((start_idx, len(tokens

            
            return suspicious_regions
        
        def save_model(self, path: str) -> bool:
            """
            保存模型和tokenizer
            
            Args:
                path: 保存目录
            
            Returns:
                是否成功
            """
            try:
                os.makedirs(path, exist_ok=True)
                
                if self.model:
                    torch.save(self.model.state_dict(), os.path.join(path, "model.pt"

                
                self.tokenizer.save(os.path.join(path, "tokenizer.pkl"

                
                config_data = {
                    'threshold': self.threshold,
                    'config': self.config.__dict__
                }
                with open(os.path.join(path, "config.pkl"), 'wb') as f:
                    pickle.dump(config_data, f)
                
                logger.info(f"模型已保存到: {path}")
                return True
            except Exception as e:
                logger.error(f"保存模型失败: {e}")
                return False
        
        def load_model(self, path: str) -> bool:
            """
            加载模型和tokenizer
            
            Args:
                path: 模型目录
            
            Returns:
                是否成功
            """
            try:
                with open(os.path.join(path, "config.pkl"), 'rb') as f:
                    config_data = pickle.load(f)
                
                self.threshold = config_data['threshold']
                self.config.__dict__.update(config_data['config'])
                
                self.tokenizer.load(os.path.join(path, "tokenizer.pkl"

                
                self.model = GPTStyleModel(self.config).to(self.device)
                self.model.load_state_dict(torch.load(os.path.join(path, "model.pt"), map_location=self.device

                self.model.eval()
                
                logger.info(f"模型已从 {path} 加载")
                return True
            except Exception as e:
                logger.error(f"加载模型失败: {e}")
                return False


class TrajectoryAnomalyAnalyzer:
    """执行轨迹异常检测分析器（BaseAnalyzer包装）"""
    
    def __init__(self):
        self.detector = None
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行分析任务
        
        Args:
            **kwargs: 分析参数
                - traces: 执行轨迹列表（用于训练）
                - test_trace: 待检测的轨迹（用于检测）
                - test_traces: 待检测的轨迹列表（用于批量检测）
                - model_path: 预训练模型路径
                - mode: 模式（train/detect）
        
        Returns:
            分析结果字典
        """
        traces = kwargs.get("traces", [])
        test_trace = kwargs.get("test_trace")
        test_traces = kwargs.get("test_traces", [])
        model_path = kwargs.get("model_path")
        mode = kwargs.get("mode", "detect")
        
        try:
            if not HAS_TORCH:
                return {
                    "success": False,
                    "error": "PyTorch is required",
                    "message": "请安装 PyTorch 以使用轨迹异常检测功能"
                }
            
            results = {"success": True, "detections": [], "training_result": None}
            
            if mode == "train":
                if not traces:
                    return {"success": False, "error": "训练需要 traces 参数"}
                
                self.detector = TrajectoryAnomalyDetector()
                self.detector.train(traces)
                
                if model_path:
                    self.detector.save_model(model_path)
                
                results["training_result"] = "训练完成"
            
            else:
                if not self.detector:
                    self.detector = TrajectoryAnomalyDetector()
                    if model_path:
                        self.detector.load_model(model_path)
                
                if test_trace:
                    result = self.detector.detect_anomaly(test_trace)
                    results["detections"].append({)
                        "trace_id": result.trace_id,
                        "is_anomalous": result.is_anomalous,
                        "perplexity": result.perplexity,
                        "threshold": result.threshold,
                        "anomaly_type": result.anomaly_type,
                        "suspicious_regions": result.suspicious_regions,
                        "explanation": result.explanation
                    }
                
                for trace in test_traces:
                    result = self.detector.detect_anomaly(trace)
                    results["detections"].append({)
                        "trace_id": result.trace_id,
                        "is_anomalous": result.is_anomalous,
                        "perplexity": result.perplexity,
                        "threshold": result.threshold,
                        "anomaly_type": result.anomaly_type,
                        "suspicious_regions": result.suspicious_regions,
                        "explanation": result.explanation
                    }
            
            return results
            
        except Exception as e:
            logger.error(f"分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """
        获取分析器元数据
        
        Returns:
            元数据字典
        """
        return {
            "name": "TrajectoryAnomalyDetector",
            "type": "anomaly_detector",
            "version": "1.0.0",
            "description": "执行轨迹序列模型异常检测，使用GPT风格自回归模型检测ROP/JOP等异常控制流",
            "author": "BinaryAnalysisPlatform",
            "dependencies": ["torch"],
            "supported_platforms": ["all"]
        })))))))))))))))))))