import logging
import os
import pickle
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
import numpy as np
import hashlib

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """图节点信息"""
    id: str
    type: str  # 'basic_block', 'instruction', 'variable', 'function'
    features: np.ndarray
    label: Optional[str] = None


@dataclass
class GraphEdge:
    """图边信息"""
    source: str
    target: str
    type: str  # 'control_flow', 'data_dependency', 'call', 'use_def'
    weight: float = 1.0


@dataclass
class FunctionGraph:
    """函数的多视图图表示"""
    function_name: str
    function_address: int
    cfg_nodes: List[GraphNode] = field(default_factory=list)
    cfg_edges: List[GraphEdge] = field(default_factory=list)
    ddg_nodes: List[GraphNode] = field(default_factory=list)
    ddg_edges: List[GraphEdge] = field(default_factory=list)
    ccg_nodes: List[GraphNode] = field(default_factory=list)
    ccg_edges: List[GraphEdge] = field(default_factory=list)


@dataclass
class EmbeddingResult:
    """嵌入结果"""
    function_name: str
    function_address: int
    embedding: np.ndarray
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SimilarityResult:
    """相似性检索结果"""
    query_function: str
    similar_functions: List[Tuple[str, float]]  # (function_name, similarity_score)
    top_k: int


class GNNEncoder(nn.Module):
    """图神经网络编码器"""
    
    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, num_layers: int = 3):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        
        self.conv_layers = nn.ModuleList()
        self.conv_layers.append(nn.Linear(input_dim, hidden_dim))
        
        for _ in range(num_layers - 1):
            self.conv_layers.append(nn.Linear(hidden_dim, hidden_dim))
        
        self.output_layer = nn.Linear(hidden_dim, output_dim)
        self.dropout = nn.Dropout(0.3)
    
    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        
        Args:
            x: 节点特征矩阵 [num_nodes, input_dim]
            adj: 邻接矩阵 [num_nodes, num_nodes]
        
        Returns:
            图嵌入向量 [output_dim]
        """
        h = x
        
        for conv in self.conv_layers:
            h = conv(h)
            h = torch.relu(h)
            h = self.dropout(h)
            # 图卷积：聚合邻居信息
            h = torch.matmul(adj, h)
        
        # 图级别嵌入：取所有节点的平均
        graph_embedding = torch.mean(h, dim=0)
        graph_embedding = self.output_layer(graph_embedding)
        
        return graph_embedding


class MultiViewGNN(nn.Module):
    """多视图图神经网络"""
    
    def __init__(self, input_dim: int = 128, hidden_dim: int = 256, output_dim: int = 512):
        super().__init__()
        self.output_dim = output_dim
        
        # 三个视图的编码器
        self.cfg_encoder = GNNEncoder(input_dim, hidden_dim, output_dim)
        self.ddg_encoder = GNNEncoder(input_dim, hidden_dim, output_dim)
        self.ccg_encoder = GNNEncoder(input_dim, hidden_dim, output_dim)
        
        # 注意力融合层
        self.attention_layer = nn.Linear(output_dim * 3, 3)
        
    def forward(self, cfg_x: torch.Tensor, cfg_adj: torch.Tensor,
                ddg_x: torch.Tensor, ddg_adj: torch.Tensor,
                ccg_x: torch.Tensor, ccg_adj: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        
        Args:
            cfg_x: CFG节点特征
            cfg_adj: CFG邻接矩阵
            ddg_x: DDG节点特征
            ddg_adj: DDG邻接矩阵
            ccg_x: CCG节点特征
            ccg_adj: CCG邻接矩阵
        
        Returns:
            融合后的函数嵌入向量
        """
        # 分别编码三个视图
        cfg_emb = self.cfg_encoder(cfg_x, cfg_adj)
        ddg_emb = self.ddg_encoder(ddg_x, ddg_adj)
        ccg_emb = self.ccg_encoder(ccg_x, ccg_adj)
        
        # 拼接特征
        concatenated = torch.cat([cfg_emb, ddg_emb, ccg_emb], dim=-1)
        
        # 注意力权重
        attn_weights = F.softmax(self.attention_layer(concatenated), dim=-1)
        
        # 加权融合
        fused = (attn_weights[0] * cfg_emb + 
                 attn_weights[1] * ddg_emb + 
                 attn_weights[2] * ccg_emb)
        
        return fused


class ContrastiveLoss(nn.Module):
    """对比学习损失函数"""
    
    def __init__(self, temperature: float = 0.5):
        super().__init__()
        self.temperature = temperature
    
    def forward(self, anchors: torch.Tensor, positives: torch.Tensor, negatives: torch.Tensor) -> torch.Tensor:
        """
        计算对比损失
        
        Args:
            anchors: 锚点样本 [batch_size, dim]
            positives: 正样本 [batch_size, dim]
            negatives: 负样本 [batch_size, num_negatives, dim]
        
        Returns:
            对比损失值
        """
        batch_size = anchors.size(0)
        
        # 计算锚点与正样本的相似度
        pos_sim = torch.bmm(anchors.unsqueeze(1), positives.unsqueeze(2)).squeeze()
        
        # 计算锚点与负样本的相似度
        neg_sim = torch.bmm(anchors.unsqueeze(1), negatives.transpose(1, 2)).squeeze()
        
        # 合并相似度
        logits = torch.cat([pos_sim.unsqueeze(1), neg_sim], dim=1) / self.temperature
        
        # 标签：正样本在第0位
        labels = torch.zeros(batch_size, dtype=torch.long).to(anchors.device)
        
        loss = F.cross_entropy(logits, labels)
        
        return loss


class MultiViewGNNEmbedder:
    """多视图GNN函数嵌入器"""
    
    def __init__(self, model_path: Optional[str] = None, device: str = "auto"):
        """
        初始化嵌入器
        
        Args:
            model_path: 预训练模型路径
            device: 运行设备，"auto"自动选择GPU或CPU
        """
        if not HAS_TORCH:
            raise ImportError("PyTorch is required for MultiViewGNNEmbedder")
        
        self.device = torch.device("cuda" if torch.cuda.is_available() and device == "auto" else "cpu")
        self.model = MultiViewGNN().to(self.device)
        self.model.eval()
        
        if model_path and os.path.exists(model_path):
            try:
                self.model.load_state_dict(torch.load(model_path, map_location=self.device))
                logger.info(f"加载预训练模型: {model_path}")
            except Exception as e:
                logger.warning(f"加载模型失败: {e}")
        
        self.embedding_cache: Dict[str, np.ndarray] = {}
    
    def _extract_basic_block_features(self, block_instructions: List[str]) -> np.ndarray:
        """
        提取基本块特征
        
        Args:
            block_instructions: 基本块中的指令列表
        
        Returns:
            特征向量 [input_dim]
        """
        features = []
        
        # 指令类型统计
        instruction_types = ['add', 'sub', 'mul', 'div', 'and', 'or', 'xor', 
                             'mov', 'load', 'store', 'call', 'ret', 'jmp', 'cmp']
        
        for instr_type in instruction_types:
            count = sum(1 for instr in block_instructions if instr_type in instr.lower())
            features.append(count)
        
        # 指令数量
        features.append(len(block_instructions))
        
        # 归一化
        features = np.array(features, dtype=np.float32)
        if np.sum(features) > 0:
            features = features / np.sum(features)
        
        # 填充到固定维度
        if len(features) < 128:
            features = np.pad(features, (0, 128 - len(features)))
        
        return features[:128]
    
    def _build_graph_representation(self, function_info: Dict[str, Any]) -> FunctionGraph:
        """
        构建函数的多视图图表示
        
        Args:
            function_info: 函数信息字典，包含CFG、DDG、CCG信息
        
        Returns:
            FunctionGraph 对象
        """
        func_graph = FunctionGraph(
            function_name=function_info.get("name", "unknown"),
            function_address=function_info.get("address", 0)
        )
        
        # 构建CFG
        cfg_nodes = function_info.get("cfg_nodes", [])
        for node in cfg_nodes:
            features = self._extract_basic_block_features(node.get("instructions", []))
            func_graph.cfg_nodes.append(GraphNode(
                id=str(node.get("id", 0)),
                type="basic_block",
                features=features,
                label=node.get("label")
            ))
        
        cfg_edges = function_info.get("cfg_edges", [])
        for edge in cfg_edges:
            func_graph.cfg_edges.append(GraphEdge(
                source=str(edge.get("source")),
                target=str(edge.get("target")),
                type="control_flow"
            ))
        
        # 构建DDG（简化版）
        ddg_vars = function_info.get("variables", [])
        for var in ddg_vars:
            features = np.random.randn(128).astype(np.float32)  # 实际应提取变量特征
            func_graph.ddg_nodes.append(GraphNode(
                id=var.get("name", "unknown"),
                type="variable",
                features=features
            ))
        
        # 构建CCG（简化版）
        call_graph = function_info.get("call_graph", [])
        for call in call_graph:
            features = np.random.randn(128).astype(np.float32)  # 实际应提取调用特征
            func_graph.ccg_nodes.append(GraphNode(
                id=call.get("callee", "unknown"),
                type="function",
                features=features
            ))
        
        return func_graph
    
    def _graph_to_tensors(self, func_graph: FunctionGraph) -> Tuple[torch.Tensor, ...]:
        """
        将图转换为张量
        
        Args:
            func_graph: FunctionGraph 对象
        
        Returns:
            (cfg_x, cfg_adj, ddg_x, ddg_adj, ccg_x, ccg_adj)
        """
        def nodes_to_tensor(nodes: List[GraphNode]) -> torch.Tensor:
            if not nodes:
                return torch.zeros(1, 128).to(self.device)
            features = np.array([n.features for n in nodes])
            return torch.tensor(features).to(self.device)
        
        def edges_to_adjacency(nodes: List[GraphNode], edges: List[GraphEdge]) -> torch.Tensor:
            num_nodes = len(nodes) if nodes else 1
            adj = torch.eye(num_nodes).to(self.device)
            
            node_id_to_idx = {n.id: i for i, n in enumerate(nodes)}
            
            for edge in edges:
                src_idx = node_id_to_idx.get(edge.source, 0)
                tgt_idx = node_id_to_idx.get(edge.target, 0)
                adj[src_idx, tgt_idx] = 1.0
                adj[tgt_idx, src_idx] = 1.0  # 无向图
            
            return adj
        
        cfg_x = nodes_to_tensor(func_graph.cfg_nodes)
        cfg_adj = edges_to_adjacency(func_graph.cfg_nodes, func_graph.cfg_edges)
        
        ddg_x = nodes_to_tensor(func_graph.ddg_nodes)
        ddg_adj = edges_to_adjacency(func_graph.ddg_nodes, func_graph.ddg_edges)
        
        ccg_x = nodes_to_tensor(func_graph.ccg_nodes)
        ccg_adj = edges_to_adjacency(func_graph.ccg_nodes, func_graph.ccg_edges)
        
        return cfg_x, cfg_adj, ddg_x, ddg_adj, ccg_x, ccg_adj
    
    def embed_function(self, function_info: Dict[str, Any]) -> EmbeddingResult:
        """
        为函数生成嵌入向量
        
        Args:
            function_info: 函数信息字典
        
        Returns:
            EmbeddingResult 对象
        """
        try:
            # 构建图表示
            func_graph = self._build_graph_representation(function_info)
            
            # 转换为张量
            tensors = self._graph_to_tensors(func_graph)
            
            # 前向传播
            with torch.no_grad():
                embedding = self.model(*tensors)
            
            # 转换为numpy
            embedding_np = embedding.cpu().numpy()
            
            # 计算置信度（基于嵌入向量的归一化程度）
            confidence = float(np.linalg.norm(embedding_np) / np.sqrt(len(embedding_np)))
            
            result = EmbeddingResult(
                function_name=func_graph.function_name,
                function_address=func_graph.function_address,
                embedding=embedding_np,
                confidence=confidence,
                metadata={
                    "num_cfg_nodes": len(func_graph.cfg_nodes),
                    "num_ddg_nodes": len(func_graph.ddg_nodes),
                    "num_ccg_nodes": len(func_graph.ccg_nodes)
                }
            )
            
            # 缓存结果
            cache_key = f"{func_graph.function_name}_{func_graph.function_address}"
            self.embedding_cache[cache_key] = embedding_np
            
            return result
        
        except Exception as e:
            logger.error(f"嵌入函数失败: {e}")
            return EmbeddingResult(
                function_name=function_info.get("name", "unknown"),
                function_address=function_info.get("address", 0),
                embedding=np.zeros(512),
                confidence=0.0,
                metadata={"error": str(e)}
            )
    
    def batch_embed(self, functions_info: List[Dict[str, Any]]) -> List[EmbeddingResult]:
        """
        批量生成函数嵌入
        
        Args:
            functions_info: 函数信息字典列表
        
        Returns:
            嵌入结果列表
        """
        results = []
        for func_info in functions_info:
            result = self.embed_function(func_info)
            results.append(result)
        return results
    
    def compute_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        计算两个嵌入向量的相似度（余弦相似度）
        
        Args:
            embedding1: 第一个嵌入向量
            embedding2: 第二个嵌入向量
        
        Returns:
            相似度分数 [0, 1]
        """
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(np.dot(embedding1, embedding2) / (norm1 * norm2))
    
    def search_similar(self, query_embedding: np.ndarray, top_k: int = 5) -> SimilarityResult:
        """
        在缓存中搜索相似函数
        
        Args:
            query_embedding: 查询嵌入向量
            top_k: 返回前k个相似函数
        
        Returns:
            SimilarityResult 对象
        """
        similarities = []
        
        for key, embedding in self.embedding_cache.items():
            sim = self.compute_similarity(query_embedding, embedding)
            similarities.append((key, sim))
        
        # 按相似度排序
        similarities.sort(key=lambda x: -x[1])
        
        return SimilarityResult(
            query_function="query",
            similar_functions=similarities[:top_k],
            top_k=top_k
        )
    
    def save_embeddings(self, path: str) -> bool:
        """
        保存嵌入缓存到文件
        
        Args:
            path: 保存路径
        
        Returns:
            是否成功保存
        """
        try:
            with open(path, 'wb') as f:
                pickle.dump(self.embedding_cache, f)
            logger.info(f"嵌入缓存已保存到: {path}")
            return True
        except Exception as e:
            logger.error(f"保存嵌入缓存失败: {e}")
            return False
    
    def load_embeddings(self, path: str) -> bool:
        """
        从文件加载嵌入缓存
        
        Args:
            path: 文件路径
        
        Returns:
            是否成功加载
        """
        try:
            with open(path, 'rb') as f:
                self.embedding_cache = pickle.load(f)
            logger.info(f"嵌入缓存已从 {path} 加载")
            return True
        except Exception as e:
            logger.error(f"加载嵌入缓存失败: {e}")
            return False


class MultiViewGNNEmbedderAnalyzer:
    """多视图图神经网络函数嵌入分析器（BaseAnalyzer包装）"""
    
    def __init__(self):
        self.embedder: Optional[MultiViewGNNEmbedder] = None
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行分析任务
        
        Args:
            **kwargs: 分析参数
                - functions: 函数信息列表
                - model_path: 预训练模型路径
                - output_path: 嵌入保存路径
                - search_query: 用于相似性检索的查询嵌入（可选）
        
        Returns:
            分析结果字典
        """
        functions = kwargs.get("functions", [])
        model_path = kwargs.get("model_path")
        output_path = kwargs.get("output_path")
        search_query = kwargs.get("search_query")
        
        try:
            # 初始化嵌入器
            self.embedder = MultiViewGNNEmbedder(model_path=model_path)
            
            results = {
                "success": True,
                "embeddings": [],
                "search_results": None
            }
            
            # 批量嵌入
            if functions:
                embeddings = self.embedder.batch_embed(functions)
                results["embeddings"] = [
                    {
                        "function_name": e.function_name,
                        "function_address": e.function_address,
                        "embedding": e.embedding.tolist(),
                        "confidence": e.confidence,
                        "metadata": e.metadata
                    }
                    for e in embeddings
                ]
            
            # 相似性检索
            if search_query is not None:
                if isinstance(search_query, list):
                    query_embedding = np.array(search_query)
                    search_result = self.embedder.search_similar(query_embedding)
                    results["search_results"] = {
                        "similar_functions": search_result.similar_functions,
                        "top_k": search_result.top_k
                    }
            
            # 保存嵌入
            if output_path:
                self.embedder.save_embeddings(output_path)
                results["saved_path"] = output_path
            
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
            "name": "MultiViewGNNEmbedder",
            "type": "feature_extractor",
            "version": "1.0.0",
            "description": "多视图图神经网络函数嵌入，构建CFG/DDG/CCG三视图，使用GNN编码为统一向量",
            "author": "BinaryAnalysisPlatform",
            "dependencies": ["torch", "numpy"],
            "supported_platforms": ["all"]
        }
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """
        验证输入参数
        
        Args:
            **kwargs: 输入参数
        
        Returns:
            (是否有效, 错误信息)
        """
        functions = kwargs.get("functions")
        if functions is not None and not isinstance(functions, list):
            return False, "functions 必须是列表类型"
        
        output_path = kwargs.get("output_path")
        if output_path is not None:
            try:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                return False, f"无法创建输出目录: {e}"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        self.embedder = None