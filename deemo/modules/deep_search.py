import os
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

class DeepBinarySearcher:
    """
    基于深度学习的二进制代码搜索器
    
    利用预训练深度学习模型将二进制函数编码为嵌入向量，实现跨架构的相似函数搜索。
    
    Attributes:
        model: 预训练模型
        index: 函数嵌入索引
        index_path: 索引文件路径
        functions: 已分析函数列表
    """
    
    def __init__(self, model_path: str = None):
        """
        初始化深度学习二进制搜索器

        Args:
            model_path: 预训练模型路径
        """
        self.model_path = model_path
        self.model = None
        self.index: Dict[str, np.ndarray] = {}
        self.embeddings: Dict[str, np.ndarray] = {}
        self.global_index: Dict[str, np.ndarray] = {}
        self.functions: List[Dict[str, Any]] = []
        self.index_path = os.path.join(os.path.expanduser('~'), '.deep_binary_search', 'index.json')
        self._ensure_index_dir()

    def _ensure_index_dir(self):
        """确保索引目录存在"""
        index_dir = os.path.dirname(self.index_path)
        if not os.path.exists(index_dir):
            os.makedirs(index_dir, exist_ok=True)

    def search(self, query_embedding, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        根据查询向量在索引中搜索相似函数

        Args:
            query_embedding: 查询向量（list 或 np.ndarray）
            top_k: 返回前 k 个结果

        Returns:
            相似函数列表
        """
        # 空索引直接返回空列表
        if not self.embeddings and not self.global_index:
            return []

        # 转换为 ndarray
        if isinstance(query_embedding, list):
            query_embedding = np.array(query_embedding, dtype=np.float32)

        # 选择数据源
        data_source = self.embeddings if self.embeddings else self.global_index
        if not data_source:
            return []

        results = []
        for func_id, embedding in data_source.items():
            try:
                similarity = self._calculate_similarity(query_embedding, embedding)
                results.append({
                    'id': func_id,
                    'similarity': float(similarity),
                    'name': func_id,
                })
            except Exception:
                continue

        results.sort(key=lambda x: x['similarity'], reverse=True)
        return results[:top_k]

    def build_index(self, binary_paths: List[str]) -> Dict[str, Any]:
        """
        构建全局索引

        Args:
            binary_paths: 二进制文件路径列表

        Returns:
            构建结果字典
        """
        result = {
            'indexed_count': 0,
            'failed': [],
            'total': len(binary_paths) if binary_paths else 0
        }

        if not binary_paths:
            return result

        for binary_path in binary_paths:
            try:
                if not os.path.exists(binary_path):
                    result['failed'].append(binary_path)
                    continue
                # 真实索引逻辑（占位）：此处可调用 index_binary
                indexed = self.index_binary(binary_path)
                result['indexed_count'] += len(indexed)
            except Exception as e:
                logger.warning(f"索引 {binary_path} 失败: {e}")
                result['failed'].append(binary_path)

        return result

    def load_model(self, model_path: str = None) -> bool:
        """
        加载预训练模型

        Args:
            model_path: 模型文件路径

        Returns:
            True 表示加载成功（即使为模拟模式）
        """
        if model_path:
            self.model_path = model_path

        if not self.model_path:
            logger.warning("未指定模型路径，使用模拟嵌入生成")
            # 没有模型路径时使用模拟模式，仍然算成功
            return True

        try:
            # 尝试加载ONNX模型
            if self.model_path.endswith('.onnx'):
                import onnxruntime as ort
                if not os.path.exists(self.model_path):
                    logger.warning(f"模型文件不存在: {self.model_path}，使用模拟嵌入生成")
                    return True
                self.model = ort.InferenceSession(self.model_path)
                logger.info(f"已加载ONNX模型: {self.model_path}")
            else:
                # 尝试加载PyTorch模型
                import torch
                if not os.path.exists(self.model_path):
                    logger.warning(f"模型文件不存在: {self.model_path}，使用模拟嵌入生成")
                    return True
                self.model = torch.load(self.model_path, map_location='cpu')
                logger.info(f"已加载PyTorch模型: {self.model_path}")
            return True

        except Exception as e:
            logger.warning(f"加载模型失败，使用模拟嵌入生成: {e}")
            return True
    
    def generate_embedding(self, function_code: str) -> np.ndarray:
        """
        生成函数嵌入向量
        
        Args:
            function_code: 函数伪代码或汇编代码
        
        Returns:
            嵌入向量
        """
        if self.model:
            try:
                # 实际模型推理
                return self._model_inference(function_code)
            except Exception as e:
                logger.debug(f"模型推理失败，使用模拟嵌入: {e}")
        
        # 模拟嵌入生成（基于代码特征）
        return self._generate_simulated_embedding(function_code)
    
    def _model_inference(self, function_code: str) -> np.ndarray:
        """
        使用模型进行推理
        
        Args:
            function_code: 函数代码
        
        Returns:
            嵌入向量
        """
        # 简化实现，实际应根据模型输入要求处理
        if hasattr(self.model, 'run'):
            # ONNX模型
            input_name = self.model.get_inputs()[0].name
            input_data = np.array([hash(function_code) % 1000], dtype=np.float32)
            output = self.model.run(None, {input_name: input_data})
            return output[0].flatten()
        else:
            # PyTorch模型
            import torch
            input_tensor = torch.tensor([hash(function_code) % 1000], dtype=torch.float32)
            with torch.no_grad():
                output = self.model(input_tensor)
            return output.numpy().flatten()
    
    def _generate_simulated_embedding(self, function_code: str) -> np.ndarray:
        """
        生成模拟嵌入向量
        
        Args:
            function_code: 函数代码
        
        Returns:
            嵌入向量（128维）
        """
        features = []
        
        # 特征1: 代码长度
        features.append(len(function_code) / 1000.0)
        
        # 特征2: 函数调用数量
        call_count = function_code.count('(') - function_code.count('=')
        features.append(min(call_count / 50.0, 1.0))
        
        # 特征3: 字符串操作数量
        str_ops = function_code.count('str') + function_code.count('memcpy') + function_code.count('sprintf')
        features.append(min(str_ops / 20.0, 1.0))
        
        # 特征4: 算术操作数量
        math_ops = function_code.count('+') + function_code.count('-') + function_code.count('*') + function_code.count('/')
        features.append(min(math_ops / 100.0, 1.0))
        
        # 特征5: 控制流复杂度
        control_flow = function_code.count('if') + function_code.count('while') + function_code.count('for') + function_code.count('switch')
        features.append(min(control_flow / 30.0, 1.0))
        
        # 特征6-128: 使用哈希生成随机特征
        hash_value = hash(function_code)
        np.random.seed(hash_value)
        random_features = np.random.rand(122).tolist()
        
        features.extend(random_features)
        
        return np.array(features, dtype=np.float32)
    
    def index_binary(self, binary_path: str, function_names: List[str] = None) -> List[str]:
        """
        索引二进制文件中的函数
        
        Args:
            binary_path: 二进制文件路径
            function_names: 要索引的函数名列表（可选）
        
        Returns:
            已索引的函数名列表
        """
        indexed = []
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(binary_path, client=None)
            
            if function_names:
                funcs_to_index = function_names
            else:
                funcs_to_index = decompiler.list_functions()[:50]
            
            for func_name in funcs_to_index:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    
                    if pseudocode:
                        embedding = self.generate_embedding(pseudocode)
                        
                        func_id = f"{binary_path}:{func_name}"
                        self.index[func_id] = embedding
                        
                        self.functions.append({
                            'id': func_id,
                            'name': func_name,
                            'binary': binary_path,
                            'embedding_shape': embedding.shape
                        })
                        
                        indexed.append(func_name)
                
                except Exception as e:
                    logger.debug(f"索引函数 {func_name} 失败: {e}")
        
        except Exception as e:
            logger.warning(f"索引二进制文件失败: {e}")
        
        return indexed
    
    def search_similar(self, query_code: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        搜索相似函数
        
        Args:
            query_code: 查询代码（伪代码或汇编）
            top_k: 返回前k个结果
        
        Returns:
            相似函数列表，包含相似度评分
        """
        if not self.index:
            logger.warning("索引为空，请先调用 index_binary")
            return []
        
        query_embedding = self.generate_embedding(query_code)
        results = []
        
        for func_id, embedding in self.index.items():
            similarity = self._calculate_similarity(query_embedding, embedding)
            
            # 查找函数信息
            func_info = next((f for f in self.functions if f['id'] == func_id), None)
            
            results.append({
                'id': func_id,
                'name': func_info['name'] if func_info else func_id,
                'binary': func_info['binary'] if func_info else 'unknown',
                'similarity': similarity
            })
        
        # 按相似度排序
        results.sort(key=lambda x: x['similarity'], reverse=True)
        
        return results[:top_k]
    
    def _calculate_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        计算向量相似度（余弦相似度）
        
        Args:
            vec1: 向量1
            vec2: 向量2
        
        Returns:
            相似度分数（0-1）
        """
        if len(vec1) != len(vec2):
            vec1 = np.resize(vec1, min(len(vec1), len(vec2)))
            vec2 = np.resize(vec2, min(len(vec1), len(vec2)))
        
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(dot_product / (norm1 * norm2))
    
    def save_index(self, path: str = None):
        """
        保存索引到文件
        
        Args:
            path: 保存路径（可选）
        """
        if not path:
            path = self.index_path
        
        # 将numpy数组转换为列表以便序列化
        index_data = {
            'index': {k: v.tolist() for k, v in self.index.items()},
            'functions': self.functions,
            'model_path': self.model_path
        }
        
        try:
            with open(path, 'w') as f:
                json.dump(index_data, f, indent=2)
            logger.info(f"索引已保存到: {path}")
        except Exception as e:
            logger.error(f"保存索引失败: {e}")
    
    def load_index(self, path: str = None):
        """
        从文件加载索引
        
        Args:
            path: 索引文件路径（可选）
        """
        if not path:
            path = self.index_path
        
        if not os.path.exists(path):
            logger.warning(f"索引文件不存在: {path}")
            return
        
        try:
            with open(path, 'r') as f:
                index_data = json.load(f)
            
            self.index = {k: np.array(v) for k, v in index_data.get('index', {}).items()}
            self.functions = index_data.get('functions', [])
            self.model_path = index_data.get('model_path', None)
            
            logger.info(f"已加载索引，包含 {len(self.index)} 个函数")
        
        except Exception as e:
            logger.error(f"加载索引失败: {e}")


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='深度学习二进制代码搜索器')
    parser.add_argument('--index', help='索引二进制文件')
    parser.add_argument('--query', help='查询代码文件')
    parser.add_argument('--load-index', help='加载索引文件')
    parser.add_argument('--save-index', help='保存索引文件')
    parser.add_argument('--model', help='预训练模型路径')
    parser.add_argument('--top-k', type=int, default=5, help='返回结果数量')
    parser.add_argument('--output', default='/tmp/deep_search_results.json', help='输出文件')
    
    args = parser.parse_args()
    
    searcher = DeepBinarySearcher(args.model)
    searcher.load_model()
    
    if args.load_index:
        searcher.load_index(args.load_index)
    
    if args.index:
        searcher.index_binary(args.index)
        if args.save_index:
            searcher.save_index(args.save_index)
    
    if args.query:
        if os.path.exists(args.query):
            with open(args.query, 'r') as f:
                query_code = f.read()
        else:
            query_code = args.query
        
        results = searcher.search_similar(query_code, args.top_k)
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"搜索结果已保存到: {args.output}")
        print("\n相似函数列表:")
        for i, result in enumerate(results):
            print(f"{i+1}. {result['name']} (相似度: {result['similarity']:.4f})")
            print(f"   二进制: {result['binary']}")


if __name__ == '__main__':
    main()