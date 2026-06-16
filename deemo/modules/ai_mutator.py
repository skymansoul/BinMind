"""
AI驱动的模糊测试智能变异模块

使用本地小型LLM或n-gram模型学习有效种子输入的语法，
在AFL++自定义变异阶段插入语义保持的变异操作，提升结构化协议覆盖率。

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Callable
from collections import Counter, defaultdict

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.fuzz_integration import FuzzManager

logger = logging.getLogger(__name__)


class MutationStrategy(ABC):
    """变异策略基类"""
    
    @abstractmethod
    def mutate(self, seed: bytes, iteration: int) -> bytes:
        """
        对种子进行变异
        
        Args:
            seed: 原始种子数据
            iteration: 当前迭代次数
            
        Returns:
            变异后的种子数据
        """
        pass
    
    @abstractmethod
    def train(self, seeds: List[bytes]) -> None:
        """
        使用种子数据训练模型
        
        Args:
            seeds: 种子数据列表
        """
        pass


@dataclass
class GrammarRule:
    """语法规则"""
    pattern: str
    replacements: List[str]
    probability: float = 0.5


@dataclass
class NGramModel:
    """n-gram语言模型"""
    n: int = 3
    transitions: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    vocabulary: set = field(default_factory=set)
    
    def train(self, data: bytes) -> None:
        """训练n-gram模型"""
        s = data.decode('latin-1', errors='replace')
        self.vocabulary.update(s)
        
        for i in range(len(s) - self.n + 1):
            prefix = s[i:i+self.n]
            if i + self.n < len(s):
                next_char = s[i+self.n]
                self.transitions[prefix][next_char] += 1
    
    def generate(self, prefix: str, length: int = 10) -> str:
        """根据前缀生成后续字符"""
        result = prefix
        current = prefix[-self.n:] if len(prefix) >= self.n else prefix.ljust(self.n, '\x00')
        
        for _ in range(length):
            if current in self.transitions:
                counter = self.transitions[current]
                total = sum(counter.values())
                if total > 0:
                    rand = random.randint(0, total - 1)
                    cumulative = 0
                    for char, count in counter.items():
                        cumulative += count
                        if rand < cumulative:
                            result += char
                            current = (current + char)[-self.n:]
                            continue
            break
        
        return result


class NgramMutator(MutationStrategy):
    """基于n-gram模型的变异器"""
    
    def __init__(self, n: int = 3):
        self.model = NGramModel(n=n)
        self.min_length = 1
        self.max_length = 1024
    
    def train(self, seeds: List[bytes]) -> None:
        """训练n-gram模型"""
        logger.info(f"训练n-gram模型，种子数量: {len(seeds)}")
        for seed in seeds:
            self.model.train(seed)
        logger.info(f"训练完成，词汇表大小: {len(self.model.vocabulary)}")
    
    def mutate(self, seed: bytes, iteration: int) -> bytes:
        """使用n-gram模型进行变异"""
        if not seed:
            return seed
        
        s = seed.decode('latin-1', errors='replace')
        mutated = list(s)
        
        # 根据迭代次数调整变异强度
        mutation_rate = min(0.3, 0.1 + (iteration % 100) / 500)
        
        # 随机选择变异位置
        num_mutations = max(1, int(len(mutated) * mutation_rate))
        
        for _ in range(num_mutations):
            pos = random.randint(0, len(mutated) - 1)
            
            # 使用n-gram模型生成替换字符
            context = s[max(0, pos-2):pos]
            generated = self.model.generate(context, length=1)
            
            if generated and len(generated) > len(context):
                mutated[pos] = generated[-1]
            else:
                # 回退到随机字符替换
                mutated[pos] = chr(random.randint(0, 255))
        
        return ''.join(mutated).encode('latin-1')


class GrammarBasedMutator(MutationStrategy):
    """基于语法规则的变异器"""
    
    def __init__(self):
        self.grammar_rules: List[GrammarRule] = []
        self.protocol_patterns = [
            # HTTP协议
            GrammarRule(r'GET|POST|PUT|DELETE', ['GET', 'POST', 'PUT', 'DELETE'], 0.3),
            GrammarRule(r'HTTP/\d\.\d', ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0'], 0.2),
            # 常见协议字段
            GrammarRule(r'Host: [^\r\n]+', ['Host: example.com', 'Host: localhost:8080'], 0.2),
            GrammarRule(r'Content-Length: \d+', ['Content-Length: 1024', 'Content-Length: 0'], 0.1),
            # 数字变异
            GrammarRule(r'\d+', ['0', '1', '255', '65535', '4294967295'], 0.3),
            # 十六进制
            GrammarRule(r'0x[0-9a-fA-F]+', ['0x0', '0x7fffffff', '0xffffffff'], 0.2),
        ]
    
    def train(self, seeds: List[bytes]) -> None:
        """从种子中学习语法规则"""
        logger.info(f"学习语法规则，种子数量: {len(seeds)}")
        
        # 统计常见模式
        pattern_counts = Counter()
        
        for seed in seeds:
            s = seed.decode('latin-1', errors='replace')
            
            # 检测URL模式
            urls = re.findall(r'https?://[^\s]+', s)
            for url in urls:
                pattern_counts['url'] += 1
            
            # 检测数字模式
            nums = re.findall(r'\b\d{4,}\b', s)
            for num in nums:
                pattern_counts['large_number'] += 1
            
            # 检测十六进制模式
            hex_vals = re.findall(r'0x[0-9a-fA-F]{8,}', s)
            for hex_val in hex_vals:
                pattern_counts['hex_value'] += 1
        
        logger.info(f"检测到的模式: {dict(pattern_counts)}")
        
        # 根据检测结果添加自定义规则
        if pattern_counts.get('url', 0) > 3:
            self.grammar_rules.append(
                GrammarRule(r'https?://[^\s]+', ['http://localhost/', 'https://example.com/api'], 0.15)
            )
    
    def mutate(self, seed: bytes, iteration: int) -> bytes:
        """应用语法规则进行变异"""
        s = seed.decode('latin-1', errors='replace')
        mutated = s
        
        # 应用内置协议模式
        for rule in self.protocol_patterns:
            if random.random() < rule.probability:
                if re.search(rule.pattern, mutated):
                    replacement = random.choice(rule.replacements)
                    mutated = re.sub(rule.pattern, replacement, mutated)
        
        # 应用学习到的规则
        for rule in self.grammar_rules:
            if random.random() < rule.probability:
                mutated = re.sub(rule.pattern, random.choice(rule.replacements), mutated)
        
        return mutated.encode('latin-1')


class HybridMutator(MutationStrategy):
    """混合变异器 - 结合n-gram和语法规则"""
    
    def __init__(self):
        self.ngram_mutator = NgramMutator(n=3)
        self.grammar_mutator = GrammarBasedMutator()
        self.strategy_weights = {
            'ngram': 0.5,
            'grammar': 0.3,
            'random': 0.2
        }
    
    def train(self, seeds: List[bytes]) -> None:
        """训练所有子变异器"""
        self.ngram_mutator.train(seeds)
        self.grammar_mutator.train(seeds)
    
    def mutate(self, seed: bytes, iteration: int) -> bytes:
        """根据权重选择变异策略"""
        rand = random.random()
        cumulative = 0
        
        for strategy, weight in self.strategy_weights.items():
            cumulative += weight
            if rand < cumulative:
                if strategy == 'ngram':
                    return self.ngram_mutator.mutate(seed, iteration)
                elif strategy == 'grammar':
                    return self.grammar_mutator.mutate(seed, iteration)
                else:
                    return self._random_mutate(seed)
        
        return self._random_mutate(seed)
    
    def _random_mutate(self, seed: bytes) -> bytes:
        """简单随机变异"""
        if not seed:
            return seed
        
        mutated = bytearray(seed)
        pos = random.randint(0, len(mutated) - 1)
        mutated[pos] = random.randint(0, 255)
        return bytes(mutated)


class AIMutator(BaseAnalyzer):
    """
    AI驱动的模糊测试智能变异分析器
    
    核心功能：
    1. 从有效种子中学习输入语法模式
    2. 使用n-gram模型生成语义保持的变异
    3. 支持协议感知的变异策略
    4. 对接AFL++自定义变异阶段
    """
    
    def __init__(self):
        self.mutator: Optional[MutationStrategy] = None
        self.seeds: List[bytes] = []
        self.iteration = 0
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行AI变异分析
        
        Args:
            **kwargs: 分析参数
                - seeds: List[bytes] - 种子数据列表
                - seed: bytes - 单种子（用于变异）
                - mode: str - 模式 'train' 或 'mutate'
                - strategy: str - 变异策略 'ngram', 'grammar', 'hybrid'
        
        Returns:
            分析结果字典，包含变异后的数据或训练状态
        """
        mode = kwargs.get('mode', 'mutate')
        strategy = kwargs.get('strategy', 'hybrid')
        
        if mode == 'train':
            seeds = kwargs.get('seeds', [])
            return self._train(seeds, strategy)
        elif mode == 'mutate':
            seed = kwargs.get('seed', b'')
            return self._mutate(seed)
        else:
            return {'success': False, 'error': f"未知模式: {mode}"}
    
    def _train(self, seeds: List[bytes], strategy: str) -> Dict[str, Any]:
        """训练变异模型"""
        try:
            logger.info(f"开始训练AI变异器，策略: {strategy}")
            
            if strategy == 'ngram':
                self.mutator = NgramMutator()
            elif strategy == 'grammar':
                self.mutator = GrammarBasedMutator()
            elif strategy == 'hybrid':
                self.mutator = HybridMutator()
            else:
                return {'success': False, 'error': f"未知策略: {strategy}"}
            
            self.seeds = seeds
            self.mutator.train(seeds)
            
            return {
                'success': True,
                'message': f"训练完成，种子数量: {len(seeds)}",
                'strategy': strategy,
                'seed_count': len(seeds)
            }
        except Exception as e:
            logger.error(f"训练失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def _mutate(self, seed: bytes) -> Dict[str, Any]:
        """执行变异操作"""
        try:
            if not self.mutator:
                # 如果没有训练过，使用默认的混合变异器
                self.mutator = HybridMutator()
                if self.seeds:
                    self.mutator.train(self.seeds)
            
            mutated = self.mutator.mutate(seed, self.iteration)
            self.iteration += 1
            
            return {
                'success': True,
                'original_length': len(seed),
                'mutated_length': len(mutated),
                'mutated_data': mutated.hex(),
                'iteration': self.iteration
            }
        except Exception as e:
            logger.error(f"变异失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def set_seeds(self, seeds: List[bytes]) -> None:
        """设置种子数据"""
        self.seeds = seeds
    
    def get_mutated_seed(self, seed: bytes) -> bytes:
        """获取单个变异后的种子"""
        result = self._mutate(seed)
        if result['success']:
            return bytes.fromhex(result['mutated_data'])
        return seed
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="AIMutator",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="AI驱动的模糊测试智能变异模块，使用n-gram模型学习输入语法并执行语义保持的变异",
            author="BinaryAnalysisPlatform",
            dependencies=["random", "re"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"]
        )


class AFLIntegrationMutator:
    """AFL++自定义变异阶段集成器"""
    
    def __init__(self, fuzz_manager: FuzzManager):
        self.fuzz_manager = fuzz_manager
        self.ai_mutator = AIMutator()
        self.enabled = False
    
    def enable(self) -> None:
        """启用AI变异器"""
        self.enabled = True
        logger.info("AI变异器已启用")
    
    def disable(self) -> None:
        """禁用AI变异器"""
        self.enabled = False
    
    def train_on_corpus(self, corpus_dir: str) -> bool:
        """从语料库训练模型"""
        import os
        
        seeds = []
        try:
            for filename in os.listdir(corpus_dir):
                filepath = os.path.join(corpus_dir, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'rb') as f:
                        seeds.append(f.read())
            
            if seeds:
                self.ai_mutator._train(seeds, 'hybrid')
                logger.info(f"从语料库训练完成，种子数量: {len(seeds)}")
                return True
            return False
        except Exception as e:
            logger.error(f"训练失败: {e}")
            return False
    
    def custom_mutate(self, seed: bytes) -> bytes:
        """AFL++自定义变异钩子"""
        if not self.enabled:
            return seed
        
        return self.ai_mutator.get_mutated_seed(seed)


def create_ai_mutator() -> AIMutator:
    """创建AI变异器实例"""
    return AIMutator()


def integrate_with_afl(fuzz_manager: FuzzManager) -> AFLIntegrationMutator:
    """与AFL++集成"""
    return AFLIntegrationMutator(fuzz_manager)