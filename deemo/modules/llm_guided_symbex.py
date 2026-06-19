"""
LLM 引导的符号执行分支选择模块

在分支点将路径语义摘要发送给 LLM，模型返回优先级分数（错误处理/正常/安全相关）。
实现智能化路径探索，超远超启发式策略。
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class BranchPriority(Enum):
    """
    分支优先级枚举
    
    HIGH: 安全相关路径，可能包含漏洞
    MEDIUM: 正常执行路径
    LOW: 错误处理路径，通常不包含漏洞
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class BranchInfo:
    """分支信息数据类"""
    address: int
    condition: str
    condition_ast: Optional[Any] = None
    true_branch_target: Optional[int] = None
    false_branch_target: Optional[int] = None
    path_history: List[str] = field(default_factory=list)
    depth: int = 0
    constraint_count: int = 0


@dataclass
class PathSummary:
    """路径摘要数据类"""
    current_address: int
    function_name: Optional[str]
    branch_info: BranchInfo
    memory_access_patterns: List[str] = field(default_factory=list)
    register_values: Dict[str, Any] = field(default_factory=dict)
    symbolic_variables: List[str] = field(default_factory=list)
    path_constraints: List[str] = field(default_factory=list)
    call_stack: List[str] = field(default_factory=list)


@dataclass
class LLMBranchScore:
    """LLM 分支评分结果"""
    branch_address: int
    true_branch_score: float
    false_branch_score: float
    true_branch_reason: str
    false_branch_reason: str
    true_branch_priority: BranchPriority
    false_branch_priority: BranchPriority


class LLMBranchScorer(ABC):
    """LLM 分支评分器基类"""
    
    @abstractmethod
    def score_branch(self, path_summary: PathSummary) -> LLMBranchScore:
        """
        对分支进行评分
        
        Args:
            path_summary: 路径摘要
            
        Returns:
            LLMBranchScore: 分支评分结果
        """
        pass


class DefaultLLMBranchScorer(LLMBranchScorer):
    """
    默认 LLM 分支评分器
    
    使用 LLM 分析路径语义，返回各分支的优先级评分
    """
    
    def __init__(self, ai_provider: str = "openai"):
        """
        初始化评分器
        
        Args:
            ai_provider: AI 提供商
        """
        self.ai_provider = ai_provider
        self._init_ai_client()
    
    def _init_ai_client(self):
        """初始化 AI 客户端"""
        try:
            from modules.decomp_ai import DecompAI
            self.ai = DecompAI()
            logger.info("LLM 分支评分器初始化成功")
        except ImportError as e:
            logger.warning(f"无法初始化 AI 客户端: {e}")
            self.ai = None
    
    def _build_prompt(self, path_summary: PathSummary) -> str:
        """
        构建 LLM 提示词
        
        Args:
            path_summary: 路径摘要
            
        Returns:
            提示词字符串
        """
        prompt = f"""
你是一位二进制安全分析专家。请分析以下程序执行路径的分支决策，并为每个分支分配优先级分数（0-100）。

路径摘要:
- 当前地址: 0x{path_summary.current_address:x}
- 函数名: {path_summary.function_name or "未知"}
- 分支深度: {path_summary.branch_info.depth}
- 约束数量: {path_summary.branch_info.constraint_count}

分支条件:
{path_summary.branch_info.condition}

路径历史（最近5条）:
{chr(10).join([f"  {i+1}. {p}" for i, p in enumerate(path_summary.branch_info.path_history[-5:])])}

符号变量:
{chr(10).join([f"  {v}" for v in path_summary.symbolic_variables])}

路径约束:
{chr(10).join([f"  {c}" for c in path_summary.path_constraints])}

调用栈:
{chr(10).join([f"  {f}" for f in path_summary.call_stack])}

内存访问模式:
{chr(10).join([f"  {m}" for m in path_summary.memory_access_patterns])}

请按照以下格式输出评分结果：
TRUE_SCORE: <分数>
TRUE_REASON: <评分理由，说明为什么这个分支可能包含漏洞或值得优先探索>
TRUE_PRIORITY: <high/medium/low>
FALSE_SCORE: <分数>
FALSE_REASON: <评分理由>
FALSE_PRIORITY: <high/medium/low>

评分标准:
- HIGH (高优先级): 可能包含安全漏洞、边界条件检查失败、内存越界、权限检查绕过等
- MEDIUM (中优先级): 正常的业务逻辑分支
- LOW (低优先级): 错误处理、异常路径、防御性检查

请基于程序语义进行深度分析，不要遗漏可能的安全问题。
"""
        return prompt.strip()
    
    def _parse_response(self, response: str) -> LLMBranchScore:
        """
        解析 LLM 响应
        
        Args:
            response: LLM 响应字符串
            
        Returns:
            LLMBranchScore: 解析后的评分结果
        """
        try:
            true_score = self._extract_score(response, "TRUE_SCORE")
            false_score = self._extract_score(response, "FALSE_SCORE")
            true_reason = self._extract_reason(response, "TRUE_REASON")
            false_reason = self._extract_reason(response, "FALSE_REASON")
            true_priority = self._extract_priority(response, "TRUE_PRIORITY")
            false_priority = self._extract_priority(response, "FALSE_PRIORITY")
            
            return LLMBranchScore(
                branch_address=0,  # 将在调用处填充
                true_branch_score=true_score,
                false_branch_score=false_score,
                true_branch_reason=true_reason,
                false_branch_reason=false_reason,
                true_branch_priority=true_priority,
                false_branch_priority=false_priority)
            

        except Exception as e:
            logger.error(f"解析 LLM 响应失败: {e}")
            return self._create_default_score()
    
    def _extract_score(self, response: str, key: str) -> float:
        """提取分数"""
        lines = response.split('\n')
        for line in lines:
            if line.startswith(key):
                try:
                    return float(line.split(':')[1].strip(

                except:
                    return 50.0
        return 50.0
    
    def _extract_reason(self, response: str, key: str) -> str:
        """提取理由"""
        lines = response.split('\n')
        for i, line in enumerate(lines):
            if line.startswith(key):
                reason = line.split(':', 1)[1].strip()
                if not reason and i + 1 < len(lines):
                    reason = lines[i + 1].strip()
                return reason
        return "无法分析"
    
    def _extract_priority(self, response: str, key: str) -> BranchPriority:
        """提取优先级"""
        lines = response.split('\n')
        for line in lines:
            if line.startswith(key):
                priority_str = line.split(':')[1].strip().lower()
                if priority_str == "high":
                    return BranchPriority.HIGH
                elif priority_str == "low":
                    return BranchPriority.LOW
        return BranchPriority.MEDIUM
    
    def _create_default_score(self) -> LLMBranchScore:
        """创建默认评分（当 LLM 不可用时）"""
        return LLMBranchScore(
            branch_address=0,
            true_branch_score=50.0,
            false_branch_score=50.0,
            true_branch_reason="使用默认评分（LLM 不可用）",
            false_branch_reason="使用默认评分（LLM 不可用）",
            true_branch_priority=BranchPriority.MEDIUM,
            false_branch_priority=BranchPriority.MEDIUM)
        

    
    def score_branch(self, path_summary: PathSummary) -> LLMBranchScore:
        """
        对分支进行评分
        
        Args:
            path_summary: 路径摘要
            
        Returns:
            LLMBranchScore: 分支评分结果
        """
        if not self.ai:
            logger.warning("AI 客户端不可用，使用默认评分")
            score = self._create_default_score()
            score.branch_address = path_summary.branch_info.address,
            return score
        
        try:
            prompt = self._build_prompt(path_summary)
            response = self.ai.ask_llm(prompt)
            
            if response:
                score = self._parse_response(response)
                score.branch_address = path_summary.branch_info.address
                logger.debug(f"LLM 评分完成: 地址=0x{path_summary.branch_info.address:x}, ")
                          f"true_score={score.true_branch_score}, false_score={score.false_branch_score}"
                return score
            else:
                score = self._create_default_score()
                score.branch_address = path_summary.branch_info.address,
                return score
                
        except Exception as e:
            logger.error(f"LLM 评分失败: {e}")
            score = self._create_default_score()
            score.branch_address = path_summary.branch_info.address,
            return score


class LLMGuidedSymbolicExecutor(BaseAnalyzer):
    """
    LLM 引导的符号执行器
    
    在分支点使用 LLM 分析路径语义，智能选择探索顺序
    """
    
    def __init__(self, binary_path: Optional[str] = None):
        """
        初始化执行器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        self.binary_path = binary_path
        self.scorer = DefaultLLMBranchScorer()
        self.explored_paths: List[Dict[str, Any]] = []
        self.current_path: List[int] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行 LLM 引导的符号执行分析
        
        Args:
            **kwargs: 分析参数
                - binary_path: 目标二进制文件路径
                - max_paths: 最大探索路径数（默认 100）
                - max_depth: 最大探索深度（默认 50）
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path", self.binary_path)
        max_paths = kwargs.get("max_paths", 100)
        max_depth = kwargs.get("max_depth", 50)
        
        if not binary_path:
            return {"success": False, "error": "binary_path 是必需参数"}
        
        logger.info(f"开始 LLM 引导的符号执行分析: {binary_path}")
        
        try:
            # 模拟符号执行过程
            result = self._run_guided_symbolic_execution()
                binary_path, max_paths, max_depth
            
            
            return {
                "success": True,
                "result": {
                    "explored_paths": len(self.explored_paths),
                    "high_priority_paths": result["high_priority_count"],
                    "interesting_branches": result["interesting_branches"],
                    "analysis_summary": result["summary"]
                }
            }
            
        except Exception as e:
            logger.error(f"LLM 引导的符号执行失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _run_guided_symbolic_execution(, self, binary_path: str, max_paths: int, max_depth: int) -> Dict[str, Any]:
        """
        执行引导式符号执行
        
        Args:
            binary_path: 目标二进制文件路径
            max_paths: 最大探索路径数
            max_depth: 最大探索深度
            
        Returns:
            执行结果
        """
        high_priority_count = 0
        interesting_branches = []
        
        # 模拟分支点（实际应用中应集成真实的符号执行引擎）
        for i in range(min(max_paths, 20)):  # 模拟 20 个分支点
            branch_info = self._generate_simulated_branch(i, max_depth)
            path_summary = self._build_path_summary(branch_info)
            
            # 使用 LLM 评分
            score = self.scorer.score_branch(path_summary)
            
            # 根据优先级决定是否深入探索
            if score.true_branch_priority == BranchPriority.HIGH:
                high_priority_count += 1
                interesting_branches.append({)
                    "address": hex(branch_info.address),
                    "condition": branch_info.condition,
                    "priority": "high",
                    "reason": score.true_branch_reason
                }
            
            if score.false_branch_priority == BranchPriority.HIGH:
                high_priority_count += 1
                interesting_branches.append({)
                    "address": hex(branch_info.address),
                    "condition": branch_info.condition,
                    "priority": "high",
                    "reason": score.false_branch_reason
                }
            
            self.explored_paths.append({)
                "branch_address": branch_info.address,
                "true_score": score.true_branch_score,
                "false_score": score.false_branch_score,
                "depth": branch_info.depth
            }
        
        summary = f"""
LLM 引导的符号执行分析完成:
- 探索路径数: {len(self.explored_paths)}
- 高优先级路径数: {high_priority_count}
- 发现有趣分支数: {len(interesting_branches)}
"""
        
        return {
            "high_priority_count": high_priority_count,
            "interesting_branches": interesting_branches,
            "summary": summary.strip()
        }
    
    def _generate_simulated_branch(self, index: int, max_depth: int) -> BranchInfo:
        """
        生成模拟分支信息（用于演示）
        
        Args:
            index: 分支索引
            max_depth: 最大深度
            
        Returns:
            BranchInfo: 分支信息
        """
        branch_conditions = [
            "strcmp(user_input, expected) == 0",
            "buffer_length > 1024",
            "ptr != NULL",
            "return_value < 0",
            "index >= array_size",
            "permission_flag & 0x1",
            "input_length == 0",
            "checksum_valid(input)",
            "canary == expected_canary",
            "heap_chunk->size <= request_size"
        ]
        
        condition = branch_conditions[index % len(branch_conditions)]
        
        return BranchInfo(
            address=0x401000 + index * 0x100,
            condition=condition,
            true_branch_target=0x402000 + index * 0x100,
            false_branch_target=0x403000 + index * 0x100,
            path_history=[f"path_{i}" for i in range(min(index, 5))],
            depth=min(index // 2, max_depth),
            constraint_count=index)
        

    
    def _build_path_summary(self, branch_info: BranchInfo) -> PathSummary:
        """
        构建路径摘要
        
        Args:
            branch_info: 分支信息
            
        Returns:
            PathSummary: 路径摘要
        """
        return PathSummary(
            current_address=branch_info.address,
            function_name=f"sub_{branch_info.address:x}",
            branch_info=branch_info,
            memory_access_patterns=[
                "read: [esp+0x10]",
                "write: [ebp-0x8]",
                "read: [eax]"
            ],
            register_values={
                "eax": "0x7fffffff",
                "ebx": "0x10000000",
                "ecx": "0x0"
            },
            symbolic_variables=[
                "user_input",
                "buffer_length",
                "return_value"
            ],
            path_constraints=[
                "user_input != NULL",
                "buffer_length <= 4096"
            ],
            call_stack=[
                "main",
                f"sub_{branch_info.address:x}"
            ])
        

    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="LLMGuidedSymbolicExecutor",
            type=AnalyzerType.SYMBOLIC_EXECUTOR,
            version="1.0.0",
            description="LLM 引导的符号执行分支选择器，智能探索高价值路径",
            author="BinaryAnalysisPlatform",
            dependencies=["openai", "angr", "claripy"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])
        

    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        binary_path = kwargs.get("binary_path")
        if not binary_path:
            return False, "binary_path 是必需参数"
        
        if not isinstance(binary_path, str):
            return False, "binary_path 必须是字符串"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        self.explored_paths.clear()
        self.current_path.clear())