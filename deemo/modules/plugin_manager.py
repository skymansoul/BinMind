import logging
import importlib
import os
import sys
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Type, Callable, Tuple
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class AnalyzerType(Enum):
    """分析器类型枚举"""
    DECOMPILER = "decompiler"
    STATIC_ANALYZER = "static_analyzer"
    SYMBOLIC_EXECUTOR = "symbolic_executor"
    VULNERABILITY_DETECTOR = "vulnerability_detector"
    EXPLOIT_GENERATOR = "exploit_generator"
    REPORT_GENERATOR = "report_generator"
    DYNAMIC_ANALYZER = "dynamic_analyzer"
    UTILITY = "utility"
    OUTPUT = "output"
    FORMAL_VERIFICATION = "formal_verification"
    OTHER = "other"


@dataclass
class AnalyzerMetadata:
    """分析器元数据"""
    name: str
    type: AnalyzerType
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    dependencies: List[str] = field(default_factory=list)
    supported_platforms: List[str] = field(default_factory=list)
    config_schema: Optional[Dict[str, Any]] = None


class BaseAnalyzer(ABC):
    """
    分析器基类 - 所有分析模块必须继承此类
    
    统一 analyze() 方法的输入输出规范
    """
    
    @abstractmethod
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行分析任务
        
        Args:
            **kwargs: 分析参数
            
        Returns:
            分析结果字典，必须包含 'success' 键
        """
        pass
    
    @classmethod
    @abstractmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """
        获取分析器元数据
        
        Returns:
            AnalyzerMetadata 对象
        """
        pass
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """
        验证输入参数
        
        Args:
            **kwargs: 输入参数
            
        Returns:
            (是否有效, 错误信息)
        """
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        pass


class PluginManager:
    """
    插件管理器
    
    负责：
    1. 加载内置分析器
    2. 加载外部插件（通过 entry_points 或配置文件）
    3. 管理分析器生命周期
    """
    
    def __init__(self, plugins_dir: str = "plugins", config_file: Optional[str] = None):
        """
        初始化插件管理器
        
        Args:
            plugins_dir: 外部插件目录
            config_file: 插件配置文件路径
        """
        self.plugins_dir = Path(plugins_dir)
        self.analyzers: Dict[str, Type[BaseAnalyzer]] = {}
        self.loaded_plugins: Dict[str, Any] = {}
        self.config_file = config_file
        
        self._load_builtin_analyzers()
        self._load_external_plugins()
    
    def _load_builtin_analyzers(self) -> None:
        """加载内置分析器"""
        builtin_analyzers = {
            "decompiler": self._create_decompiler_analyzer,
            "static_analyzer": self._create_static_analyzer,
            "symbolic_executor": self._create_symbolic_executor,
            "vulnerability_detector": self._create_vuln_detector,
            "exploit_generator": self._create_exploit_generator,
            "report_generator": self._create_report_generator,
            # AI/LLM 集成模块
            "semantic_search": self._create_semantic_search_analyzer,
            "path_prioritizer": self._create_path_prioritizer_analyzer,
            "root_cause_analyzer": self._create_root_cause_analyzer,
            "rl_vuln_agent": self._create_rl_vuln_agent_analyzer,
            # 新型表示学习与相似性分析模块
            "multi_view_gnn": self._create_multi_view_gnn_analyzer,
            "distilled_vuln_detector": self._create_distilled_vuln_detector_analyzer,
            "trajectory_anomaly": self._create_trajectory_anomaly_analyzer,
        }
        
        for name, creator in builtin_analyzers.items():
            try:
                analyzer_class = creator()
                if analyzer_class:
                    self.analyzers[name] = analyzer_class
                    logger.info(f"加载内置分析器: {name}")
            except Exception as e:
                logger.warning(f"加载内置分析器 {name} 失败: {e}")
    
    def _create_decompiler_analyzer(self) -> Type[BaseAnalyzer]:
        """创建反编译器分析器包装类"""
        from modules.decomp_ai import DecompAI
        
        class DecompilerAnalyzer(BaseAnalyzer):
            def __init__(self):
                self.decompiler = DecompAI()
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                binary_path = kwargs.get("binary_path")
                if not binary_path:
                    return {"success": False, "error": "binary_path 是必需参数"}
                
                try:
                    result = self.decompiler.decompile(binary_path)
                    return {"success": True, "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="Decompiler",
                    type=AnalyzerType.DECOMPILER,
                    version="1.0.0",
                    description="二进制反编译器，支持多种架构",
                    author="BinaryAnalysisPlatform",
                    supported_platforms=["x86", "x86_64", "arm", "arm64"]
                )
        
        return DecompilerAnalyzer
    
    def _create_static_analyzer(self) -> Type[BaseAnalyzer]:
        """创建静态分析器包装类"""
        from modules.static_analysis import StaticDataFlowAnalyzer
        
        class StaticAnalyzer(BaseAnalyzer):
            def analyze(self, **kwargs) -> Dict[str, Any]:
                binary_path = kwargs.get("binary_path")
                function_name = kwargs.get("function_name", "main")
                
                if not binary_path:
                    return {"success": False, "error": "binary_path 是必需参数"}
                
                try:
                    analyzer = StaticDataFlowAnalyzer(binary_path)
                    result = analyzer.analyze_function(function_name)
                    return {"success": True, "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="StaticAnalyzer",
                    type=AnalyzerType.STATIC_ANALYZER,
                    version="1.0.0",
                    description="静态数据流分析器，检测潜在漏洞",
                    author="BinaryAnalysisPlatform",
                    supported_platforms=["x86", "x86_64", "arm", "arm64", "mips"]
                )
        
        return StaticAnalyzer
    
    def _create_symbolic_executor(self) -> Type[BaseAnalyzer]:
        """创建符号执行器包装类"""
        from modules.symbolic_exe import SymbolicExecutor
        
        class SymbolicExecutorAnalyzer(BaseAnalyzer):
            def analyze(self, **kwargs) -> Dict[str, Any]:
                binary_path = kwargs.get("binary_path")
                
                if not binary_path:
                    return {"success": False, "error": "binary_path 是必需参数"}
                
                try:
                    executor = SymbolicExecutor(binary_path)
                    result = executor.comprehensive_analysis()
                    return {"success": True, "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="SymbolicExecutor",
                    type=AnalyzerType.SYMBOLIC_EXECUTOR,
                    version="1.0.0",
                    description="符号执行引擎，探索程序路径",
                    author="BinaryAnalysisPlatform",
                    dependencies=["angr", "claripy"],
                    supported_platforms=["x86", "x86_64", "arm", "arm64"]
                )
        
        return SymbolicExecutorAnalyzer
    
    def _create_vuln_detector(self) -> Type[BaseAnalyzer]:
        """创建漏洞检测器包装类"""
        from modules.crash_analysis import CrashAnalyzer
        
        class VulnerabilityDetector(BaseAnalyzer):
            def analyze(self, **kwargs) -> Dict[str, Any]:
                binary_path = kwargs.get("binary_path")
                
                if not binary_path:
                    return {"success": False, "error": "binary_path 是必需参数"}
                
                try:
                    analyzer = CrashAnalyzer(binary_path)
                    result = analyzer.analyze()
                    return {"success": True, "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="VulnerabilityDetector",
                    type=AnalyzerType.VULNERABILITY_DETECTOR,
                    version="1.0.0",
                    description="漏洞检测器，识别安全漏洞",
                    author="BinaryAnalysisPlatform",
                    supported_platforms=["x86", "x86_64", "arm", "arm64"]
                )
        
        return VulnerabilityDetector
    
    def _create_exploit_generator(self) -> Type[BaseAnalyzer]:
        """创建利用生成器包装类"""
        from modules.exploit_gen import ExploitGenerator
        
        class ExploitGeneratorAnalyzer(BaseAnalyzer):
            def analyze(self, **kwargs) -> Dict[str, Any]:
                binary_path = kwargs.get("binary_path")
                
                if not binary_path:
                    return {"success": False, "error": "binary_path 是必需参数"}
                
                try:
                    generator = ExploitGenerator(binary_path)
                    result = generator.generate()
                    return {"success": True, "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="ExploitGenerator",
                    type=AnalyzerType.EXPLOIT_GENERATOR,
                    version="1.0.0",
                    description="漏洞利用生成器",
                    author="BinaryAnalysisPlatform",
                    supported_platforms=["x86", "x86_64"]
                )
        
        return ExploitGeneratorAnalyzer
    
    def _create_report_generator(self) -> Type[BaseAnalyzer]:
        """创建报告生成器包装类"""
        from modules.report import ReportGenerator
        
        class ReportGeneratorAnalyzer(BaseAnalyzer):
            def analyze(self, **kwargs) -> Dict[str, Any]:
                binary_path = kwargs.get("binary_path")
                analysis_results = kwargs.get("analysis_results", {})
                
                if not binary_path:
                    return {"success": False, "error": "binary_path 是必需参数"}
                
                try:
                    generator = ReportGenerator(binary_path)
                    result = generator.generate(analysis_results)
                    return {"success": True, "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="ReportGenerator",
                    type=AnalyzerType.REPORT_GENERATOR,
                    version="1.0.0",
                    description="分析报告生成器",
                    author="BinaryAnalysisPlatform",
                    supported_platforms=["all"]
                )
        
        return ReportGeneratorAnalyzer
    
    def _create_semantic_search_analyzer(self) -> Type[BaseAnalyzer]:
        """创建LLM语义搜索分析器包装类"""
        from modules.semantic_search_llm import SemanticSearchLLM
        
        class SemanticSearchAnalyzer(BaseAnalyzer):
            def __init__(self):
                self.searcher = SemanticSearchLLM(llm_type="openai")
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                query = kwargs.get("query")
                functions = kwargs.get("functions", [])
                mode = kwargs.get("mode", "llm")
                
                try:
                    if functions:
                        self.searcher.build_index(functions)
                    
                    result = self.searcher.search(query, mode=mode)
                    return {"success": True, "result": result.__dict__}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="SemanticSearch",
                    type=AnalyzerType.OTHER,
                    version="1.0.0",
                    description="LLM驱动的二进制摘要与语义搜索，支持自然语言查询函数定位",
                    author="BinaryAnalysisPlatform",
                    dependencies=["openai", "numpy", "scikit-learn"],
                    supported_platforms=["all"]
                )
        
        return SemanticSearchAnalyzer
    
    def _create_path_prioritizer_analyzer(self) -> Type[BaseAnalyzer]:
        """创建AI路径优先级分析器包装类"""
        from modules.ai_path_prioritizer import AIPathPrioritizer
        
        class PathPrioritizerAnalyzer(BaseAnalyzer):
            def __init__(self):
                self.prioritizer = AIPathPrioritizer(strategy="hybrid")
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                paths = kwargs.get("paths", [])
                top_k = kwargs.get("top_k", None)
                
                try:
                    result = self.prioritizer.prioritize(paths, top_k)
                    return {"success": True, "result": result.__dict__}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="PathPrioritizer",
                    type=AnalyzerType.SYMBOLIC_EXECUTOR,
                    version="1.0.0",
                    description="AI辅助的符号执行路径优先级，缓解路径爆炸问题",
                    author="BinaryAnalysisPlatform",
                    dependencies=["openai", "numpy"],
                    supported_platforms=["all"]
                )
        
        return PathPrioritizerAnalyzer
    
    def _create_root_cause_analyzer(self) -> Type[BaseAnalyzer]:
        """创建自动化漏洞根因分析器包装类"""
        from modules.auto_root_cause import AutoRootCauseAnalyzer
        
        class RootCauseAnalyzer(BaseAnalyzer):
            def __init__(self):
                self.analyzer = AutoRootCauseAnalyzer(analyzer_type="llm")
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                vulnerability_type = kwargs.get("vulnerability_type")
                function_name = kwargs.get("function_name")
                pseudocode = kwargs.get("pseudocode")
                function_address = kwargs.get("function_address", 0)
                binary_path = kwargs.get("binary_path", "")
                
                if not vulnerability_type or not function_name or not pseudocode:
                    return {"success": False, "error": "缺少必需参数"}
                
                try:
                    result = self.analyzer.analyze_vulnerability(
                        vulnerability_type=vulnerability_type,
                        function_name=function_name,
                        pseudocode=pseudocode,
                        function_address=function_address,
                        binary_path=binary_path
                    )
                    return {"success": True, "result": result.__dict__}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="RootCauseAnalyzer",
                    type=AnalyzerType.VULNERABILITY_DETECTOR,
                    version="1.0.0",
                    description="自动化漏洞根因解释，结合CWE生成CVE级分析报告",
                    author="BinaryAnalysisPlatform",
                    dependencies=["openai"],
                    supported_platforms=["all"]
                )
        
        return RootCauseAnalyzer
    
    def _create_rl_vuln_agent_analyzer(self) -> Type[BaseAnalyzer]:
        """创建强化学习漏洞挖掘代理分析器包装类"""
        from modules.rl_vuln_agent import RLVulnAgent
        
        class RLVulnAgentAnalyzer(BaseAnalyzer):
            def __init__(self):
                self.agent = None
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                target_binary = kwargs.get("target_binary", "")
                agent_type = kwargs.get("agent_type", "dqn")
                episodes = kwargs.get("episodes", 100)
                max_steps = kwargs.get("max_steps", 50)
                initial_input = kwargs.get("initial_input", None)
                
                try:
                    self.agent = RLVulnAgent(target_binary=target_binary, agent_type=agent_type)
                    result = self.agent.train(episodes=episodes, max_steps=max_steps, 
                                              initial_input=initial_input, verbose=False)
                    return {"success": True, "result": result.__dict__}
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            def cleanup(self) -> None:
                if self.agent:
                    self.agent = None
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="RLVulnAgent",
                    type=AnalyzerType.VULNERABILITY_DETECTOR,
                    version="1.0.0",
                    description="强化学习自主漏洞挖掘代理，自动探索并发现漏洞",
                    author="BinaryAnalysisPlatform",
                    dependencies=["torch", "numpy"],
                    supported_platforms=["x86", "x86_64"]
                )
        
        return RLVulnAgentAnalyzer
    
    def _create_multi_view_gnn_analyzer(self) -> Type[BaseAnalyzer]:
        """创建多视图图神经网络函数嵌入分析器包装类"""
        from modules.multi_view_gnn import MultiViewGNNEmbedderAnalyzer
        
        class MultiViewGNNAnalyzer(BaseAnalyzer):
            def __init__(self):
                self.analyzer = None
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                try:
                    self.analyzer = MultiViewGNNEmbedderAnalyzer()
                    return self.analyzer.analyze(**kwargs)
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            def cleanup(self) -> None:
                if self.analyzer:
                    self.analyzer.cleanup()
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="MultiViewGNN",
                    type=AnalyzerType.OTHER,
                    version="1.0.0",
                    description="多视图图神经网络函数嵌入，构建CFG/DDG/CCG三视图，使用GNN编码为统一向量",
                    author="BinaryAnalysisPlatform",
                    dependencies=["torch", "numpy"],
                    supported_platforms=["all"]
                )
        
        return MultiViewGNNAnalyzer
    
    def _create_distilled_vuln_detector_analyzer(self) -> Type[BaseAnalyzer]:
        """创建知识蒸馏漏洞检测器分析器包装类"""
        from modules.distilled_vuln_detector import DistilledVulnDetectorAnalyzer
        
        class DistilledVulnDetector(BaseAnalyzer):
            def __init__(self):
                self.analyzer = None
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                try:
                    self.analyzer = DistilledVulnDetectorAnalyzer()
                    return self.analyzer.analyze(**kwargs)
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            def cleanup(self) -> None:
                if self.analyzer:
                    self.analyzer.cleanup()
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="DistilledVulnDetector",
                    type=AnalyzerType.VULNERABILITY_DETECTOR,
                    version="1.0.0",
                    description="知识蒸馏轻量级漏洞检测模型，使用大模型生成标注数据训练TinyBERT级模型",
                    author="BinaryAnalysisPlatform",
                    dependencies=["transformers", "torch", "datasets"],
                    supported_platforms=["all"]
                )
        
        return DistilledVulnDetector
    
    def _create_trajectory_anomaly_analyzer(self) -> Type[BaseAnalyzer]:
        """创建执行轨迹异常检测分析器包装类"""
        from modules.trajectory_anomaly import TrajectoryAnomalyAnalyzer
        
        class TrajectoryAnomaly(BaseAnalyzer):
            def __init__(self):
                self.analyzer = None
            
            def analyze(self, **kwargs) -> Dict[str, Any]:
                try:
                    self.analyzer = TrajectoryAnomalyAnalyzer()
                    return self.analyzer.analyze(**kwargs)
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            def cleanup(self) -> None:
                if self.analyzer:
                    self.analyzer.cleanup()
            
            @classmethod
            def get_metadata(cls) -> AnalyzerMetadata:
                return AnalyzerMetadata(
                    name="TrajectoryAnomaly",
                    type=AnalyzerType.OTHER,
                    version="1.0.0",
                    description="执行轨迹序列模型异常检测，使用GPT风格自回归模型检测ROP/JOP等异常控制流",
                    author="BinaryAnalysisPlatform",
                    dependencies=["torch", "numpy"],
                    supported_platforms=["all"]
                )
        
        return TrajectoryAnomaly
    
    def _load_external_plugins(self) -> None:
        """加载外部插件"""
        if not self.plugins_dir.exists():
            return
        
        for item in self.plugins_dir.iterdir():
            if item.is_dir():
                self._load_plugin_from_dir(item)
            elif item.suffix == ".py":
                self._load_plugin_from_file(item)
    
    def _load_plugin_from_dir(self, plugin_dir: Path) -> None:
        """从目录加载插件"""
        init_file = plugin_dir / "__init__.py"
        if not init_file.exists():
            return
        
        try:
            sys.path.insert(0, str(self.plugins_dir))
            module_name = plugin_dir.name
            module = importlib.import_module(module_name)
            
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, type) and issubclass(obj, BaseAnalyzer) and obj != BaseAnalyzer:
                    self.analyzers[module_name] = obj
                    logger.info(f"加载外部插件: {module_name}")
            
        except Exception as e:
            logger.warning(f"加载插件目录 {plugin_dir} 失败: {e}")
        finally:
            if str(self.plugins_dir) in sys.path:
                sys.path.remove(str(self.plugins_dir))
    
    def _load_plugin_from_file(self, plugin_file: Path) -> None:
        """从文件加载插件"""
        try:
            sys.path.insert(0, str(plugin_file.parent))
            module_name = plugin_file.stem
            module = importlib.import_module(module_name)
            
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, type) and issubclass(obj, BaseAnalyzer) and obj != BaseAnalyzer:
                    self.analyzers[module_name] = obj
                    logger.info(f"加载外部插件文件: {module_name}")
                    
        except Exception as e:
            logger.warning(f"加载插件文件 {plugin_file} 失败: {e}")
        finally:
            if str(plugin_file.parent) in sys.path:
                sys.path.remove(str(plugin_file.parent))
    
    def get_analyzer(self, name: str) -> Optional[BaseAnalyzer]:
        """
        获取分析器实例
        
        Args:
            name: 分析器名称
            
        Returns:
            分析器实例，如果不存在返回 None
        """
        analyzer_class = self.analyzers.get(name)
        if analyzer_class:
            return analyzer_class()
        return None
    
    def get_analyzer_metadata(self, name: str) -> Optional[AnalyzerMetadata]:
        """
        获取分析器元数据
        
        Args:
            name: 分析器名称
            
        Returns:
            分析器元数据，如果不存在返回 None
        """
        analyzer_class = self.analyzers.get(name)
        if analyzer_class:
            return analyzer_class.get_metadata()
        return None
    
    def list_analyzers(self) -> List[str]:
        """列出所有可用的分析器"""
        return list(self.analyzers.keys())
    
    def list_analyzers_with_metadata(self) -> List[Dict[str, Any]]:
        """列出所有分析器及其元数据"""
        result = []
        for name, analyzer_class in self.analyzers.items():
            metadata = analyzer_class.get_metadata()
            result.append({
                "name": name,
                "type": metadata.type.value,
                "version": metadata.version,
                "description": metadata.description,
                "author": metadata.author,
                "dependencies": metadata.dependencies,
                "supported_platforms": metadata.supported_platforms
            })
        return result
    
    def run_analyzer(self, name: str, **kwargs) -> Dict[str, Any]:
        """
        运行分析器
        
        Args:
            name: 分析器名称
            **kwargs: 分析参数
            
        Returns:
            分析结果
        """
        analyzer = self.get_analyzer(name)
        if not analyzer:
            return {"success": False, "error": f"分析器 {name} 未找到"}
        
        is_valid, error = analyzer.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}
        
        try:
            return analyzer.analyze(**kwargs)
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            analyzer.cleanup()
    
    def run_analysis_pipeline(self, analyzers: List[str], **kwargs) -> Dict[str, Dict[str, Any]]:
        """
        运行分析流水线
        
        Args:
            analyzers: 分析器名称列表
            **kwargs: 共享参数
            
        Returns:
            各分析器的执行结果
        """
        results = {}
        
        for analyzer_name in analyzers:
            results[analyzer_name] = self.run_analyzer(analyzer_name, **kwargs)
            
            if not results[analyzer_name].get("success"):
                logger.warning(f"分析器 {analyzer_name} 执行失败")
        
        return results
    
    def save_config(self, path: str) -> bool:
        """
        保存配置
        
        Args:
            path: 配置文件路径
            
        Returns:
            是否成功保存
        """
        config = {
            "plugins_dir": str(self.plugins_dir),
            "loaded_analyzers": self.list_analyzers()
        }
        
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
            return False
    
    def load_config(self, path: str) -> bool:
        """
        加载配置
        
        Args:
            path: 配置文件路径
            
        Returns:
            是否成功加载
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            if "plugins_dir" in config:
                self.plugins_dir = Path(config["plugins_dir"])
                self._load_external_plugins()
            
            return True
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
            return False


def get_plugin_manager() -> PluginManager:
    """获取全局插件管理器实例"""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


_plugin_manager = None
