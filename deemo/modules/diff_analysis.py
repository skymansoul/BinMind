import logging
import os
import json
import hashlib
import subprocess
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config import Config, call_ai_with_retry, get_current_ai_model, mask_sensitive_data
from prompts import BINARY_DIFF_ANALYSIS_TEMPLATE
from modules.vuln_db import VulnerabilityDatabase
from modules.decomp_ai import DecompilerAI, strip_ansi_escape

logger = logging.getLogger(__name__)

SIMILARITY_THRESHOLD = 0.7
MIN_FUNCTION_SIZE = 16

DANGEROUS_FUNCTIONS = {
    'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf',
    'memcpy', 'memset', 'strncpy', 'strncat', 'snprintf',
    'system', 'execve', 'popen', 'fork', 'pipe',
    'read', 'write', 'recv', 'send',
    'malloc', 'free', 'calloc', 'realloc'
}


class FunctionFeatures:
    """
    函数特征提取类
    """
    
    def __init__(self, name: str, address: int = 0):
        self.name = name
        self.address = address
        self.pseudocode = ""
        self.basic_block_count = 0
        self.instruction_count = 0
        self.calls: List[str] = []
        self.cfg_hash = ""
        self.feature_vector: List[float] = []
        self.dangerous_calls: Set[str] = set()
        self.size = 0
    
    def extract_features(self, decompiler: DecompilerAI) -> None:
        """
        从反编译引擎提取函数特征
        """
        try:
            self.pseudocode = decompiler.decompile(self.name) or ""
            
            self.basic_block_count = self._count_basic_blocks(self.pseudocode)
            self.instruction_count = self._count_instructions(self.pseudocode)
            self.calls = self._extract_function_calls(self.pseudocode)
            self.dangerous_calls = self._identify_dangerous_calls(self.calls)
            self.cfg_hash = self._compute_cfg_hash()
            self.feature_vector = self._generate_feature_vector()
            
        except Exception as e:
            logger.warning(f"提取函数 {self.name} 特征失败: {e}")
    
    def _count_basic_blocks(self, pseudocode: str) -> int:
        """统计基本块数量"""
        if not pseudocode:
            return 0
        # 简单启发式：统计 if/else/while/for/switch 等控制流语句
        control_flow_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'break', 'return']
        count = 1  # 至少一个基本块
        for keyword in control_flow_keywords:
            count += pseudocode.count(keyword)
        return min(count, 100)
    
    def _count_instructions(self, pseudocode: str) -> int:
        """统计指令/语句数量"""
        if not pseudocode:
            return 0
        lines = [line.strip() for line in pseudocode.split('\n') if line.strip() and not line.strip().startswith('//')]
        return len(lines)
    
    def _extract_function_calls(self, pseudocode: str) -> List[str]:
        """提取函数调用"""
        if not pseudocode:
            return []
        
        import re
        call_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.findall(call_pattern, pseudocode)
        
        # 过滤常见关键字
        keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'struct', 'typedef'}
        return [m for m in matches if m not in keywords]
    
    def _identify_dangerous_calls(self, calls: List[str]) -> Set[str]:
        """识别危险函数调用"""
        return {call for call in calls if call.lower() in DANGEROUS_FUNCTIONS}
    
    def _compute_cfg_hash(self) -> str:
        """计算控制流图哈希"""
        features = [
            str(self.basic_block_count),
            str(self.instruction_count),
            str(len(self.calls)),
            str(len(self.dangerous_calls))
        ]
        return hashlib.md5('|'.join(features).encode()).hexdigest()
    
    def _generate_feature_vector(self) -> List[float]:
        """生成特征向量"""
        vector = [
            self.basic_block_count / 100.0,
            self.instruction_count / 500.0,
            len(self.calls) / 50.0,
            len(self.dangerous_calls) / len(DANGEROUS_FUNCTIONS),
            self.size / 1000.0 if self.size else 0.0
        ]
        return vector


class BinaryDiffAnalyzer:
    """
    跨版本二进制差异分析与漏洞回归检测类
    """
    
    def __init__(self, baseline_binary: str, target_binary: str):
        """
        初始化二进制差异分析器
        
        Args:
            baseline_binary: 基准版本二进制文件路径
            target_binary: 比较版本二进制文件路径
        """
        self.baseline_path = self._validate_binary_path(baseline_binary)
        self.target_path = self._validate_binary_path(target_binary)
        
        self.baseline_decompiler: Optional[DecompilerAI] = None
        self.target_decompiler: Optional[DecompilerAI] = None
        
        self.baseline_functions: Dict[str, FunctionFeatures] = {}
        self.target_functions: Dict[str, FunctionFeatures] = {}
        
        self.matched_functions: List[Dict[str, Any]] = []
        self.added_functions: List[str] = []
        self.removed_functions: List[str] = []
        self.modified_functions: List[Dict[str, Any]] = []
        
        self.vuln_db: Optional[VulnerabilityDatabase] = None
        
        self.diff_report: Dict[str, Any] = {}
    
    def _validate_binary_path(self, path: str) -> str:
        """验证二进制文件路径"""
        if not path or not isinstance(path, str):
            raise ValueError("二进制路径必须是有效字符串")
        
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"文件不存在: {abs_path}")
        
        if not os.path.isfile(abs_path):
            raise ValueError(f"不是有效文件: {abs_path}")
        
        return abs_path
    
    def _extract_functions_from_radare2(self, binary_path: str) -> List[str]:
        """使用 radare2 提取函数列表"""
        functions = []
        
        try:
            cmd = [
                'r2',
                '-q',
                '-e', 'io.color=false',
                '-c', 'afl',
                binary_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            
            if result.returncode == 0:
                libc_prefixes = ('_start', '__libc_csu', '__libc_start', '_init', '_fini', '__gmon', '_dl_')
                
                for line in result.stdout.strip().split('\n'):
                    line = strip_ansi_escape(line)
                    parts = line.split()
                    if len(parts) >= 3:
                        func_name = parts[-1]
                        
                        if func_name.startswith('sym.'):
                            clean_name = func_name[4:]
                        else:
                            clean_name = func_name
                        
                        if not clean_name.startswith(libc_prefixes):
                            functions.append(clean_name)
        
        except Exception as e:
            logger.warning(f"从 radare2 提取函数列表失败: {e}")
        
        return functions
    
    def _calculate_cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """计算余弦相似度"""
        if not vec1 or not vec2:
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = (sum(a * a for a in vec1)) ** 0.5
        norm2 = (sum(b * b for b in vec2)) ** 0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def _calculate_jaccard_similarity(self, set1: Set[str], set2: Set[str]) -> float:
        """计算 Jaccard 相似度"""
        if not set1 and not set2:
            return 1.0
        
        union = set1 | set2
        if not union:
            return 0.0
        
        intersection = set1 & set2
        return len(intersection) / len(union)
    
    def _compare_pseudocode(self, pseudo1: str, pseudo2: str) -> float:
        """比较伪代码相似度"""
        if not pseudo1 or not pseudo2:
            return 0.0
        
        words1 = set(pseudo1.split())
        words2 = set(pseudo2.split())
        
        return self._calculate_jaccard_similarity(words1, words2)
    
    def load_binaries(self) -> None:
        """加载两个二进制文件进行分析"""
        logger.info(f"加载基准二进制: {self.baseline_path}")
        logger.info(f"加载目标二进制: {self.target_path}")
        
        try:
            self.baseline_decompiler = DecompilerAI(self.baseline_path)
            self.target_decompiler = DecompilerAI(self.target_path)
            
            baseline_funcs = self._extract_functions_from_radare2(self.baseline_path)
            target_funcs = self._extract_functions_from_radare2(self.target_path)
            
            logger.info(f"基准版本函数数量: {len(baseline_funcs)}")
            logger.info(f"目标版本函数数量: {len(target_funcs)}")
            
            self._extract_function_features(baseline_funcs, self.baseline_functions, self.baseline_decompiler)
            self._extract_function_features(target_funcs, self.target_functions, self.target_decompiler)
            
        except Exception as e:
            logger.error(f"加载二进制文件失败: {e}")
            raise
    
    def _extract_function_features(
        self,
        func_names: List[str],
        func_dict: Dict[str, FunctionFeatures],
        decompiler: DecompilerAI
    ) -> None:
        """批量提取函数特征"""
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_func = {}
            
            for func_name in func_names[:50]:
                ff = FunctionFeatures(func_name)
                func_dict[func_name] = ff
                future_to_func[executor.submit(ff.extract_features, decompiler)] = func_name
            
            for future in as_completed(future_to_func):
                func_name = future_to_func[future]
                try:
                    future.result()
                except Exception as e:
                    logger.warning(f"提取函数 {func_name} 特征时出错: {e}")
    
    def match_functions(self) -> None:
        """匹配两个版本中的函数"""
        logger.info("开始函数匹配...")
        
        baseline_names = set(self.baseline_functions.keys())
        target_names = set(self.target_functions.keys())
        
        exact_matches = baseline_names & target_names
        self.added_functions = list(target_names - baseline_names)
        self.removed_functions = list(baseline_names - target_names)
        
        logger.info(f"精确匹配函数: {len(exact_matches)}")
        logger.info(f"新增函数: {len(self.added_functions)}")
        logger.info(f"删除函数: {len(self.removed_functions)}")
        
        for func_name in exact_matches:
            baseline_func = self.baseline_functions[func_name]
            target_func = self.target_functions[func_name]
            
            similarity = self._compare_functions(baseline_func, target_func)
            
            result = {
                'function_name': func_name,
                'similarity': similarity,
                'baseline_features': self._feature_to_dict(baseline_func),
                'target_features': self._feature_to_dict(target_func),
                'is_modified': similarity < SIMILARITY_THRESHOLD
            }
            
            self.matched_functions.append(result)
            
            if similarity < SIMILARITY_THRESHOLD:
                self.modified_functions.append(result)
    
    def _compare_functions(self, baseline: FunctionFeatures, target: FunctionFeatures) -> float:
        """比较两个函数的相似度"""
        if not baseline.pseudocode or not target.pseudocode:
            cfg_sim = 1.0 if baseline.cfg_hash == target.cfg_hash else 0.5
            return cfg_sim
        
        pseudo_sim = self._compare_pseudocode(baseline.pseudocode, target.pseudocode)
        call_sim = self._calculate_jaccard_similarity(set(baseline.calls), set(target.calls))
        danger_sim = self._calculate_jaccard_similarity(baseline.dangerous_calls, target.dangerous_calls)
        
        # 加权平均
        weights = [0.4, 0.3, 0.3]
        return weights[0] * pseudo_sim + weights[1] * call_sim + weights[2] * danger_sim
    
    def _feature_to_dict(self, ff: FunctionFeatures) -> Dict[str, Any]:
        """将函数特征转换为字典"""
        return {
            'name': ff.name,
            'address': ff.address,
            'basic_block_count': ff.basic_block_count,
            'instruction_count': ff.instruction_count,
            'call_count': len(ff.calls),
            'dangerous_calls': list(ff.dangerous_calls),
            'cfg_hash': ff.cfg_hash,
            'has_pseudocode': bool(ff.pseudocode)
        }
    
    def check_vulnerability_regression(self) -> List[Dict[str, Any]]:
        """检查漏洞回归"""
        if not self.vuln_db:
            self.vuln_db = VulnerabilityDatabase()
        
        regressions = []
        
        for modified in self.modified_functions:
            func_name = modified['function_name']
            baseline_func = self.baseline_functions[func_name]
            target_func = self.target_functions[func_name]
            
            # 检查危险函数调用变化
            baseline_danger = baseline_func.dangerous_calls
            target_danger = target_func.dangerous_calls
            
            added_danger = target_danger - baseline_danger
            removed_danger = baseline_danger - target_danger
            
            if added_danger:
                regressions.append({
                    'function_name': func_name,
                    'type': 'new_dangerous_call',
                    'description': f"函数 {func_name} 新增危险函数调用: {added_danger}",
                    'severity': 'High',
                    'added_calls': list(added_danger),
                    'removed_calls': list(removed_danger)
                })
            
            # 检查已知漏洞是否仍存在
            vuln_matches = self.vuln_db.search_by_function(func_name, limit=5)
            if vuln_matches:
                regressions.append({
                    'function_name': func_name,
                    'type': 'known_vulnerability',
                    'description': f"函数 {func_name} 存在已知漏洞记录",
                    'severity': 'Medium',
                    'known_vulnerabilities': vuln_matches
                })
        
        return regressions
    
    def analyze_with_ai(self, client=None) -> Optional[str]:
        """调用 AI 分析伪代码变更的语义影响"""
        if not client:
            logger.warning("未配置 AI 客户端，跳过 AI 分析")
            return None
        
        diff_summary = self._generate_diff_summary()
        
        if not diff_summary:
            return None
        
        try:
            prompt = BINARY_DIFF_ANALYSIS_TEMPLATE.format(
                baseline_binary=os.path.basename(self.baseline_path),
                target_binary=os.path.basename(self.target_path),
                diff_summary=diff_summary
            )
            
            logger.info("调用 AI API 进行差异分析")
            
            system_message = {"role": "system", "content": "你是一个资深的二进制安全研究员，擅长分析代码变更的安全影响。"}
            user_message = {"role": "user", "content": prompt}
            
            result_text = call_ai_with_retry(
                client,
                model=get_current_ai_model(),
                messages=[system_message, user_message],
                temperature=0.3,
                max_tokens=4000
            )
            
            return result_text
        
        except Exception as e:
            logger.error(f"AI 分析失败: {e}")
            return None
    
    def _generate_diff_summary(self) -> str:
        """生成差异摘要"""
        lines = []
        
        lines.append(f"基准版本: {os.path.basename(self.baseline_path)}")
        lines.append(f"目标版本: {os.path.basename(self.target_path)}")
        lines.append("")
        lines.append(f"新增函数: {len(self.added_functions)}")
        if self.added_functions:
            lines.append(f"  {', '.join(self.added_functions[:10])}")
        
        lines.append(f"删除函数: {len(self.removed_functions)}")
        if self.removed_functions:
            lines.append(f"  {', '.join(self.removed_functions[:10])}")
        
        lines.append(f"修改函数: {len(self.modified_functions)}")
        for mod in self.modified_functions[:5]:
            lines.append(f"  {mod['function_name']}: 相似度 {mod['similarity']:.2f}")
        
        return '\n'.join(lines)
    
    def generate_report(self, output_dir: str = './reports', ai_analysis: str = None) -> Dict[str, str]:
        """生成差异分析报告"""
        os.makedirs(output_dir, exist_ok=True)
        
        report_data = {
            'analysis_time': datetime.now().isoformat(),
            'baseline_binary': self.baseline_path,
            'target_binary': self.target_path,
            'summary': {
                'total_functions_baseline': len(self.baseline_functions),
                'total_functions_target': len(self.target_functions),
                'matched_functions': len(self.matched_functions),
                'added_functions': len(self.added_functions),
                'removed_functions': len(self.removed_functions),
                'modified_functions': len(self.modified_functions)
            },
            'added_functions': self.added_functions,
            'removed_functions': self.removed_functions,
            'modified_functions': self.modified_functions,
            'vulnerability_regressions': self.check_vulnerability_regression(),
            'ai_analysis': ai_analysis
        }
        
        self.diff_report = report_data
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        baseline_name = os.path.splitext(os.path.basename(self.baseline_path))[0]
        target_name = os.path.splitext(os.path.basename(self.target_path))[0]
        
        report_paths = {}
        
        # JSON 报告
        json_path = os.path.join(output_dir, f'diff_report_{baseline_name}_vs_{target_name}_{timestamp}.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        report_paths['json'] = json_path
        
        # Markdown 报告
        md_path = os.path.join(output_dir, f'diff_report_{baseline_name}_vs_{target_name}_{timestamp}.md')
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(self._generate_markdown_report(report_data))
        report_paths['markdown'] = md_path
        
        logger.info(f"差异分析报告已生成: {md_path}")
        
        return report_paths
    
    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """生成 Markdown 格式报告"""
        lines = []
        
        lines.append(f"# 二进制差异分析报告")
        lines.append("")
        lines.append(f"**分析时间**: {data['analysis_time']}")
        lines.append("")
        lines.append("## 比较概览")
        lines.append("")
        lines.append("| 项目 | 基准版本 | 目标版本 |")
        lines.append("|------|----------|----------|")
        lines.append(f"| 文件 | `{os.path.basename(data['baseline_binary'])}` | `{os.path.basename(data['target_binary'])}` |")
        lines.append(f"| 函数总数 | {data['summary']['total_functions_baseline']} | {data['summary']['total_functions_target']} |")
        lines.append(f"| 匹配函数 | {data['summary']['matched_functions']} | |")
        lines.append(f"| 新增函数 | | {data['summary']['added_functions']} |")
        lines.append(f"| 删除函数 | {data['summary']['removed_functions']} | |")
        lines.append(f"| 修改函数 | | {data['summary']['modified_functions']} |")
        lines.append("")
        
        if data['added_functions']:
            lines.append("## 新增函数")
            lines.append("")
            lines.append(f"共 {len(data['added_functions'])} 个新增函数:")
            lines.append("")
            for func in data['added_functions']:
                lines.append(f"- `{func}`")
            lines.append("")
        
        if data['removed_functions']:
            lines.append("## 删除函数")
            lines.append("")
            lines.append(f"共 {len(data['removed_functions'])} 个删除函数:")
            lines.append("")
            for func in data['removed_functions']:
                lines.append(f"- `{func}`")
            lines.append("")
        
        if data['modified_functions']:
            lines.append("## 修改函数")
            lines.append("")
            lines.append("| 函数名 | 相似度 | 危险调用变化 |")
            lines.append("|--------|--------|--------------|")
            for mod in data['modified_functions']:
                baseline_danger = mod['baseline_features']['dangerous_calls']
                target_danger = mod['target_features']['dangerous_calls']
                danger_change = ""
                if set(target_danger) != set(baseline_danger):
                    danger_change = "有变化"
                lines.append(f"| `{mod['function_name']}` | {mod['similarity']:.2f} | {danger_change} |")
            lines.append("")
        
        if data['vulnerability_regressions']:
            lines.append("## 漏洞回归警告")
            lines.append("")
            for reg in data['vulnerability_regressions']:
                lines.append(f"### {reg['type']}")
                lines.append("")
                lines.append(f"**函数**: `{reg['function_name']}`")
                lines.append(f"**严重程度**: {reg['severity']}")
                lines.append(f"**描述**: {reg['description']}")
                if 'added_calls' in reg:
                    lines.append(f"**新增危险调用**: {', '.join(reg['added_calls'])}")
                lines.append("")
        
        if data['ai_analysis']:
            lines.append("## AI 分析结果")
            lines.append("")
            lines.append(data['ai_analysis'])
        
        return '\n'.join(lines)
    
    def run(self, client=None) -> Dict[str, Any]:
        """执行完整的差异分析流程"""
        logger.info("开始跨版本二进制差异分析...")
        
        self.load_binaries()
        self.match_functions()
        
        regressions = self.check_vulnerability_regression()
        ai_analysis = self.analyze_with_ai(client)
        
        reports = self.generate_report(ai_analysis=ai_analysis)
        
        return {
            'summary': {
                'baseline_functions': len(self.baseline_functions),
                'target_functions': len(self.target_functions),
                'matched': len(self.matched_functions),
                'added': len(self.added_functions),
                'removed': len(self.removed_functions),
                'modified': len(self.modified_functions),
                'regressions_found': len(regressions)
            },
            'reports': reports,
            'ai_analysis': ai_analysis is not None
        }