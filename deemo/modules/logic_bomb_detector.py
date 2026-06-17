import os
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class LogicBombDetector:
    """
    逻辑炸弹与定时炸弹检测器
    
    检测二进制中基于特定条件（如特定日期、用户、文件名、计数器）触发恶意行为的逻辑炸弹或定时炸弹，
    通过符号执行分析触发条件，并提取触发逻辑。
    
    Attributes:
        binary_path: 目标二进制文件路径
        time_functions: 检测到的时间相关函数
        trigger_conditions: 提取的触发条件
        logic_bombs: 检测到的逻辑炸弹列表
    """
    
    def __init__(self, binary_path: str = None):
        """
        初始化逻辑炸弹检测器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        self.binary_path = binary_path
        self.time_functions: List[Dict[str, Any]] = []
        self.trigger_conditions: List[Dict[str, Any]] = []
        self.logic_bombs: List[Dict[str, Any]] = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的逻辑炸弹检测
        
        Returns:
            检测结果字典
        """
        logger.info("开始逻辑炸弹检测")
        
        # 查找时间相关函数
        self._find_time_functions()
        
        # 分析触发条件
        self._analyze_trigger_conditions()
        
        # 检测逻辑炸弹模式
        self._detect_logic_bombs()
        
        # 分析条件表达式
        self._analyze_conditional_expressions()
        
        result = {
            'time_functions': self.time_functions,
            'trigger_conditions': self.trigger_conditions,
            'logic_bombs': self.logic_bombs,
            'risk_level': self._calculate_risk_level()
        }
        
        return result
    
    def _find_time_functions(self):
        """查找时间相关函数"""
        if not self.binary_path:
            return
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.binary_path, client=None)
            functions = decompiler.list_functions()
            
            # 时间相关函数模式
            time_patterns = [
                r'time\b',
                r'clock\b',
                r'gettimeofday\b',
                r'localtime\b',
                r'gmtime\b',
                r'strftime\b',
                r'QueryPerformanceCounter\b',
                r'GetSystemTime\b',
                r'GetLocalTime\b',
                r'date\b',
                r'tm_year\b',
                r'tm_mon\b',
                r'tm_mday\b',
                r'tm_hour\b'
            ]
            
            # 日期常量模式
            date_constants = [
                r'20\d{2}',
                r'\d{4}[-/]\d{2}[-/]\d{2}',
                r'\d{2}[-/]\d{2}[-/]\d{4}'
            ]
            
            for func_name in functions:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    
                    if pseudocode:
                        # 检查时间函数调用
                        for pattern in time_patterns:
                            if re.search(pattern, pseudocode):
                                self.time_functions.append({)
                                    'function': func_name,
                                    'pattern': pattern,
                                    'pseudocode_snippet': pseudocode[:300],
                                    'type': 'time_function'
                                }
                                break
                        
                        # 检查日期常量
                        for pattern in date_constants:
                            matches = re.findall(pattern, pseudocode)
                            if matches:
                                self.time_functions.append({)
                                    'function': func_name,
                                    'pattern': pattern,
                                    'dates_found': matches,
                                    'pseudocode_snippet': pseudocode[:300],
                                    'type': 'date_constant'
                                }
                
                except Exception as e:
                    logger.debug(f"分析函数 {func_name} 失败: {e}")
        
        except Exception as e:
            logger.warning(f"查找时间相关函数失败: {e}")
    
    def _analyze_trigger_conditions(self):
        """分析触发条件"""
        for time_func in self.time_functions:
            pseudocode = time_func.get('pseudocode_snippet', '')
            
            if not pseudocode:
                continue
            
            # 查找时间相关的条件判断
            time_conditions = self._extract_time_conditions(pseudocode)
            
            for condition in time_conditions:
                self.trigger_conditions.append({)
                    'function': time_func['function'],
                    'condition': condition['condition'],
                    'operator': condition['operator'],
                    'value': condition['value'],
                    'type': time_func['type']
                }
    
    def _extract_time_conditions(self, pseudocode: str) -> List[Dict[str, Any]]:
        """从伪代码中提取时间条件"""
        conditions = []
        
        # 查找日期比较
        date_compare_patterns = [
            (r'(tm_year|year)\s*([<>!=]=?)\s*(\d+)', 'year'),
            (r'(tm_mon|month)\s*([<>!=]=?)\s*(\d+)', 'month'),
            (r'(tm_mday|day)\s*([<>!=]=?)\s*(\d+)', 'day'),
            (r'(tm_hour|hour)\s*([<>!=]=?)\s*(\d+)', 'hour'),
            (r'(time|timestamp|date)\s*([<>!=]=?)\s*(0x[0-9a-fA-F]+|\d+)', 'generic')
        ]
        
        for pattern, condition_type in date_compare_patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                var_name, operator, value = match
                conditions.append({)
                    'condition': f"{var_name} {operator} {value}",
                    'operator': operator,
                    'value': value,
                    'type': condition_type
                }
        
        # 查找字符串日期比较
        string_date_pattern = r'(strcmp|strncmp).*"(20\d{2}[-/]\d{2}[-/]\d{2})"'
        matches = re.findall(string_date_pattern, pseudocode)
        for match in matches:
            if isinstance(match, tuple):
                date_str = match[1]
            else:
                date_str = match
            conditions.append({)
                'condition': f"strcmp(..., \"{date_str}\")",
                'operator': '==',
                'value': date_str,
                'type': 'date_string'
            }
        
        return conditions
    
    def _detect_logic_bombs(self):
        """检测逻辑炸弹模式"""
        for condition in self.trigger_conditions:
            # 分析条件后可能的恶意行为
            if self._has_malicious_behavior(condition['function']):
                self.logic_bombs.append({)
                    'function': condition['function'],
                    'trigger_condition': condition['condition'],
                    'trigger_type': condition['type'],
                    'risk': self._evaluate_risk(condition),
                    'description': self._generate_description(condition)
                }
        
        # 去重
        seen = set()
        unique_bombs = []
        for bomb in self.logic_bombs:
            key = f"{bomb['function']}_{bomb['trigger_condition']}",
            if key not in seen:
                seen.add(key)
                unique_bombs.append(bomb)
        
        self.logic_bombs = unique_bombs
    
    def _has_malicious_behavior(self, func_name: str) -> bool:
        """检查函数是否包含恶意行为"""
        if not self.binary_path:
            return False
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.binary_path, client=None)
            analysis = decompiler.analyze_function(func_name, {})
            pseudocode = analysis.get('pseudocode', '')
            
            # 恶意行为模式
            malicious_patterns = [
                r'(remove|unlink|delete)\s*\(')
                r'system\s*\(\s*["\'].*rm\s+')
                r'system\s*\(\s*["\'].*format\s+')
                r'exit\s*\(\s*(-?\d+)\s*\)',
                r'abort\s*\(\)',
                r'assert\s*\(')
                r'(shutdown|reboot)\s*\(')
                r'kill\s*\(')
                r'unlink\s*\(')
                r'(chmod|chown)\s*\(')
                r'WriteProcessMemory\s*\(')
                r'CreateRemoteThread\s*\(')
            ]
            
            for pattern in malicious_patterns:
                if re.search(pattern, pseudocode):
                    return True
            
        except Exception as e:
            logger.debug(f"检查恶意行为失败 {func_name}: {e}")
        
        return False
    
    def _evaluate_risk(self, condition: Dict[str, Any]) -> str:
        """评估风险等级"""
        value = condition.get('value', '')
        
        # 检查是否为未来日期（高危）
        if isinstance(value, str):
            if value.startswith('20'):
                year = int(value[:4])
                if year > 2024:
                    return 'high'
        
        # 检查比较操作符
        operator = condition.get('operator', '')
        if operator in ['>', '>=']:
            return 'high'
        
        return 'medium'
    
    def _generate_description(self, condition: Dict[str, Any]) -> str:
        """生成描述"""
        condition_type = condition.get('type', '')
        operator = condition.get('operator', '')
        value = condition.get('value', '')
        
        descriptions = {
            'year': f"年份条件: 当年份 {operator} {value} 时触发",
            'month': f"月份条件: 当月份 {operator} {value} 时触发",
            'day': f"日期条件: 当日期 {operator} {value} 时触发",
            'hour': f"时间条件: 当小时 {operator} {value} 时触发",
            'date_string': f"字符串日期比较: {value}",
            'generic': f"通用时间条件: {condition.get('condition', '')}"
        }
        
        return descriptions.get(condition_type, f"时间条件: {condition.get('condition', '')}")
    
    def _analyze_conditional_expressions(self):
        """分析条件表达式"""
        # 查找计数器模式
        counter_patterns = [
            r'(count|counter|loop).*[<>!=]=?\s*\d+',
            r'(\+=|\-=).*\d+'
        ]
        
        if not self.binary_path:
            return
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.binary_path, client=None)
            functions = decompiler.list_functions()
            
            for func_name in functions[:20]:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    
                    for pattern in counter_patterns:
                        matches = re.findall(pattern, pseudocode)
                        if matches:
                            self.trigger_conditions.append({)
                                'function': func_name,
                                'condition': ', '.join(matches),
                                'operator': 'counter',
                                'value': '多次执行',
                                'type': 'counter'
                            }
                            
                            if self._has_malicious_behavior(func_name):
                                self.logic_bombs.append({)
                                    'function': func_name,
                                    'trigger_condition': f"计数器条件: {', '.join(matches)}",
                                    'trigger_type': 'counter',
                                    'risk': 'medium',
                                    'description': f"基于执行次数的触发条件，可能为逻辑炸弹"
                                }
                
                except Exception as e:
                    logger.debug(f"分析条件表达式失败 {func_name}: {e}")
        
        except Exception as e:
            logger.warning(f"分析条件表达式失败: {e}")
    
    def _calculate_risk_level(self) -> str:
        """计算总体风险等级"""
        high_count = sum(1 for bomb in self.logic_bombs if bomb['risk'] == 'high')
        medium_count = len(self.logic_bombs)
        
        if high_count >= 1:
            return 'high'
        elif medium_count >= 2:
            return 'medium'
        elif medium_count > 0:
            return 'low'
        else:
            return 'none'
    
    def extract_trigger_conditions(self) -> List[str]:
        """
        提取触发条件表达式
        
        Returns:
            触发条件表达式列表
        """
        conditions = []
        
        for condition in self.trigger_conditions:
            conditions.append(condition['condition'])
        
        for bomb in self.logic_bombs:
            conditions.append(bomb['trigger_condition'])
        
        return conditions


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='逻辑炸弹检测器')
    parser.add_argument('--binary', required=True, help='目标二进制文件路径')
    parser.add_argument('--output', default='/tmp/logic_bomb_report.txt', help='报告输出路径')
    
    args = parser.parse_args()
    
    detector = LogicBombDetector(args.binary)
    result = detector.analyze()
    
    with open(args.output, 'w') as f:
        f.write("逻辑炸弹检测报告\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("风险等级: {}\n\n".format(result['risk_level']

        
        f.write("检测到的时间相关函数:\n")
        f.write("-" * 30 + "\n")
        for func in result['time_functions']:
            f.write(f"函数: {func['function']}\n")
            f.write(f"  类型: {func['type']}\n")
            f.write(f"  模式: {func['pattern']}\n")
            if 'dates_found' in func:
                f.write(f"  日期常量: {', '.join(func['dates_found'])}\n")
            f.write("\n")
        
        f.write("提取的触发条件:\n")
        f.write("-" * 30 + "\n")
        for condition in result['trigger_conditions']:
            f.write(f"函数: {condition['function']}\n")
            f.write(f"  条件: {condition['condition']}\n")
            f.write(f"  类型: {condition['type']}\n")
            f.write("\n")
        
        f.write("检测到的逻辑炸弹:\n")
        f.write("-" * 30 + "\n")
        for bomb in result['logic_bombs']:
            f.write(f"函数: {bomb['function']}\n")
            f.write(f"  触发条件: {bomb['trigger_condition']}\n")
            f.write(f"  触发类型: {bomb['trigger_type']}\n")
            f.write(f"  风险等级: {bomb['risk']}\n")
            f.write(f"  描述: {bomb['description']}\n")
            f.write("\n")
    
    print(f"检测报告已保存到: {args.output}")


if __name__ == '__main__':
    main()))