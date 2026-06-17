import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DangerousFunction(Enum):
    MEMCPY = "memcpy"
    STRCPY = "strcpy"
    STRCAT = "strcat"
    SPRINTF = "sprintf"
    VSPRINTF = "vsprintf"
    GETS = "gets"
    REALLOC = "realloc"
    MEMMOVE = "memmove"
    FREAD = "fread"
    READ = "read"


@dataclass
class ParameterAnalysis:
    function_name: str
    parameter_index: int
    parameter_name: str
    source_type: str
    bounds_check: bool
    risk_level: RiskLevel
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'parameter_index': self.parameter_index,
            'parameter_name': self.parameter_name,
            'source_type': self.source_type,
            'bounds_check': self.bounds_check,
            'risk_level': self.risk_level.value,
            'description': self.description
        }


@dataclass
class FunctionAnalysis:
    function_name: str
    address: int
    parameters: List[ParameterAnalysis]
    overall_risk: RiskLevel
    vulnerabilities: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'address': hex(self.address),
            'parameters': [p.to_dict() for p in self.parameters],
            'overall_risk': self.overall_risk.value,
            'vulnerabilities': self.vulnerabilities
        }


@dataclass
class AnalysisResult:
    dangerous_functions: List[FunctionAnalysis]
    total_functions: int
    high_risk_count: int
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'dangerous_functions': [f.to_dict() for f in self.dangerous_functions],
            'total_functions': self.total_functions,
            'high_risk_count': self.high_risk_count,
            'summary': self.summary
        }


class DangerousFunctionAnalyzer:
    
    def __init__(self):
        self.dangerous_funcs = {
            DangerousFunction.MEMCPY: {
                'params': [
                    {'name': 'dest', 'type': 'pointer', 'risk': 'high'},
                    {'name': 'src', 'type': 'pointer', 'risk': 'medium'},
                    {'name': 'n', 'type': 'size', 'risk': 'critical'}
                ],
                'description': '内存拷贝函数，长度参数控制不当可能导致缓冲区溢出'
            },
            DangerousFunction.STRCPY: {
                'params': [
                    {'name': 'dest', 'type': 'pointer', 'risk': 'high'},
                    {'name': 'src', 'type': 'string', 'risk': 'critical'}
                ],
                'description': '字符串拷贝函数，没有长度限制，极易导致缓冲区溢出'
            },
            DangerousFunction.STRCAT: {
                'params': [
                    {'name': 'dest', 'type': 'pointer', 'risk': 'high'},
                    {'name': 'src', 'type': 'string', 'risk': 'critical'}
                ],
                'description': '字符串拼接函数，没有长度限制，极易导致缓冲区溢出'
            },
            DangerousFunction.SPRINTF: {
                'params': [
                    {'name': 'str', 'type': 'pointer', 'risk': 'high'},
                    {'name': 'format', 'type': 'string', 'risk': 'critical'},
                    {'name': '...', 'type': 'variadic', 'risk': 'medium'}
                ],
                'description': '格式化输出函数，格式字符串漏洞风险'
            },
            DangerousFunction.VSPRINTF: {
                'params': [
                    {'name': 'str', 'type': 'pointer', 'risk': 'high'},
                    {'name': 'format', 'type': 'string', 'risk': 'critical'},
                    {'name': 'ap', 'type': 'va_list', 'risk': 'medium'}
                ],
                'description': '可变参数格式化输出函数，格式字符串漏洞风险'
            },
            DangerousFunction.GETS: {
                'params': [
                    {'name': 'str', 'type': 'pointer', 'risk': 'critical'}
                ],
                'description': '危险的输入函数，完全没有长度限制'
            }
        }
    
    def analyze(self, binary_info: Dict[str, Any]) -> AnalysisResult:
        dangerous_functions = []
        high_risk_count = 0
        
        for func in binary_info.get('functions', []):
            func_name = func.get('name', '')
            
            for dangerous_func in DangerousFunction:
                if dangerous_func.value in func_name.lower():
                    analysis = self._analyze_function(func, dangerous_func)
                    dangerous_functions.append(analysis)
                    
                    if analysis.overall_risk in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                        high_risk_count += 1
        
        summary = self._generate_summary(dangerous_functions)
        
        return AnalysisResult(
            dangerous_functions=dangerous_functions,
            total_functions=len(binary_info.get('functions', [])),
            high_risk_count=high_risk_count,
            summary=summary)
        

    
    def _analyze_function(self, func: Dict[str, Any], dangerous_func: DangerousFunction) -> FunctionAnalysis:
        params = []
        vulnerabilities = []
        
        func_info = self.dangerous_funcs.get(dangerous_func, {})
        param_info = func_info.get('params', [])
        
        for i, param in enumerate(param_info):
            bounds_check = self._has_bounds_check(func, param['name'])
            source_type = self._get_source_type(func, param['name'])
            
            risk_level = RiskLevel[param['risk'].upper()]
            
            if not bounds_check and risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                vulnerabilities.append(f"{param['name']} 参数缺少边界检查")
            
            param_analysis = ParameterAnalysis()
                function_name=func.get('name', ''),
                parameter_index=i,
                parameter_name=param['name'],
                source_type=source_type,
                bounds_check=bounds_check,
                risk_level=risk_level,
                description=f"{param['name']}: {param['type']} 参数"
            
            params.append(param_analysis)
        
        overall_risk = self._determine_overall_risk(params, vulnerabilities)
        
        return FunctionAnalysis(
            function_name=func.get('name', ''),
            address=func.get('address', 0),
            parameters=params,
            overall_risk=overall_risk,
            vulnerabilities=vulnerabilities)
        

    
    def _has_bounds_check(self, func: Dict[str, Any], param_name: str) -> bool:
        code = func.get('pseudocode', '')
        
        check_patterns = [
            f"{param_name} < ",
            f"{param_name} <= ",
            f"len({param_name})",
            f"sizeof(")
            "MAX_",
            "_MAX"
        ]
        
        return any(pattern in code for pattern in check_patterns)
    
    def _get_source_type(self, func: Dict[str, Any], param_name: str) -> str:
        code = func.get('pseudocode', '')
        
        if 'user_input' in code.lower() or 'argv' in code.lower():
            return 'user_input'
        elif 'file' in code.lower() or 'read' in code.lower():
            return 'file_input'
        elif 'network' in code.lower() or 'socket' in code.lower():
            return 'network_input'
        else:
            return 'internal'
    
    def _determine_overall_risk(self, params: List[ParameterAnalysis], vulnerabilities: List[str]) -> RiskLevel:
        if vulnerabilities:
            return RiskLevel.CRITICAL
        
        critical_params = [p for p in params if p.risk_level == RiskLevel.CRITICAL and p.source_type == 'user_input']
        if critical_params:
            return RiskLevel.CRITICAL
        
        high_params = [p for p in params if p.risk_level == RiskLevel.HIGH and not p.bounds_check]
        if high_params:
            return RiskLevel.HIGH
        
        return RiskLevel.MEDIUM
    
    def _generate_summary(self, functions: List[FunctionAnalysis]) -> Dict[str, Any]:
        by_risk = {r.value: 0 for r in RiskLevel}
        
        for func in functions:
            by_risk[func.overall_risk.value] += 1
        
        return {
            'total_dangerous_functions': len(functions),
            'risk_distribution': by_risk,
            'critical_functions': by_risk['critical'],
            'high_risk_functions': by_risk['high']
        }


def analyze_dangerous_functions(binary_info: Dict[str, Any]) -> AnalysisResult:
    analyzer = DangerousFunctionAnalyzer()
    return analyzer.analyze(binary_info)