import os
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class ScriptLanguage(Enum):
    """脚本语言枚举"""
    LUA = 'lua'
    PYTHON = 'python'
    JAVASCRIPT = 'javascript'
    VBSCRIPT = 'vbscript'
    PHP = 'php'
    PERL = 'perl'
    RUBY = 'ruby'
    UNKNOWN = 'unknown'

class ScriptRiskLevel(Enum):
    """脚本风险级别"""
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    NONE = 'none'

@dataclass
class ExtractedScript:
    """提取的脚本信息"""
    language: ScriptLanguage
    offset: int
    size: int
    content: str
    risk_level: ScriptRiskLevel
    risk_details: List[str] = None
    script_name: str = ''
    
    def __post_init__(self):
        if self.risk_details is None:
            self.risk_details = []

@dataclass
class ScriptAnalysisResult:
    """脚本分析结果"""
    scripts: List[ExtractedScript]
    num_scripts: int
    total_size: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int

class EmbeddedScriptExtractor:
    """内嵌脚本提取器"""
    
    # 脚本引擎特征模式
    LUA_PATTERNS = [
        b'luaL_loadbuffer',
        b'luaL_loadstring',
        b'lua_pcall',
        b'lua_pushstring',
        b'lua_setglobal',
        b'LuaState',
        b'_lua_',
    ]
    
    PYTHON_PATTERNS = [
        b'Py_Initialize',
        b'Py_Finalize',
        b'PyRun_SimpleString',
        b'PyImport_ImportModule',
        b'PyObject_',
        b'_Py_',
    ]
    
    JAVASCRIPT_PATTERNS = [
        b'ExecuteScript',
        b'eval(',
        b'ExecuteJScript',
        b'VBScript',
        b'JScript',
        b'ActiveScript',
        b'mshtml',
    ]
    
    VBSCRIPT_PATTERNS = [
        b'VBScript',
        b'ExecuteVB',
        b'RunVB',
        b'CreateObject',
        b'WScript',
    ]
    
    # 脚本内容特征
    LUA_SIGNATURES = [
        b'function ',
        b'local ',
        b'end\n',
        b'else\n',
        b'then\n',
        b'while ',
        b'for ',
        b'do\n',
        b'return ',
        b'print(',
    ]
    
    PYTHON_SIGNATURES = [
        b'def ',
        b'class ',
        b'import ',
        b'from ',
        b'print(',
        b'__init__',
        b'self.',
        b'lambda ',
        b'elif ',
        b'except ',
    ]
    
    JS_SIGNATURES = [
        b'function ',
        b'var ',
        b'let ',
        b'const ',
        b'function(',
        b'=>',
        b'console.log',
        b'document.',
        b'window.',
    ]
    
    # 危险API模式
    DANGEROUS_FUNCTIONS = {
        ScriptLanguage.LUA: [
            b'os.execute',
            b'io.popen',
            b'loadstring',
            b'dofile',
            b'require',
            b'package.loadlib',
        ],
        ScriptLanguage.PYTHON: [
            b'os.system',
            b'subprocess.',
            b'exec(',
            b'eval(',
            b'__import__',
            b'pickle.load',
            b'pickle.loads',
            b'marshal.load',
        ],
        ScriptLanguage.JAVASCRIPT: [
            b'eval(',
            b'exec(',
            b'Function(',
            b'document.write',
            b'XMLHttpRequest',
            b'fetch(',
            b'WebSocket',
        ],
        ScriptLanguage.VBSCRIPT: [
            b'CreateObject',
            b'WScript.Shell',
            b'Shell.Application',
            b'Run(',
            b'Execute',
        ],
    }
    
    def __init__(self, binary_path: str = None, binary_data: bytes = None):
        """初始化内嵌脚本提取器"""
        self.binary_path = binary_path
        self.binary_data = binary_data
        self.scripts: List[ExtractedScript] = []
        
        if binary_path and not binary_data:
            self._load_binary()
    
    def _load_binary(self):
        """加载二进制文件"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            logger.info(f"已加载二进制文件: {self.binary_path}")
        except Exception as e:
            logger.error(f"加载二进制文件失败: {e}")
    
    def _detect_script_engine(self) -> List[ScriptLanguage]:
        """检测二进制中使用的脚本引擎"""
        engines = []
        
        if not self.binary_data:
            return engines
        
        if any(pattern in self.binary_data for pattern in self.LUA_PATTERNS):
            engines.append(ScriptLanguage.LUA)
        
        if any(pattern in self.binary_data for pattern in self.PYTHON_PATTERNS):
            engines.append(ScriptLanguage.PYTHON)
        
        if any(pattern in self.binary_data for pattern in self.JAVASCRIPT_PATTERNS):
            engines.append(ScriptLanguage.JAVASCRIPT)
        
        if any(pattern in self.binary_data for pattern in self.VBSCRIPT_PATTERNS):
            engines.append(ScriptLanguage.VBSCRIPT)
        
        return engines
    
    def _find_script_boundaries(self, language: ScriptLanguage) -> List[Tuple[int, int]]:
        """查找脚本内容的边界"""
        boundaries = []
        
        if language == ScriptLanguage.LUA:
            signatures = self.LUA_SIGNATURES
        elif language == ScriptLanguage.PYTHON:
            signatures = self.PYTHON_SIGNATURES
        elif language == ScriptLanguage.JAVASCRIPT:
            signatures = self.JS_SIGNATURES
        else:
            return boundaries
        
        # 查找连续的字符串区域
        # 使用简单的启发式：查找以常见脚本模式开头的区域
        for sig in signatures:
            offset = 0
            while offset < len(self.binary_data):
                pos = self.binary_data.find(sig, offset)
                if pos == -1:
                    break
                
                # 尝试找到字符串边界
                start = pos
                # 向前查找可能的字符串开始
                while start > 0 and self._is_text_byte(self.binary_data[start-1]):
                    start -= 1
                
                # 向后查找字符串结束
                end = pos + len(sig)
                while end < len(self.binary_data) and self._is_text_byte(self.binary_data[end]):
                    end += 1
                
                # 只保留合理大小的脚本片段
                if 10 < (end - start) < 100000:
                    boundaries.append((start, end))
                
                offset = end
        
        # 去重
        unique_boundaries = []
        seen = set()
        for start, end in boundaries:
            if (start, end) not in seen:
                seen.add((start, end))
                unique_boundaries.append((start, end))
        
        return unique_boundaries
    
    def _is_text_byte(self, byte: int) -> bool:
        """判断字节是否为可打印文本"""
        # 可打印ASCII或UTF-8文本
        if 0x20 <= byte <= 0x7E:  # 可打印ASCII
            return True
        if byte in [0x09, 0x0A, 0x0D]:  # 制表符、换行符、回车符
            return True
        # UTF-8多字节字符
        if 0xC0 <= byte <= 0xFD:
            return True
        return False
    
    def _extract_script_content(self, offset: int, size: int) -> Optional[str]:
        """提取脚本内容"""
        try:
            content = self.binary_data[offset:offset+size]
            # 尝试解码
            return content.decode('utf-8', errors='replace')
        except Exception as e:
            logger.debug(f"提取脚本内容失败: {e}")
            return None
    
    def _analyze_script_risk(self, content: str, language: ScriptLanguage) -> Tuple[ScriptRiskLevel, List[str]]:
        """分析脚本风险级别"""
        risk_details = []
        level = ScriptRiskLevel.NONE
        
        dangerous_funcs = self.DANGEROUS_FUNCTIONS.get(language, [])
        
        for func in dangerous_funcs:
            if func.decode('ascii') in content:
                risk_details.append(f"危险函数调用: {func.decode('ascii')}")
        
        if any(keyword in content.lower() for keyword in ['shell', 'cmd', 'command', 'rm -rf', 'delete']):
            risk_details.append("可能的命令执行")
        
        if any(keyword in content.lower() for keyword in ['network', 'socket', 'http', 'fetch', 'connect']):
            risk_details.append("可能的网络通信")
        
        if any(keyword in content.lower() for keyword in ['readfile', 'writefile', 'filesystem', 'open(', 'io.open']):
            risk_details.append("可能的文件系统操作")
        
        if len(risk_details) >= 2:
            level = ScriptRiskLevel.HIGH
        elif len(risk_details) >= 1:
            level = ScriptRiskLevel.MEDIUM
        else:
            level = ScriptRiskLevel.LOW
        
        return level, risk_details
    
    def _extract_from_resources(self) -> List[ExtractedScript]:
        """从资源段提取脚本"""
        scripts = []
        
        if not self.binary_data:
            return scripts
        
        # 查找可能包含脚本的资源区域
        # 脚本通常以字符串形式存储
        null_positions = [i for i, byte in enumerate(self.binary_data) if byte == 0]
        
        for i in range(len(null_positions) - 1):
            start = null_positions[i] + 1
            end = null_positions[i + 1]
            size = end - start
            
            if 10 < size < 100000:
                try:
                    content = self.binary_data[start:end].decode('utf-8')
                    # 检查是否看起来像脚本
                    if any(s in content for s in ['function', 'def ', 'var ', 'local ']):
                        language = self._detect_language(content)
                        level, details = self._analyze_script_risk(content, language)
                        
                        scripts.append(ExtractedScript(
                            language=language,
                            offset=start,
                            size=size,
                            content=content,
                            risk_level=level,
                            risk_details=details
                        ))
                except:
                    continue
        
        return scripts
    
    def _detect_language(self, content: str) -> ScriptLanguage:
        """根据内容检测脚本语言"""
        if any(p in content for p in ['local ', 'function(', 'end\n', 'then\n']):
            return ScriptLanguage.LUA
        
        if any(p in content for p in ['def ', 'class ', 'import ', 'self.']):
            return ScriptLanguage.PYTHON
        
        if any(p in content for p in ['var ', 'let ', 'const ', 'console.log']):
            return ScriptLanguage.JAVASCRIPT
        
        if any(p in content for p in ['Sub ', 'Function ', 'Set ', 'WScript']):
            return ScriptLanguage.VBSCRIPT
        
        return ScriptLanguage.UNKNOWN
    
    def extract(self) -> ScriptAnalysisResult:
        """执行脚本提取"""
        if not self.binary_data:
            return ScriptAnalysisResult(
                scripts=[],
                num_scripts=0,
                total_size=0,
                high_risk_count=0,
                medium_risk_count=0,
                low_risk_count=0
            )
        
        # 检测脚本引擎
        engines = self._detect_script_engine()
        logger.info(f"检测到脚本引擎: {[e.value for e in engines]}")
        
        # 从资源提取脚本
        self.scripts = self._extract_from_resources()
        
        # 额外查找脚本边界
        for engine in engines:
            boundaries = self._find_script_boundaries(engine)
            for start, end in boundaries:
                content = self._extract_script_content(start, end - start)
                if content:
                    level, details = self._analyze_script_risk(content, engine)
                    
                    # 检查是否已存在
                    exists = any(s.offset == start and s.size == (end - start) for s in self.scripts)
                    if not exists:
                        self.scripts.append(ExtractedScript(
                            language=engine,
                            offset=start,
                            size=end - start,
                            content=content,
                            risk_level=level,
                            risk_details=details
                        ))
        
        # 统计风险级别
        high_count = sum(1 for s in self.scripts if s.risk_level == ScriptRiskLevel.HIGH)
        medium_count = sum(1 for s in self.scripts if s.risk_level == ScriptRiskLevel.MEDIUM)
        low_count = sum(1 for s in self.scripts if s.risk_level == ScriptRiskLevel.LOW)
        
        return ScriptAnalysisResult(
            scripts=self.scripts,
            num_scripts=len(self.scripts),
            total_size=sum(s.size for s in self.scripts),
            high_risk_count=high_count,
            medium_risk_count=medium_count,
            low_risk_count=low_count
        )
    
    def save_scripts(self, output_dir: str) -> List[str]:
        """保存提取的脚本到文件"""
        saved_paths = []
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for i, script in enumerate(self.scripts):
            filename = f"script_{i}_{script.language.value}.txt"
            filepath = os.path.join(output_dir, filename)
            
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"// Language: {script.language.value}\n")
                    f.write(f"// Offset: 0x{script.offset:08X}\n")
                    f.write(f"// Size: {script.size} bytes\n")
                    f.write(f"// Risk Level: {script.risk_level.value}\n")
                    if script.risk_details:
                        f.write(f"// Risk Details: {', '.join(script.risk_details)}\n")
                    f.write("// ============================================\n\n")
                    f.write(script.content)
                
                saved_paths.append(filepath)
                logger.info(f"脚本已保存: {filepath}")
            except Exception as e:
                logger.error(f"保存脚本失败 {filepath}: {e}")
        
        return saved_paths
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        result = self.extract()
        
        return {
            'num_scripts': result.num_scripts,
            'total_size': result.total_size,
            'high_risk_count': result.high_risk_count,
            'medium_risk_count': result.medium_risk_count,
            'low_risk_count': result.low_risk_count,
            'scripts': [{
                'language': s.language.value,
                'offset': s.offset,
                'size': s.size,
                'risk_level': s.risk_level.value,
                'risk_details': s.risk_details
            } for s in result.scripts]
        }
