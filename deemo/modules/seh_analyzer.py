import os
import logging
import struct
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class SEHChainStatus(Enum):
    """SEH链状态枚举"""
    SAFE = 'safe'
    OVERFLOWABLE = 'overflowable'
    UNKNOWN = 'unknown'

class VEHStatus(Enum):
    """VEH状态枚举"""
    NONE = 'none'
    WEAK_VALIDATION = 'weak_validation'
    STRONG_VALIDATION = 'strong_validation'
    UNKNOWN = 'unknown'

@dataclass
class SEHRecord:
    """SEH记录结构"""
    offset: int
    handler_address: int
    next_record: int
    is_overwritable: bool = False
    description: str = ''

@dataclass
class VEHandler:
    """VEH处理器信息"""
    address: int
    name: str
    validation_level: str
    is_reachable: bool = True
    risk_score: float = 0.0

@dataclass
class SEHAnalysisResult:
    """SEH分析结果"""
    seh_records: List[SEHRecord]
    seh_chain_status: SEHChainStatus
    ve_handlers: List[VEHandler]
    veh_status: VEHStatus
    vulnerabilities: List[str]
    exploitation_suggestions: List[str]

class SEHAnalyzer:
    """Windows SEH/VEH 分析器"""
    
    # SEH相关的特征模式
    SEH_INDICATORS = [
        b'\x64\xa1\x00\x00\x00\x00',  # mov eax, fs:[0]
        b'\x64\x8b\x0d\x00\x00\x00\x00',  # mov ecx, fs:[0]
        b'\x64\x89\x0d\x00\x00\x00\x00',  # mov fs:[0], ecx
        b'\x64\xff\x35\x00\x00\x00\x00',  # push dword ptr fs:[0]
        b'\x64\xff\x25\x00\x00\x00\x00',  # jmp qword ptr fs:[0]
    ]
    
    SEH_HANDLER_FUNCTIONS = [
        b'except_handler4',
        b'except_handler3',
        b'except_handler2',
        b'except_handler',
        b'_except_handler4',
        b'_except_handler3',
        b'_except_handler2',
        b'_except_handler',
        b'_XcptFilter',
        b'__C_specific_handler',
    ]
    
    VEH_FUNCTIONS = [
        b'AddVectoredExceptionHandler',
        b'RemoveVectoredExceptionHandler',
        b'AddVectoredContinueHandler',
        b'RemoveVectoredContinueHandler',
        b'_AddVectoredExceptionHandler',
        b'_RemoveVectoredExceptionHandler',
    ]
    
    def __init__(self, pe_data: bytes = None, pe_path: str = None):
        """初始化SEH分析器"""
        self.pe_data = pe_data
        self.pe_path = pe_path
        self.seh_records: List[SEHRecord] = []
        self.ve_handlers: List[VEHandler] = []
        self.seh_chain_status = SEHChainStatus.UNKNOWN
        self.veh_status = VEHStatus.NONE
        
        if pe_path and not pe_data:
            self._load_pe_file(pe_path)
    
    def _load_pe_file(self, pe_path: str):
        """加载PE文件"""
        try:
            with open(pe_path, 'rb') as f:
                self.pe_data = f.read()
            logger.info(f"已加载 PE 文件: {pe_path}")
        except Exception as e:
            logger.error(f"加载 PE 文件失败: {e}")
    
    def _is_pe_binary(self) -> bool:
        """检查是否为PE二进制文件"""
        if not self.pe_data:
            return False
        return self.pe_data[:2] == b'MZ'
    
    def _find_pattern(self, pattern: bytes) -> List[int]:
        """在PE数据中查找模式"""
        results = []
        offset = 0
        while True:
            idx = self.pe_data.find(pattern, offset)
            if idx == -1:
                break
            results.append(idx)
            offset = idx + 1
        return results
    
    def _parse_pe_headers(self) -> Dict[str, Any]:
        """解析PE文件头"""
        headers = {}
        if not self._is_pe_binary():
            return headers
        
        # 检查数据长度是否足够
        if len(self.pe_data) < 0x40:
            return headers
        
        # DOS头
        e_lfanew = struct.unpack('<I', self.pe_data[0x3C:0x40])[0]
        
        # NT头
        pe_signature = self.pe_data[e_lfanew:e_lfanew+4]
        if pe_signature != b'PE\x00\x00':
            return headers
        
        # 文件头
        machine = struct.unpack('<H', self.pe_data[e_lfanew+4:e_lfanew+6])[0]
        num_sections = struct.unpack('<H', self.pe_data[e_lfanew+6:e_lfanew+8])[0]
        
        # 可选头
        opt_header_offset = e_lfanew + 24
        magic = struct.unpack('<H', self.pe_data[opt_header_offset:opt_header_offset+2])[0]
        
        headers.update({
            'e_lfanew': e_lfanew,
            'machine': machine,
            'num_sections': num_sections,
            'is_64bit': magic == 0x20B,
        })
        
        return headers
    
    def _extract_seh_chain_patterns(self) -> List[Tuple[int, str]]:
        """提取SEH链相关模式"""
        patterns = []
        
        for indicator in self.SEH_INDICATORS:
            offsets = self._find_pattern(indicator)
            for offset in offsets:
                patterns.append((offset, 'SEH_REGISTER'))
        
        for handler in self.SEH_HANDLER_FUNCTIONS:
            offsets = self._find_pattern(handler)
            for offset in offsets:
                patterns.append((offset, 'SEH_HANDLER_REFERENCE'))
        
        return patterns
    
    def _extract_veh_patterns(self) -> List[Tuple[int, str]]:
        """提取VEH相关模式"""
        patterns = []
        
        for func in self.VEH_FUNCTIONS:
            offsets = self._find_pattern(func)
            for offset in offsets:
                patterns.append((offset, 'VEH_FUNCTION_CALL'))
        
        return patterns
    
    def _analyze_seh_chain(self) -> SEHChainStatus:
        """分析SEH链安全性"""
        patterns = self._extract_seh_chain_patterns()
        
        if not patterns:
            return SEHChainStatus.UNKNOWN
        
        # 检查是否存在可被溢出覆盖的SEH记录
        has_fs_access = any(p[1] == 'SEH_REGISTER' for p in patterns)
        has_handler_ref = any(p[1] == 'SEH_HANDLER_REFERENCE' for p in patterns)
        
        # 简单的启发式分析：如果存在fs:[0]写入且代码中有缓冲区操作，标记为可能可溢出
        if has_fs_access:
            # 检查是否有典型的缓冲区操作模式
            buffer_patterns = [
                b'strcpy', b'strcat', b'sprintf', b'gets',
                b'memcpy', b'memmove', b'_strcpy', b'_strcat',
            ]
            for pattern in buffer_patterns:
                if pattern in self.pe_data:
                    return SEHChainStatus.OVERFLOWABLE
        
        return SEHChainStatus.SAFE
    
    def _analyze_veh_handlers(self) -> Tuple[List[VEHandler], VEHStatus]:
        """分析VEH处理器"""
        patterns = self._extract_veh_patterns()
        handlers = []
        
        if not patterns:
            return handlers, VEHStatus.NONE
        
        # 模拟VEH处理器分析
        for offset, pattern_type in patterns:
            handler = VEHandler(
                address=offset,
                name='VEH_Handler',
                validation_level='unknown',
                is_reachable=True,
                risk_score=0.5  # 默认风险评分
            )
            handlers.append(handler)
        
        # 检查是否有参数验证逻辑
        validation_patterns = [
            b'IsValidHandler', b'ValidateHandler',
            b'CheckHandler', b'VerifyHandler'
        ]
        has_validation = any(p in self.pe_data for p in validation_patterns)
        
        if has_validation:
            return handlers, VEHStatus.STRONG_VALIDATION
        else:
            return handlers, VEHStatus.WEAK_VALIDATION
    
    def _generate_exploitation_suggestions(self) -> List[str]:
        """生成利用建议"""
        suggestions = []
        
        if self.seh_chain_status == SEHChainStatus.OVERFLOWABLE:
            suggestions.append(
                "[+] SEH链可被溢出覆盖，建议使用经典SEH利用技术："
                "覆盖next SEH为POP/POP/RET gadget，handler为shellcode地址"
            )
            suggestions.append(
                "[+] 尝试查找模块基址+偏移方式绕过ASLR"
            )
        
        if self.veh_status == VEHStatus.WEAK_VALIDATION:
            suggestions.append(
                "[+] VEH处理器验证较弱，可尝试通过异常触发VEH并劫持控制流"
            )
        
        if self.seh_records:
            suggestions.append(
                f"[+] 发现 {len(self.seh_records)} 个SEH记录，可尝试定位可写SEH链"
            )
        
        return suggestions
    
    def analyze(self) -> SEHAnalysisResult:
        """执行完整的SEH/VEH分析"""
        if not self._is_pe_binary():
            logger.warning("输入不是有效的PE二进制文件")
            return SEHAnalysisResult(
                seh_records=[],
                seh_chain_status=SEHChainStatus.UNKNOWN,
                ve_handlers=[],
                veh_status=VEHStatus.NONE,
                vulnerabilities=[],
                exploitation_suggestions=[]
            )
        
        # 提取PE头信息
        headers = self._parse_pe_headers()
        logger.info(f"PE架构: {'x64' if headers.get('is_64bit') else 'x86'}")
        
        # 分析SEH链
        self.seh_chain_status = self._analyze_seh_chain()
        
        # 分析VEH处理器
        self.ve_handlers, self.veh_status = self._analyze_veh_handlers()
        
        # 收集漏洞信息
        vulnerabilities = []
        if self.seh_chain_status == SEHChainStatus.OVERFLOWABLE:
            vulnerabilities.append("SEH链可能存在缓冲区溢出漏洞")
        if self.veh_status == VEHStatus.WEAK_VALIDATION:
            vulnerabilities.append("VEH处理器验证不足")
        
        # 生成利用建议
        suggestions = self._generate_exploitation_suggestions()
        
        return SEHAnalysisResult(
            seh_records=self.seh_records,
            seh_chain_status=self.seh_chain_status,
            ve_handlers=self.ve_handlers,
            veh_status=self.veh_status,
            vulnerabilities=vulnerabilities,
            exploitation_suggestions=suggestions
        )
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        result = self.analyze()
        
        return {
            'seh_chain_status': result.seh_chain_status.value,
            'veh_status': result.veh_status.value,
            'num_seh_records': len(result.seh_records),
            'num_veh_handlers': len(result.ve_handlers),
            'vulnerabilities': result.vulnerabilities,
            'exploitation_suggestions': result.exploitation_suggestions,
        }
    
    def detect_seh_hijack_opportunity(self) -> bool:
        """检测是否存在SEH劫持机会"""
        result = self.analyze()
        return result.seh_chain_status == SEHChainStatus.OVERFLOWABLE
    
    def detect_veh_hijack_opportunity(self) -> bool:
        """检测是否存在VEH劫持机会"""
        result = self.analyze()
        return result.veh_status == VEHStatus.WEAK_VALIDATION
