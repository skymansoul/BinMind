"""
托管语言运行时字节码分析模块

支持 .NET 程序集（CLR）和 Java 字节码的分析，提取类型、方法信息，
反编译为中间语言，并进行漏洞模式检测。
"""

import logging
import os
import re
import subprocess
import struct
import zipfile
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from config import Config, ensure_directories, get_current_ai_model, call_ai_with_retry, mask_sensitive_data

logger = logging.getLogger(__name__)

# 魔数常量
JAVA_CLASS_MAGIC = 0xCAFEBABE
CLR_PE_SIGNATURE = 0x5A4D  # MZ header
CLR_DIRECTORY_ENTRY = 14  # PE CLR Data Directory entry index

# Java 危险方法模式（模块级别）
JAVA_DANGEROUS_METHODS = {
    'ObjectInputStream': {'description': '反序列化漏洞 - ObjectInputStream 可导致远程代码执行', 'severity': 'Critical'},
    'ObjectInputStream.readObject': {'description': '反序列化漏洞 - ObjectInputStream 可导致远程代码执行', 'severity': 'Critical'},
    'ObjectInputStream.readUnshared': {'description': '反序列化漏洞 - readUnshared', 'severity': 'High'},
    'XMLDecoder.readObject': {'description': '反序列化漏洞 - XMLDecoder 高危', 'severity': 'Critical'},
    'Yaml.load': {'description': '反序列化漏洞 - YAML 解析', 'severity': 'High'},
    'SnakeYaml.load': {'description': '反序列化漏洞 - SnakeYAML', 'severity': 'High'},
    'JSON.parseObject': {'description': '反序列化漏洞 - FastJSON', 'severity': 'High'},
    'Class.forName': {'description': '动态加载 - 加载任意类', 'severity': 'Medium'},
    'ClassLoader.loadClass': {'description': '动态加载 - 类加载器', 'severity': 'Medium'},
    'Method.invoke': {'description': '动态调用 - 反射调用方法', 'severity': 'Medium'},
    'Constructor.newInstance': {'description': '动态创建 - 反射创建实例', 'severity': 'Medium'},
    'getMethod': {'description': '反射获取 - 获取方法', 'severity': 'Low'},
    'Runtime.exec': {'description': 'Command execution via Runtime.exec', 'severity': 'Critical'},
    'ProcessBuilder.start': {'description': '命令执行 - 进程构建器', 'severity': 'Critical'},
    'FileInputStream': {'description': '文件操作 - 文件输入流', 'severity': 'Low'},
    'FileOutputStream': {'description': '文件操作 - 文件输出流', 'severity': 'Low'},
    'FileReader': {'description': '文件操作 - 文件读取', 'severity': 'Low'},
    'FileWriter': {'description': '文件操作 - 文件写入', 'severity': 'Low'},
    'Files.readAllBytes': {'description': '文件操作 - 读取文件', 'severity': 'Low'},
    'Files.write': {'description': '文件操作 - 写入文件', 'severity': 'Low'},
    'URL.openStream': {'description': '网络请求 - 打开 URL', 'severity': 'Medium'},
    'URLConnection': {'description': '网络连接 - URL 连接', 'severity': 'Medium'},
    'Socket': {'description': '网络套接字 - Socket', 'severity': 'Medium'},
    'HttpURLConnection': {'description': 'HTTP 连接 - HTTP 请求', 'severity': 'Medium'},
    'MessageDigest.getInstance("MD5")': {'description': '弱加密 - MD5', 'severity': 'Low'},
    'MessageDigest.getInstance("SHA1")': {'description': '弱加密 - SHA1', 'severity': 'Low'},
    'Cipher.getInstance("DES")': {'description': '弱加密 - DES', 'severity': 'Low'},
    'Statement.executeQuery': {'description': 'SQL 执行 - 可能存在注入', 'severity': 'High'},
    'Statement.executeUpdate': {'description': 'SQL 执行 - 更新操作', 'severity': 'High'},
    'PreparedStatement': {'description': 'SQL 预编译 - 相对安全但需检查', 'severity': 'Low'},
    'Connection.createStatement': {'description': 'SQL 连接 - 创建语句', 'severity': 'Medium'},
    'InitialContext.lookup': {'description': 'JNDI 注入 - 远程查找', 'severity': 'Critical'},
    'Context.lookup': {'description': 'JNDI 注入 - 上下文查找', 'severity': 'Critical'},
    'Thread.start': {'description': '线程启动 - 多线程风险', 'severity': 'Low'},
    'System.loadLibrary': {'description': '本地库加载 - 加载 JNI', 'severity': 'Medium'},
    'System.load': {'description': '本地库加载 - 加载库文件', 'severity': 'Medium'},
}

# .NET 危险方法模式（模块级别）
DOTNET_DANGEROUS_METHODS = {
    'BinaryFormatter.Deserialize': {'description': '反序列化漏洞 - BinaryFormatter 可导致远程代码执行', 'severity': 'Critical'},
    'Type.InvokeMember': {'description': '动态调用 - 反射可能导致绕过访问控制', 'severity': 'High'},
    'XmlSerializer.Deserialize': {'description': '反序列化漏洞 - XmlSerializer', 'severity': 'High'},
    'DataContractSerializer.ReadObject': {'description': '反序列化漏洞 - DataContractSerializer', 'severity': 'High'},
    'JavaScriptSerializer.Deserialize': {'description': '反序列化漏洞 - JavaScriptSerializer', 'severity': 'High'},
    'Type.GetType': {'description': '动态加载 - 获取类型', 'severity': 'Medium'},
    'Assembly.Load': {'description': '动态加载 - 加载程序集', 'severity': 'Medium'},
    'Activator.CreateInstance': {'description': '动态创建 - 反射创建实例', 'severity': 'Medium'},
    'MethodInfo.Invoke': {'description': '动态调用 - 反射调用方法', 'severity': 'Medium'},
    'Process.Start': {'description': '命令执行 - 执行系统命令', 'severity': 'Critical'},
    'File.OpenRead': {'description': '文件操作 - 文件读取', 'severity': 'Low'},
    'File.OpenWrite': {'description': '文件操作 - 文件写入', 'severity': 'Low'},
    'File.ReadAllText': {'description': '文件操作 - 读取文本', 'severity': 'Low'},
    'File.WriteAllText': {'description': '文件操作 - 写入文本', 'severity': 'Low'},
    'WebClient.DownloadString': {'description': '网络请求 - 下载字符串', 'severity': 'Medium'},
    'WebClient.DownloadFile': {'description': '网络请求 - 下载文件', 'severity': 'Medium'},
    'HttpClient.GetString': {'description': 'HTTP 请求 - 获取字符串', 'severity': 'Medium'},
    'HttpWebRequest.Create': {'description': 'HTTP 请求 - 创建请求', 'severity': 'Medium'},
    'MD5.Create': {'description': '弱加密 - MD5', 'severity': 'Low'},
    'SHA1.Create': {'description': '弱加密 - SHA1', 'severity': 'Low'},
    'SqlCommand.ExecuteReader': {'description': 'SQL 执行 - 可能存在注入', 'severity': 'High'},
    'SqlCommand.ExecuteNonQuery': {'description': 'SQL 执行 - 更新操作', 'severity': 'High'},
    'SqlConnection.Open': {'description': 'SQL 连接 - 数据库连接', 'severity': 'Low'},
}


class ManagedCodeType(Enum):
    """托管代码类型枚举"""
    UNKNOWN = 'unknown'
    DOTNET = 'dotnet'
    JAVA = 'java'


@dataclass
class MethodInfo:
    """方法信息数据类"""
    name: str
    class_name: str = ''
    namespace: str = ''
    signature: str = ''
    is_public: bool = False
    is_static: bool = False
    is_dangerous: bool = False
    danger_type: str = ''
    danger_reasons: List[str] = field(default_factory=lambda: [])
    il_code: str = ''
    bytecode: bytes = field(default_factory=lambda: b'')
    instructions: List[str] = field(default_factory=lambda: [])
    parameters: List[str] = field(default_factory=lambda: [])
    return_type: str = ''


@dataclass
class ClassInfo:
    """类信息数据类"""
    name: str
    namespace: str = ''
    methods: List[MethodInfo] = field(default_factory=lambda: [])
    fields: List[str] = field(default_factory=lambda: [])
    base_class: str = ''
    interfaces: List[str] = field(default_factory=lambda: [])
    is_public: bool = False
    is_dangerous: bool = False
    danger_reasons: List[str] = field(default_factory=lambda: [])
    attributes: List[str] = field(default_factory=lambda: [])


@dataclass
class ManagedCodeAnalysisResult:
    """托管代码分析结果数据类"""
    file_path: str = ''
    code_type: ManagedCodeType = ManagedCodeType.UNKNOWN
    classes: List[ClassInfo] = field(default_factory=lambda: [])
    dangerous_methods: List[MethodInfo] = field(default_factory=lambda: [])
    vulnerabilities: List[Any] = field(default_factory=lambda: [])
    decompiled_code: str = ''
    metadata: Dict[str, Any] = field(default_factory=lambda: {})
    summary: str = ''
    error: Optional[str] = None


class ManagedCodeAnalyzer:
    """
    托管代码分析器
    
    支持 .NET 和 Java 字节码的分析，包括：
    - 文件格式识别
    - 类和方法提取
    - 漏洞模式检测
    - 反编译输出
    """
    
    # .NET 危险方法模式
    DOTNET_DANGEROUS_METHODS = {
        # 反序列化漏洞
        'BinaryFormatter.Deserialize': '反序列化漏洞 - BinaryFormatter 可导致远程代码执行',
        'BinaryFormatter.UnsafeDeserialize': '反序列化漏洞 - UnsafeDeserialize 高危',
        'JavaScriptSerializer.Deserialize': '反序列化漏洞 - JavaScriptSerializer 可能不安全',
        'DataContractSerializer.ReadObject': '反序列化漏洞 - DataContractSerializer',
        'XmlSerializer.Deserialize': '反序列化漏洞 - XmlSerializer 类型混淆风险',
        'NetDataContractSerializer.ReadObject': '反序列化漏洞 - NetDataContractSerializer',
        'ObjectStateFormatter.Deserialize': '反序列化漏洞 - ViewState 解析',
        
        # 反射和动态调用
        'Type.InvokeMember': '动态调用 - 反射可能导致绕过访问控制',
        'MethodInfo.Invoke': '动态调用 - 反射调用',
        'Activator.CreateInstance': '动态创建 - 可能创建危险类型',
        'Assembly.Load': '动态加载 - 加载任意程序集',
        'Assembly.LoadFrom': '动态加载 - 从路径加载程序集',
        'Assembly.LoadFile': '动态加载 - 加载文件程序集',
        
        # 命令执行
        'Process.Start': '命令执行 - 可执行任意命令',
        'ProcessStartInfo': '命令执行 - 进程启动信息配置',
        
        # 文件操作
        'File.Open': '文件操作 - 文件读写',
        'File.ReadAllText': '文件操作 - 读取文件内容',
        'File.WriteAllText': '文件操作 - 写入文件',
        'FileStream': '文件操作 - 文件流操作',
        'Directory.GetFiles': '文件操作 - 目录遍历',
        
        # 网络
        'WebClient.DownloadFile': '网络下载 - 下载任意文件',
        'HttpClient': '网络请求 - HTTP 请求',
        'Socket': '网络套接字 - 网络通信',
        
        # 加密
        'MD5': '弱加密 - MD5 已不安全',
        'SHA1': '弱加密 - SHA1 已不安全',
        'DES': '弱加密 - DES 已不安全',
        'RC2': '弱加密 - RC2 已不安全',
        
        # 内存操作
        'Marshal.Copy': '内存操作 - 内存复制',
        'Marshal.PtrToStructure': '内存操作 - 指针转换',
        'Unsafe': '不安全代码 - unsafe 块',
        
        # SQL
        'SqlCommand': 'SQL 操作 - 可能存在注入',
        'SqlConnection': 'SQL 连接 - 数据库连接',
        'ExecuteNonQuery': 'SQL 执行 - 执行 SQL',
        'ExecuteReader': 'SQL 执行 - 执行查询',
    }
    
    # Java 危险方法模式
    JAVA_DANGEROUS_METHODS = {
        # 反序列化漏洞
        'ObjectInputStream.readObject': '反序列化漏洞 - ObjectInputStream 可导致远程代码执行',
        'ObjectInputStream.readUnshared': '反序列化漏洞 - readUnshared',
        'XMLDecoder.readObject': '反序列化漏洞 - XMLDecoder 高危',
        'Yaml.load': '反序列化漏洞 - YAML 解析',
        'SnakeYaml.load': '反序列化漏洞 - SnakeYAML',
        'JSON.parseObject': '反序列化漏洞 - FastJSON',
        
        # 反射
        'Class.forName': '动态加载 - 加载任意类',
        'ClassLoader.loadClass': '动态加载 - 类加载器',
        'Method.invoke': '动态调用 - 反射调用方法',
        'Constructor.newInstance': '动态创建 - 反射创建实例',
        'getMethod': '反射获取 - 获取方法',
        
        # 命令执行
        'Runtime.exec': '命令执行 - 执行系统命令',
        'ProcessBuilder.start': '命令执行 - 进程构建器',
        
        # 文件操作
        'FileInputStream': '文件操作 - 文件输入流',
        'FileOutputStream': '文件操作 - 文件输出流',
        'FileReader': '文件操作 - 文件读取',
        'FileWriter': '文件操作 - 文件写入',
        'Files.readAllBytes': '文件操作 - 读取文件',
        'Files.write': '文件操作 - 写入文件',
        
        # 网络
        'URL.openStream': '网络请求 - 打开 URL',
        'URLConnection': '网络连接 - URL 连接',
        'Socket': '网络套接字 - Socket',
        'HttpURLConnection': 'HTTP 连接 - HTTP 请求',
        
        # 加密
        'MessageDigest.getInstance("MD5")': '弱加密 - MD5',
        'MessageDigest.getInstance("SHA1")': '弱加密 - SHA1',
        'Cipher.getInstance("DES")': '弱加密 - DES',
        
        # SQL
        'Statement.executeQuery': 'SQL 执行 - 可能存在注入',
        'Statement.executeUpdate': 'SQL 执行 - 更新操作',
        'PreparedStatement': 'SQL 预编译 - 相对安全但需检查',
        'Connection.createStatement': 'SQL 连接 - 创建语句',
        
        # JNDI
        'InitialContext.lookup': 'JNDI 注入 - 远程查找',
        'Context.lookup': 'JNDI 注入 - 上下文查找',
        
        # 其他
        'Thread.start': '线程启动 - 多线程风险',
        'System.loadLibrary': '本地库加载 - 加载 JNI',
        'System.load': '本地库加载 - 加载库文件',
    }
    
    def __init__(, self)
        file_path: str = None,
        output_dir: str = None,
        use_ai: bool = True
    ):
        """
        初始化托管代码分析器

        Args:
            file_path: 要分析的文件路径（可选）
            output_dir: 输出目录
            use_ai: 是否使用 AI 辅助分析
        """
        self.file_path = file_path
        self.output_dir = output_dir or os.path.join(Config.REPORTS_DIR, 'managed_analysis')
        self.use_ai = use_ai

        # 确保输出目录存在
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except Exception as e:
                logger.warning(f"创建输出目录失败: {e}")

        self.code_type = ManagedCodeType.UNKNOWN
        self.classes: List[ClassInfo] = []
        self.dangerous_methods: List[MethodInfo] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

        # 检查依赖可用性
        self._check_dependencies()
    
    def _check_dependencies(self) -> None:
        """检查分析依赖是否可用"""
        self.ilspy_available = False
        self.cfr_available = False
        self.procyon_available = False
        
        # 检查 ILSpy
        try:
            result = subprocess.run()
                ['ilspy', '--help'],
                capture_output=True,
                timeout=5
            
            if result.returncode == 0:
                self.ilspy_available = True
                logger.info("[Managed] ILSpy 可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[Managed] ILSpy 未安装，将使用内置解析")
        
        # 检查 CFR
        try:
            result = subprocess.run()
                ['java', '-jar', 'cfr.jar', '--help'],
                capture_output=True,
                timeout=5
            
            if result.returncode == 0:
                self.cfr_available = True
                logger.info("[Managed] CFR 可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[Managed] CFR 未安装，将使用内置解析")
    
    def analyze(self, file_path: str = None) -> ManagedCodeAnalysisResult:
        """
        执行完整的托管代码分析

        Args:
            file_path: 可选的文件路径，未提供则使用 self.file_path

        Returns:
            ManagedCodeAnalysisResult 分析结果
        """
        # 如果传入了新的文件路径，更新
        target_path = file_path or self.file_path

        # 处理空或无效输入
        if not target_path or not isinstance(target_path, str):
            return ManagedCodeAnalysisResult(
                file_path=str(target_path) if target_path else '',
                code_type=ManagedCodeType.UNKNOWN,
                classes=[],
                dangerous_methods=[],
                vulnerabilities=[],
                error='File not found')
            


        # 检查路径是否安全（防止路径遍历）
        if not self._is_safe_path(target_path):
            return ManagedCodeAnalysisResult(
                file_path=target_path,
                code_type=ManagedCodeType.UNKNOWN,
                classes=[],
                dangerous_methods=[],
                vulnerabilities=[],
                error='Invalid file path')
            


        # 检查文件是否存在
        if not os.path.exists(target_path):
            return ManagedCodeAnalysisResult(
                file_path=target_path,
                code_type=ManagedCodeType.UNKNOWN,
                classes=[],
                dangerous_methods=[],
                vulnerabilities=[],
                error='File not found')
            


        self.file_path = target_path
        logger.info(f"[Managed] 开始分析: {self.file_path}")

        # 识别文件类型
        self.code_type = self._detect_code_type()

        if self.code_type == ManagedCodeType.UNKNOWN:
            logger.warning(f"[Managed] 无法识别文件类型: {self.file_path}")
            return ManagedCodeAnalysisResult(
                file_path=self.file_path,
                code_type=ManagedCodeType.UNKNOWN,
                summary='无法识别的文件类型')
            


        # 根据类型执行分析
        if self.code_type == ManagedCodeType.DOTNET:
            self._analyze_dotnet()
        elif self.code_type == ManagedCodeType.JAVA:
            self._analyze_java()

        # 检测漏洞
        self._detect_vulnerabilities()

        # 生成反编译代码
        decompiled = self._decompile()

        # 生成摘要
        summary = self._generate_summary()

        return ManagedCodeAnalysisResult(
            file_path=self.file_path,
            code_type=self.code_type,
            classes=self.classes,
            dangerous_methods=self.dangerous_methods,
            vulnerabilities=self.vulnerabilities,
            decompiled_code=decompiled,
            metadata=self._extract_metadata(),
            summary=summary)
        


    def _is_safe_path(self, path: str) -> bool:
        """检查路径是否安全（防止路径遍历）"""
        if not path:
            return False
        # 检查路径遍历模式
        if '..' in path:
            # 允许路径中包含 '..' 但需要规范化检查
            try:
                norm = os.path.normpath(path)
                if norm.startswith('..') or '/../' in norm or '\\..\\' in norm:
                    return False
            except Exception:
                return False
        return True

    def _detect_code_type(self, file_path: str = None) -> ManagedCodeType:
        """
        检测托管代码类型

        Args:
            file_path: 可选文件路径，未提供则使用 self.file_path

        Returns:
            ManagedCodeType 枚举值
        """
        target_path = file_path or self.file_path,
        if not target_path or not os.path.exists(target_path):
            return ManagedCodeType.UNKNOWN

        try:
            with open(target_path, 'rb') as f:
                # 读取前4字节检查 Java 魔数
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    return ManagedCodeType.UNKNOWN
                magic = struct.unpack('>I', magic_bytes)[0]

                if magic == JAVA_CLASS_MAGIC:
                    logger.info("[Managed] 检测到 Java class 文件")
                    return ManagedCodeType.JAVA

                # 检查 PE 文件（可能是 .NET）
                f.seek(0)
                pe_sig = struct.unpack('<H', f.read(2))[0]

                if pe_sig == CLR_PE_SIGNATURE:
                    # 进一步检查 CLR 头
                    f.seek(60)  # PE header offset
                    pe_header_offset = struct.unpack('<I', f.read(4))[0]

                    f.seek(pe_header_offset + 24 + CLR_DIRECTORY_ENTRY * 8)
                    clr_dir_offset = struct.unpack('<I', f.read(4))[0]
                    clr_dir_size = struct.unpack('<I', f.read(4))[0]

                    if clr_dir_offset != 0 and clr_dir_size != 0:
                        logger.info("[Managed] 检测到 .NET 程序集")
                        return ManagedCodeType.DOTNET

                # 检查 JAR 文件（ZIP 格式）
                f.seek(0)
                zip_magic = f.read(4)
                if zip_magic == b'PK\x03\x04':
                    # 检查是否包含 .class 文件
                    try:
                        with zipfile.ZipFile(target_path, 'r') as zf:
                            class_files = [n for n in zf.namelist() if n.endswith('.class')]
                            if class_files:
                                logger.info("[Managed] 检测到 Java JAR 文件")
                                return ManagedCodeType.JAVA
                    except zipfile.BadZipFile:
                        pass

        except Exception as e:
            logger.error(f"[Managed] 文件类型检测失败: {e}")

        return ManagedCodeType.UNKNOWN
    
    def _analyze_dotnet(self) -> None:
        """
        分析 .NET 程序集
        """
        logger.info("[Managed] 分析 .NET 程序集")
        
        if self.ilspy_available:
            self._analyze_dotnet_with_ilspy()
        else:
            self._analyze_dotnet_builtin()
    
    def _analyze_dotnet_with_ilspy(self) -> None:
        """
        使用 ILSpy 分析 .NET 程序集
        """
        try:
            # 使用 ILSpy 输出反编译结果
            result = subprocess.run()
                ['ilspy', '--output', self.output_dir, self.file_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            
            
            if result.returncode == 0:
                # 解析 ILSpy 输出
                self._parse_ilspy_output(result.stdout)
            else:
                logger.warning(f"[Managed] ILSpy 分析失败: {result.stderr}")
                self._analyze_dotnet_builtin()
                
        except subprocess.TimeoutExpired:
            logger.warning("[Managed] ILSpy 分析超时")
            self._analyze_dotnet_builtin()
        except Exception as e:
            logger.error(f"[Managed] ILSpy 分析出错: {e}")
            self._analyze_dotnet_builtin()
    
    def _analyze_dotnet_builtin(self) -> None:
        """
        内置 .NET 分析（基础 PE/CLR 解析）
        """
        try:
            with open(self.file_path, 'rb') as f:
                # 解析 CLR 头
                f.seek(0)
                pe_sig = f.read(2)
                
                if pe_sig != b'MZ':
                    return
                
                # 获取 PE header 位置
                f.seek(60)
                pe_header_offset = struct.unpack('<I', f.read(4))[0]
                
                # 检查 PE signature
                f.seek(pe_header_offset)
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return
                
                # 获取 CLR 目录
                f.seek(pe_header_offset + 24 + CLR_DIRECTORY_ENTRY * 8)
                clr_dir_offset = struct.unpack('<I', f.read(4))[0]
                clr_dir_size = struct.unpack('<I', f.read(4))[0]
                
                if clr_dir_offset == 0:
                    return
                
                # 解析 CLR 头
                f.seek(clr_dir_offset)
                clr_header = f.read(72)
                
                # CLR 头结构
                cb = struct.unpack('<I', clr_header[0:4])[0]
                runtime_version = struct.unpack('<H', clr_header[4:6])[0], struct.unpack('<H', clr_header[6:8])[0]
                metadata_offset = struct.unpack('<I', clr_header[8:12])[0]
                metadata_size = struct.unpack('<I', clr_header[12:16])[0]
                
                # 提取字符串表
                strings = self._extract_dotnet_strings(f)
                
                # 基于字符串检测危险方法
                self._detect_dangerous_from_strings(strings, ManagedCodeType.DOTNET)
                
                self._extract_metadata()['runtime_version'] = f'{runtime_version[0]}.{runtime_version[1]}'
                
        except Exception as e:
            logger.error(f"[Managed] 内置 .NET 分析失败: {e}")
    
    def _extract_dotnet_strings(self, f) -> List[str]:
        """
        从 .NET 程序集提取字符串
        
        Args:
            f: 文件对象
            
        Returns:
            字符串列表
        """
        strings = []
        
        try:
            # 搜索 US（User Strings）流
            f.seek(0)
            data = f.read()
            
            # 搜索可能的字符串模式
            # .NET 字符串以特定格式存储
            pattern = re.compile(b'[\x01-\x7F]{4,100}')
            
            for match in pattern.finditer(data):
                try:
                    s = match.group().decode('utf-8', errors='ignore')
                    if len(s) >= 4 and not s.startswith('\x00'):
                        strings.append(s)
                except UnicodeDecodeError:
                    pass
            
            # 限制数量
            strings = strings[:500]
            
        except Exception as e:
            logger.debug(f"[Managed] 字符串提取失败: {e}")
        
        return strings
    
    def _analyze_java(self) -> None:
        """
        分析 Java 字节码
        """
        logger.info("[Managed] 分析 Java 字节码")
        
        # 检查是否是 JAR 文件
        if self.file_path.endswith('.jar'):
            self._analyze_jar()
        else:
            self._analyze_class_file(self.file_path)
    
    def _analyze_jar(self) -> None:
        """
        分析 JAR 文件
        """
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                class_files = [n for n in zf.namelist() if n.endswith('.class')]
                
                logger.info(f"[Managed] JAR 包含 {len(class_files)} 个类文件")
                
                # 分析每个类文件（限制数量）
                for class_file in class_files[:50]:
                    try:
                        class_data = zf.read(class_file)
                        self._analyze_class_bytes(class_data, class_file)
                    except Exception as e:
                        logger.debug(f"[Managed] 类文件 {class_file} 分析失败: {e}")
                
                # 提取 MANIFEST.MF 信息
                if 'META-INF/MANIFEST.MF' in zf.namelist():
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='ignore')
                    self._extract_metadata()['manifest'] = manifest
                    
        except zipfile.BadZipFile as e:
            logger.error(f"[Managed] JAR 文件解析失败: {e}")
        except Exception as e:
            logger.error(f"[Managed] JAR 分析失败: {e}")
    
    def _analyze_class_file(self, file_path: str) -> None:
        """
        分析单个 .class 文件
        
        Args:
            file_path: class 文件路径
        """
        try:
            with open(file_path, 'rb') as f:
                class_data = f.read()
                self._analyze_class_bytes(class_data, file_path)
        except Exception as e:
            logger.error(f"[Managed] class 文件分析失败: {e}")
    
    def _analyze_class_bytes(self, class_data: bytes, source: str) -> None:
        """
        分析 class 字节码
        
        Args:
            class_data: class 文件字节
            source: 来源路径
        """
        try:
            # 解析 class 文件格式
            magic = struct.unpack('>I', class_data[0:4])[0]
            if magic != JAVA_CLASS_MAGIC:
                return
            
            minor_version = struct.unpack('>H', class_data[4:6])[0]
            major_version = struct.unpack('>H', class_data[6:8])[0]
            
            # 解析常量池
            constant_pool_count = struct.unpack('>H', class_data[8:10])[0]
            constant_pool, cp_end = self._parse_constant_pool(class_data, constant_pool_count)
            
            # 解析类信息
            access_flags = struct.unpack('>H', class_data[cp_end:cp_end+2])[0]
            this_class = struct.unpack('>H', class_data[cp_end+2:cp_end+4])[0]
            super_class = struct.unpack('>H', class_data[cp_end+4:cp_end+6])[0]
            
            # 获取类名
            class_name = self._get_class_name_from_cp(constant_pool, this_class)
            super_class_name = self._get_class_name_from_cp(constant_pool, super_class)
            
            # 解析方法
            methods = self._parse_methods(class_data, cp_end + 6, constant_pool)
            
            # 创建类信息
            class_info = ClassInfo()
                name=class_name.split('/')[-1],
                namespace='/'.join(class_name.split('/')[:-1]),
                methods=methods,
                base_class=super_class_name,
                is_public=(access_flags & 0x0001) != 0
            
            
            self.classes.append(class_info)
            
            # 检测危险方法
            for method in methods:
                self._check_java_method_danger(method)
            
        except Exception as e:
            logger.debug(f"[Managed] class 字节码解析失败 ({source}): {e}")
    
    def _parse_constant_pool(self, class_data: bytes = b'', count: int = None) -> Any:
        """
        解析 Java 常量池

        支持两种调用方式：
        1. _parse_constant_pool(class_data, count) -> (list, end_offset)
        2. _parse_constant_pool(pool_data) -> dict  兼容测试

        Args:
            class_data: class 文件字节（如果包含 count 字段，前 2 字节为 count）
            count: 常量池数量（可选）

        Returns:
            旧接口：(常量池列表, 结束位置)
            新接口：dict 形式的简化结果
        """
        # 新接口：仅传一个参数时返回 dict
        if count is None:
            try:
                pool_dict = {}
                if len(class_data) < 3:
                    return pool_dict
                # 解析 count
                if len(class_data) >= 3:
                    cp_count = struct.unpack('>H', class_data[0:2])[0]
                else:
                    cp_count = 0
                offset = 2,
                for i in range(1, min(cp_count, 200)):  # 限制解析数量,
                    if offset >= len(class_data):
                        break
                    tag = class_data[offset]
                    offset += 1,
                    if tag == 1:  # CONSTANT_Utf8,
                        if offset + 2 > len(class_data):
                            break
                        length = struct.unpack('>H', class_data[offset:offset+2])[0]
                        offset += 2,
                        if offset + length > len(class_data):
                            break
                        value = class_data[offset:offset+length].decode('utf-8', errors='replace')
                        pool_dict[f'#{i}'] = {'tag': 'Utf8', 'value': value}
                        offset += length
                    elif tag == 7:  # CONSTANT_Class,
                        if offset + 2 > len(class_data):
                            break
                        name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                        pool_dict[f'#{i}'] = {'tag': 'Class', 'name_index': name_index}
                        offset += 2
                    else:
                        # 跳过未知类型，避免崩溃
                        break
                return pool_dict
            except Exception as e:
                logger.debug(f"[Managed] 简化常量池解析失败: {e}")
                return {}

        # 旧接口：完整解析
        constant_pool = [None]  # 索引从1开始
        offset = 10

        for i in range(1, count):
            if offset >= len(class_data):
                break
            
            tag = class_data[offset]
            offset += 1
            
            entry = None
            
            if tag == 7:  # CONSTANT_Class_info
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('Class', name_index)
                offset += 2
            elif tag == 9:  # CONSTANT_Fieldref_info
                class_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('Fieldref', class_index, name_and_type_index)
                offset += 4
            elif tag == 10:  # CONSTANT_Methodref_info
                class_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('Methodref', class_index, name_and_type_index)
                offset += 4
            elif tag == 11:  # CONSTANT_InterfaceMethodref_info
                class_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('InterfaceMethodref', class_index, name_and_type_index)
                offset += 4
            elif tag == 8:  # CONSTANT_String_info
                string_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('String', string_index)
                offset += 2
            elif tag == 3:  # CONSTANT_Integer_info
                value = struct.unpack('>I', class_data[offset:offset+4])[0]
                entry = ('Integer', value)
                offset += 4
            elif tag == 4:  # CONSTANT_Float_info
                value = struct.unpack('>f', class_data[offset:offset+4])[0]
                entry = ('Float', value)
                offset += 4
            elif tag == 5:  # CONSTANT_Long_info
                value = struct.unpack('>Q', class_data[offset:offset+8])[0]
                entry = ('Long', value)
                offset += 8
                constant_pool.append(None)  # Long 占两个位置
            elif tag == 6:  # CONSTANT_Double_info
                value = struct.unpack('>d', class_data[offset:offset+8])[0]
                entry = ('Double', value)
                offset += 8
                constant_pool.append(None)  # Double 占两个位置
            elif tag == 12:  # CONSTANT_NameAndType_info
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                descriptor_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('NameAndType', name_index, descriptor_index)
                offset += 4
            elif tag == 1:  # CONSTANT_Utf8_info
                length = struct.unpack('>H', class_data[offset:offset+2])[0]
                value = class_data[offset+2:offset+2+length].decode('utf-8', errors='replace')
                entry = ('Utf8', value)
                offset += 2 + length
            elif tag == 15:  # CONSTANT_MethodHandle_info
                reference_kind = class_data[offset]
                reference_index = struct.unpack('>H', class_data[offset+1:offset+3])[0]
                entry = ('MethodHandle', reference_kind, reference_index)
                offset += 3
            elif tag == 16:  # CONSTANT_MethodType_info
                descriptor_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('MethodType', descriptor_index)
                offset += 2
            elif tag == 17:  # CONSTANT_Dynamic_info
                bootstrap_method_attr_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('Dynamic', bootstrap_method_attr_index, name_and_type_index)
                offset += 4
            elif tag == 18:  # CONSTANT_InvokeDynamic_info
                bootstrap_method_attr_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('InvokeDynamic', bootstrap_method_attr_index, name_and_type_index)
                offset += 4
            elif tag == 19:  # CONSTANT_Module_info
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('Module', name_index)
                offset += 2
            elif tag == 20:  # CONSTANT_Package_info
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('Package', name_index)
                offset += 2
            else:
                # 未知的 tag，跳过
                entry = ('Unknown', tag)
                offset += 1
            
            constant_pool.append(entry)
        
        return constant_pool, offset
    
    def _get_class_name_from_cp(self, constant_pool: List[Any], class_index: int) -> str:
        """
        从常量池获取类名
        
        Args:
            constant_pool: 常量池
            class_index: 类索引
            
        Returns:
            类名
        """
        if class_index == 0 or class_index >= len(constant_pool):
            return 'Unknown'
        
        entry = constant_pool[class_index]
        if entry and entry[0] == 'Class':
            name_index = entry[1]
            if name_index < len(constant_pool):
                name_entry = constant_pool[name_index]
                if name_entry and name_entry[0] == 'Utf8':
                    return name_entry[1]
        
        return 'Unknown'
    
    def _parse_methods(self, class_data: bytes, offset: int, constant_pool: List[Any]) -> List[MethodInfo]:
        """
        解析方法列表
        
        Args:
            class_data: class 文件字节
            offset: 起始偏移
            constant_pool: 常量池
            
        Returns:
            方法信息列表
        """
        methods = []
        
        try:
            # 跳过接口数量
            interfaces_count = struct.unpack('>H', class_data[offset:offset+2])[0]
            offset += 2 + interfaces_count * 2
            
            # 跳过字段
            fields_count = struct.unpack('>H', class_data[offset:offset+2])[0]
            offset += 2
            
            for _ in range(fields_count):
                access_flags = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                descriptor_index = struct.unpack('>H', class_data[offset+4:offset+6])[0]
                attributes_count = struct.unpack('>H', class_data[offset+6:offset+8])[0]
                offset += 8
                
                for _ in range(attributes_count):
                    attr_name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                    attr_length = struct.unpack('>I', class_data[offset+2:offset+6])[0]
                    offset += 6 + attr_length
            
            # 解析方法
            methods_count = struct.unpack('>H', class_data[offset:offset+2])[0]
            offset += 2
            
            for _ in range(methods_count):
                access_flags = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                descriptor_index = struct.unpack('>H', class_data[offset+4:offset+6])[0]
                attributes_count = struct.unpack('>H', class_data[offset+6:offset+8])[0]
                offset += 8
                
                # 获取方法名
                method_name = 'Unknown',
                if name_index < len(constant_pool):
                    name_entry = constant_pool[name_index]
                    if name_entry and name_entry[0] == 'Utf8':
                        method_name = name_entry[1]
                
                # 获取方法签名
                method_signature = 'Unknown',
                if descriptor_index < len(constant_pool):
                    desc_entry = constant_pool[descriptor_index]
                    if desc_entry and desc_entry[0] == 'Utf8':
                        method_signature = desc_entry[1]
                
                # 解析属性（包括 Code 属性）
                bytecode = b''
                instructions = []
                
                for _ in range(attributes_count):
                    attr_name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                    attr_length = struct.unpack('>I', class_data[offset+2:offset+6])[0]
                    offset += 6
                    
                    attr_name = '',
                    if attr_name_index < len(constant_pool):
                        attr_entry = constant_pool[attr_name_index]
                        if attr_entry and attr_entry[0] == 'Utf8':
                            attr_name = attr_entry[1]
                    
                    if attr_name == 'Code':
                        max_stack = struct.unpack('>H', class_data[offset:offset+2])[0]
                        max_locals = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                        code_length = struct.unpack('>I', class_data[offset+4:offset+8])[0]
                        
                        bytecode = class_data[offset+8:offset+8+code_length]
                        instructions = self._parse_bytecode_instructions(bytecode)
                        
                        offset += 8 + code_length
                        
                        # 跳过异常表和属性
                        exception_table_length = struct.unpack('>H', class_data[offset:offset+2])[0]
                        offset += 2 + exception_table_length * 8
                        
                        code_attributes_count = struct.unpack('>H', class_data[offset:offset+2])[0]
                        offset += 2
                        
                        for _ in range(code_attributes_count):
                            ca_name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                            ca_length = struct.unpack('>I', class_data[offset+2:offset+6])[0]
                            offset += 6 + ca_length
                    else:
                        offset += attr_length
                
                method_info = MethodInfo()
                    name=method_name,
                    class_name=self._get_class_name_from_cp(constant_pool, struct.unpack('>H', class_data[8:10])[0]) if len(class_data) > 10 else '',
                    signature=method_signature,
                    is_public=(access_flags & 0x0001) != 0,
                    is_static=(access_flags & 0x0008) != 0,
                    bytecode=bytecode,
                    instructions=instructions
                
                
                methods.append(method_info)
                
        except Exception as e:
            logger.debug(f"[Managed] 方法解析失败: {e}")
        
        return methods
    
    def _parse_bytecode_instructions(self, bytecode: bytes) -> List[str]:
        """
        解析字节码指令
        
        Args:
            bytecode: 字节码
            
        Returns:
            指令列表
        """
        instructions = []
        opcode_names = {
            0x00: 'nop', 0x01: 'aconst_null', 0x02: 'iconst_m1', 0x03: 'iconst_0',
            0x04: 'iconst_1', 0x05: 'iconst_2', 0x06: 'iconst_3', 0x07: 'iconst_4',
            0x08: 'iconst_5', 0x09: 'lconst_0', 0x0a: 'lconst_1', 0x0b: 'fconst_0',
            0x0c: 'fconst_1', 0x0d: 'fconst_2', 0x0e: 'dconst_0', 0x0f: 'dconst_1',
            0x10: 'bipush', 0x11: 'sipush', 0x12: 'ldc', 0x13: 'ldc_w', 0x14: 'ldc2_w',
            0x15: 'iload', 0x16: 'lload', 0x17: 'fload', 0x18: 'dload', 0x19: 'aload',
            0x2a: 'aload_0', 0x2b: 'aload_1', 0x2c: 'aload_2', 0x2d: 'aload_3',
            0x36: 'istore', 0x37: 'lstore', 0x38: 'fstore', 0x39: 'dstore', 0x3a: 'astore',
            0x4b: 'astore_0', 0x4c: 'astore_1', 0x4d: 'astore_2', 0x4e: 'astore_3',
            0x57: 'pop', 0x58: 'pop2', 0x59: 'dup', 0x5a: 'dup_x1', 0x5b: 'dup_x2',
            0x5c: 'dup2', 0x5d: 'dup2_x1', 0x5e: 'dup2_x2', 0x5f: 'swap',
            0x60: 'iadd', 0x61: 'ladd', 0x62: 'fadd', 0x63: 'dadd',
            0x64: 'isub', 0x65: 'lsub', 0x66: 'fsub', 0x67: 'dsub',
            0x68: 'imul', 0x69: 'lmul', 0x6a: 'fmul', 0x6b: 'dmul',
            0x6c: 'idiv', 0x6d: 'ldiv', 0x6e: 'fdiv', 0x6f: 'ddiv',
            0x70: 'irem', 0x71: 'lrem', 0x72: 'frem', 0x73: 'drem',
            0x74: 'ineg', 0x75: 'lneg', 0x76: 'fneg', 0x77: 'dneg',
            0x84: 'iinc',
            0x85: 'i2l', 0x86: 'i2f', 0x87: 'i2d', 0x88: 'l2i', 0x89: 'l2f', 0x8a: 'l2d',
            0x8b: 'f2i', 0x8c: 'f2l', 0x8d: 'f2d', 0x8e: 'd2i', 0x8f: 'd2l', 0x90: 'd2f',
            0x91: 'i2b', 0x92: 'i2c', 0x93: 'i2s',
            0x94: 'lcmp', 0x95: 'fcmpl', 0x96: 'fcmpg', 0x97: 'dcmpl', 0x98: 'dcmpg',
            0x99: 'ifeq', 0x9a: 'ifne', 0x9b: 'iflt', 0x9c: 'ifge', 0x9d: 'ifgt', 0x9e: 'ifle',
            0x9f: 'if_icmpeq', 0xa0: 'if_icmpne', 0xa1: 'if_icmplt', 0xa2: 'if_icmpge',
            0xa3: 'if_icmpgt', 0xa4: 'if_icmple', 0xa5: 'if_acmpeq', 0xa6: 'if_acmpne',
            0xa7: 'goto', 0xa8: 'jsr', 0xa9: 'ret',
            0xac: 'ireturn', 0xad: 'lreturn', 0xae: 'freturn', 0xaf: 'dreturn',
            0xb0: 'areturn', 0xb1: 'return',
            0xb2: 'getstatic', 0xb3: 'putstatic', 0xb4: 'getfield', 0xb5: 'putfield',
            0xb6: 'invokevirtual', 0xb7: 'invokespecial', 0xb8: 'invokestatic',
            0xb9: 'invokeinterface', 0xba: 'invokedynamic',
            0xbb: 'new', 0xbc: 'newarray', 0xbd: 'anewarray', 0xbe: 'arraylength',
            0xbf: 'athrow', 0xc0: 'checkcast', 0xc1: 'instanceof',
            0xc2: 'monitorenter', 0xc3: 'monitorexit', 0xc4: 'wide',
            0xc5: 'multianewarray', 0xc6: 'ifnull', 0xc7: 'ifnonnull',
            0xc8: 'goto_w', 0xc9: 'jsr_w',
        }
        
        try:
            offset = 0,
            while offset < len(bytecode):
                opcode = bytecode[offset]
                name = opcode_names.get(opcode, f'unknown_{opcode:02x}')
                
                # 处理有参数的指令
                if opcode in (0x10):  # bipush,
                    if offset + 1 < len(bytecode):
                        param = bytecode[offset + 1]
                        instructions.append(f'{name} {param}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0x11):  # sipush,
                    if offset + 2 < len(bytecode):
                        param = struct.unpack('>h', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} {param}')
                        offset += 3
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0x12):  # ldc,
                    if offset + 1 < len(bytecode):
                        param = bytecode[offset + 1]
                        instructions.append(f'{name} #{param}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x84):  # load/store/iinc,
                    if offset + 1 < len(bytecode):
                        param = bytecode[offset + 1]
                        instructions.append(f'{name} {param}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xc6, 0xc7):  # branch,
                    if offset + 2 < len(bytecode):
                        param = struct.unpack('>h', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} {param}')
                        offset += 3
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1):  # field/method/ref,
                    if offset + 2 < len(bytecode):
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} #{param}')
                        offset += 3
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xb9):  # invokeinterface,
                    if offset + 4 < len(bytecode):
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        count = bytecode[offset + 3]
                        instructions.append(f'{name} #{param} {count}')
                        offset += 5
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xba):  # invokedynamic,
                    if offset + 2 < len(bytecode):
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} #{param}')
                        offset += 4
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xbc):  # newarray,
                    if offset + 1 < len(bytecode):
                        atype = bytecode[offset + 1]
                        type_names = {4: 'boolean', 5: 'char', 6: 'float', 7: 'double', 8: 'byte', 9: 'short', 10: 'int', 11: 'long'}
                        type_name = type_names.get(atype, str(atype

                        instructions.append(f'{name} {type_name}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xc4):  # wide,
                    if offset + 1 < len(bytecode):
                        sub_opcode = bytecode[offset + 1]
                        if offset + 3 < len(bytecode):
                            index = struct.unpack('>H', bytecode[offset+2:offset+4])[0]
                            instructions.append(f'{name} {opcode_names.get(sub_opcode, "unknown")} {index}')
                            offset += 4
                        else:
                            instructions.append(name)
                            offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xc5):  # multianewarray,
                    if offset + 3 < len(bytecode):
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        dimensions = bytecode[offset + 3]
                        instructions.append(f'{name} #{param} {dimensions}')
                        offset += 4
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xc8, 0xc9):  # goto_w, jsr_w,
                    if offset + 4 < len(bytecode):
                        param = struct.unpack('>i', bytecode[offset+1:offset+5])[0]
                        instructions.append(f'{name} {param}')
                        offset += 5
                    else:
                        instructions.append(name)
                        offset += 1
                else:
                    instructions.append(name)
                    offset += 1
                
        except Exception as e:
            logger.debug(f"[Managed] 字节码指令解析失败: {e}")
        
        return instructions
    
    def _check_java_method_danger(self, bytecode: str = '', method_name: str = '', method: MethodInfo = None) -> Tuple[bool, List[str]]:
        """
        检查 Java 方法是否危险

        支持两种调用方式：
        1. _check_java_method_danger(bytecode, method_name) -> (is_dangerous, reasons)
        2. _check_java_method_danger(method=MethodInfo) -> (is_dangerous, reasons) 兼容旧调用

        Args:
            bytecode: 字节码字符串
            method_name: 方法名
            method: MethodInfo 对象（可选，用于旧接口兼容）

        Returns:
            (is_dangerous, reasons) 元组
        """
        is_dangerous = False
        reasons = []

        # 兼容旧的 method 传入方式
        if method is not None and isinstance(method, MethodInfo):
            bytecode = method.bytecode or ''
            method_name = method.name or ''
            # 直接修改传入对象并返回元组
            for pattern, danger_info in JAVA_DANGEROUS_METHODS.items():
                if pattern in method_name or pattern.split('.')[-1] in bytecode:
                    if not is_dangerous:
                        is_dangerous = True
                        method.is_dangerous = True
                        desc = danger_info.get('description', str(danger_info)) if isinstance(danger_info, dict) else str(danger_info)
                        reasons.append(desc)
                        method.danger_type = desc,
            return is_dangerous, reasons

        # 新接口：基于字节码和方法名进行检测
        for pattern, danger_info in JAVA_DANGEROUS_METHODS.items():
            desc = danger_info.get('description', str(danger_info)) if isinstance(danger_info, dict) else str(danger_info)
            # 检查字节码中是否调用了危险方法
            if pattern in bytecode:
                is_dangerous = True
                reasons.append(desc)
                continue
            # 检查方法名是否匹配危险模式
            if method_name and (pattern in method_name or pattern.split('.')[-1] in method_name):
                is_dangerous = True
                reasons.append(desc)
                continue
            # 检查方法名是否在危险方法列表中
            if method_name and method_name in pattern:
                is_dangerous = True
                reasons.append(desc)

        return is_dangerous, reasons

    def _check_dotnet_method_danger(self, il_code: str = '', method_name: str = '') -> Tuple[bool, List[str]]:
        """
        检查 .NET 方法是否危险

        Args:
            il_code: IL 代码字符串
            method_name: 方法名

        Returns:
            (is_dangerous, reasons) 元组
        """
        is_dangerous = False
        reasons = []

        for pattern, danger_info in DOTNET_DANGEROUS_METHODS.items():
            desc = danger_info.get('description', str(danger_info)) if isinstance(danger_info, dict) else str(danger_info)
            # 检查 IL 代码中是否调用了危险方法
            if pattern in il_code:
                is_dangerous = True
                reasons.append(desc)
                continue
            # 检查方法名是否匹配危险模式
            if method_name and (pattern in method_name or pattern.split('.')[-1] in method_name):
                is_dangerous = True
                reasons.append(desc)
                continue
            # 检查方法名是否在危险方法列表中
            if method_name and method_name in pattern:
                is_dangerous = True
                reasons.append(desc)

        return is_dangerous, reasons

    def get_danger_summary(self, result: ManagedCodeAnalysisResult = None) -> Dict[str, Any]:
        """
        获取危险摘要

        Args:
            result: 可选的分析结果，未提供则基于 self 构建

        Returns:
            危险摘要字典
        """
        if result is None:
            result = ManagedCodeAnalysisResult()
                code_type=self.code_type,
                classes=self.classes,
                dangerous_methods=self.dangerous_methods,
                vulnerabilities=self.vulnerabilities
            

        # 按严重程度统计
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for method in result.dangerous_methods:
            method_name = method.name
            # 在 JAVA_DANGEROUS_METHODS 中查找严重程度
            for pattern, danger_info in JAVA_DANGEROUS_METHODS.items():
                if method_name in pattern or pattern.split('.')[-1] in method_name:
                    if isinstance(danger_info, dict):
                        sev = danger_info.get('severity', 'Medium')
                        severity_count[sev] = severity_count.get(sev, 0) + 1
                    break
            else:
                # 在 DOTNET_DANGEROUS_METHODS 中查找
                for pattern, danger_info in DOTNET_DANGEROUS_METHODS.items():
                    if method_name in pattern or pattern.split('.')[-1] in method_name:
                        if isinstance(danger_info, dict):
                            sev = danger_info.get('severity', 'Medium')
                            severity_count[sev] = severity_count.get(sev, 0) + 1
                        break

        return {
            'code_type': result.code_type.value if hasattr(result.code_type, 'value') else str(result.code_type),
            'total_classes': len(result.classes),
            'dangerous_methods': len(result.dangerous_methods),
            'vulnerabilities': len(result.vulnerabilities) if isinstance(result.vulnerabilities, list) else 0,
            'severity_count': severity_count,
            'file_path': result.file_path,
            'error': result.error,
            'dangerous_method_names': [m.name for m in result.dangerous_methods[:10]],
        }
    
    def _detect_dangerous_from_strings(self, strings: List[str], code_type: ManagedCodeType) -> None:
        """
        从字符串列表检测危险方法
        
        Args:
            strings: 字符串列表
            code_type: 代码类型
        """
        dangerous_patterns = self.DOTNET_DANGEROUS_METHODS if code_type == ManagedCodeType.DOTNET else self.JAVA_DANGEROUS_METHODS
        
        for s in strings:
            for pattern, danger_desc in dangerous_patterns.items():
                if pattern in s:
                    # 创建虚拟方法信息
                    method = MethodInfo()
                        name=s,
                        class_name='',
                        is_dangerous=True,
                        danger_type=danger_desc
                    
                    self.dangerous_methods.append(method)
                    logger.warning(f"[Managed] 从字符串发现危险模式: {s} - {danger_desc}")
    
    def _detect_vulnerabilities(self) -> None:
        """
        检测漏洞
        """
        for method in self.dangerous_methods:
            vuln_type = method.danger_type
            
            # 根据危险类型映射漏洞严重程度
            severity = 'high',
            if '反序列化' in vuln_type:
                severity = 'critical'
            elif '命令执行' in vuln_type:
                severity = 'critical'
            elif '弱加密' in vuln_type:
                severity = 'medium'
            elif 'SQL' in vuln_type:
                severity = 'high'
            elif 'JNDI' in vuln_type:
                severity = 'critical'
            
            vulnerability = {
                'type': vuln_type,
                'severity': severity,
                'location': f'{method.class_name}.{method.name}',
                'description': f'检测到危险方法调用: {method.name}',
                'recommendation': self._get_recommendation(vuln_type)
            }
            
            self.vulnerabilities.append(vulnerability)
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """
        获取漏洞修复建议
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            修复建议
        """
        recommendations = {
            '反序列化漏洞': '避免使用不安全的反序列化方法，使用白名单验证输入类型',
            '命令执行': '避免直接执行用户输入，使用参数化命令',
            '动态调用': '限制反射调用的类型范围，使用白名单',
            '动态加载': '限制可加载的类/程序集，使用沙箱隔离',
            '弱加密': '使用安全的加密算法（AES-256, SHA-256, RSA-2048）',
            'SQL 操作': '使用参数化查询，避免拼接 SQL',
            'JNDI 注入': '避免远程 JNDI 查找，限制 lookup 目标',
            '文件操作': '验证文件路径，使用白名单限制访问范围',
            '网络请求': '验证 URL 来源，限制网络访问范围',
        }
        
        for key, rec in recommendations.items():
            if key in vuln_type:
                return rec
        
        return '审查该方法的调用上下文，确保输入经过验证'
    
    def _decompile(self) -> str:
        """
        反编译代码
        
        Returns:
            反编译后的代码
        """
        if self.use_ai and self.classes:
            return self._decompile_with_ai()
        
        return self._generate_pseudocode()
    
    def _decompile_with_ai(self) -> str:
        """
        使用 AI 反编译
        """
        try:
            context = {
                'file_path': self.file_path,
                'code_type': self.code_type.value,
                'classes': [
                    {
                        'name': c.name,
                        'namespace': c.namespace,
                        'methods': [
                            {
                                'name': m.name,
                                'signature': m.signature,
                                'instructions': m.instructions[:50]  # 限制指令数量
                            }
                            for m in c.methods[:10]  # 限制方法数量
                        ]
                    }
                    for c in self.classes[:10]  # 限制类数量
                ]
            }
            
            from prompts import MANAGED_CODE_DECOMPILE_TEMPLATE
            
            result = call_ai_with_retry()
                model=get_current_ai_model(),
                messages=[
                    {"role": "system", "content": MANAGED_CODE_DECOMPILE_TEMPLATE},
                    {"role": "user", "content": json.dumps(context, ensure_ascii=False, indent=2)}
                ],
                temperature=0.2,
                max_tokens=4000
            
            
            return result
            
        except Exception as e:
            logger.error(f"[Managed] AI 反编译失败: {e}")
            return self._generate_pseudocode()
    
    def _generate_pseudocode(self) -> str:
        """
        生成伪代码
        """
        lines = []
        
        if self.code_type == ManagedCodeType.DOTNET:
            lines.append('// .NET Assembly Analysis')
        elif self.code_type == ManagedCodeType.JAVA:
            lines.append('// Java Bytecode Analysis')
        
        lines.append(f'// File: {os.path.basename(self.file_path)}')
        lines.append('')
        
        for cls in self.classes:
            if cls.namespace:
                lines.append(f'namespace {cls.namespace} {{')
                indent = '    '
            else:
                indent = ''
            
            access = 'public' if cls.is_public else 'private'
            lines.append(f'{indent}{access} class {cls.name} : {cls.base_class} {{')
            
            for method in cls.methods[:20]:
                method_access = 'public' if method.is_public else 'private'
                static = 'static ' if method.is_static else ''
                danger_marker = ' // [DANGER]' if method.is_dangerous else ''
                
                lines.append(f'{indent}    {method_access} {static}{method.name}({method.signature}){danger_marker}')
                
                if method.instructions:
                    lines.append(f'{indent}    {{')
                    for inst in method.instructions[:10]:
                        lines.append(f'{indent}        {inst}')
                    lines.append(f'{indent}    }}')
            
            lines.append(f'{indent}}}')
            
            if cls.namespace:
                lines.append('}')
            
            lines.append('')
        
        return '\n'.join(lines)
    
    def _extract_metadata(self) -> Dict[str, Any]:
        """
        提取元数据
        
        Returns:
            元数据字典
        """
        metadata = {
            'file_path': self.file_path,
            'code_type': self.code_type.value,
            'class_count': len(self.classes),
            'method_count': sum(len(c.methods) for c in self.classes),
            'dangerous_method_count': len(self.dangerous_methods),
            'vulnerability_count': len(self.vulnerabilities)
        }
        
        return metadata
    
    def _generate_summary(self) -> str:
        """
        生成分析摘要
        
        Returns:
            摘要字符串
        """
        summary_lines = [
            f'托管代码分析结果 ({self.code_type.value})',
            f'文件: {os.path.basename(self.file_path)}',
            f'发现 {len(self.classes)} 个类',
            f'发现 {len(self.dangerous_methods)} 个危险方法',
            f'发现 {len(self.vulnerabilities)} 个潜在漏洞'
        ]
        
        if self.vulnerabilities:
            severity_counts = defaultdict(int)
            for vuln in self.vulnerabilities:
                severity_counts[vuln['severity']] += 1
            
            summary_lines.append('漏洞严重程度分布:')
            for sev, count in sorted(severity_counts.items(), key=lambda x: ['critical', 'high', 'medium', 'low'].index(x[0]) if x[0] in ['critical', 'high', 'medium', 'low'] else 99):
                summary_lines.append(f'  - {sev}: {count}')
        
        return '\n'.join(summary_lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            分析结果字典
        """
        return {
            'file_path': self.file_path,
            'code_type': self.code_type.value,
            'classes': [
                {
                    'name': c.name,
                    'namespace': c.namespace,
                    'methods': [
                        {
                            'name': m.name,
                            'is_dangerous': m.is_dangerous,
                            'danger_type': m.danger_type
                        }
                        for m in c.methods
                    ]
                }
                for c in self.classes
            ],
            'dangerous_methods': [
                {
                    'name': m.name,
                    'class_name': m.class_name,
                    'danger_type': m.danger_type
                }
                for m in self.dangerous_methods
            ],
            'vulnerabilities': self.vulnerabilities,
            'summary': self._generate_summary()
        }


def analyze_managed_code(, file_path: str, output_dir: str = None, use_ai: bool = True) -> ManagedCodeAnalysisResult:
    """
    分析托管代码的便捷函数
    
    Args:
        file_path: 文件路径
        output_dir: 输出目录
        use_ai: 是否使用 AI
        
    Returns:
        分析结果
    """
    analyzer = ManagedCodeAnalyzer(file_path, output_dir, use_ai)
    return analyzer.analyze()


def detect_managed_code_type(file_path: str) -> ManagedCodeType:
    """
    检测托管代码类型的便捷函数
    
    Args:
        file_path: 文件路径
        
    Returns:
        代码类型
    """
    try:
        with open(file_path, 'rb') as f:
            magic = struct.unpack('>I', f.read(4))[0]
            if magic == JAVA_CLASS_MAGIC:
                return ManagedCodeType.JAVA
            
            f.seek(0)
            if f.read(2) == b'MZ':
                f.seek(60)
                pe_header_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_header_offset + 24 + CLR_DIRECTORY_ENTRY * 8)
                clr_dir_offset = struct.unpack('<I', f.read(4))[0]
                if clr_dir_offset != 0:
                    return ManagedCodeType.DOTNET
            
            f.seek(0)
            if f.read(4) == b'PK\x03\x04':
                try:
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        if any(n.endswith('.class') for n in zf.namelist()):
                            return ManagedCodeType.JAVA
                except zipfile.BadZipFile:
                    pass
    except Exception:
        pass
    
    return ManagedCodeType.UNKNOWN
