import logging
import os
import re
import subprocess
import struct
import zipfile
import json

from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum

from core.config import Config, ensure_directories, get_current_ai_model, call_ai_with_retry, mask_sensitive_data

logger = logging.getLogger(__name__)


JAVA_CLASS_MAGIC = 0xCAFEBABE
CLR_PE_SIGNATURE = 0x5A4D
CLR_DIRECTORY_ENTRY = 14


JAVA_DANGEROUS_METHODS = {
    'ObjectInputStream': {'description': 'Deserialization vuln - ObjectInputStream can lead to RCE', 'severity': 'Critical'},
    'ObjectInputStream.readObject': {'description': 'Deserialization vuln - ObjectInputStream can lead to RCE', 'severity': 'Critical'},
    'ObjectInputStream.readUnshared': {'description': 'Deserialization vuln - readUnshared', 'severity': 'High'},
    'XMLDecoder.readObject': {'description': 'Deserialization vuln - XMLDecoder high risk', 'severity': 'Critical'},
    'Yaml.load': {'description': 'Deserialization vuln - YAML parsing', 'severity': 'High'},
    'SnakeYaml.load': {'description': 'Deserialization vuln - SnakeYAML', 'severity': 'High'},
    'JSON.parseObject': {'description': 'Deserialization vuln - FastJSON', 'severity': 'High'},
    'Class.forName': {'description': 'Dynamic loading - load arbitrary class', 'severity': 'Medium'},
    'ClassLoader.loadClass': {'description': 'Dynamic loading - class loader', 'severity': 'Medium'},
    'Method.invoke': {'description': 'Dynamic invocation - reflection call', 'severity': 'Medium'},
    'Constructor.newInstance': {'description': 'Dynamic creation - reflection instance', 'severity': 'Medium'},
    'getMethod': {'description': 'Reflection - get method', 'severity': 'Low'},
    'Runtime.exec': {'description': 'Command execution via Runtime.exec', 'severity': 'Critical'},
    'ProcessBuilder.start': {'description': 'Command execution - ProcessBuilder', 'severity': 'Critical'},
    'FileInputStream': {'description': 'File operation - input stream', 'severity': 'Low'},
    'FileOutputStream': {'description': 'File operation - output stream', 'severity': 'Low'},
    'FileReader': {'description': 'File operation - file reader', 'severity': 'Low'},
    'FileWriter': {'description': 'File operation - file writer', 'severity': 'Low'},
    'Files.readAllBytes': {'description': 'File operation - read bytes', 'severity': 'Low'},
    'Files.write': {'description': 'File operation - write file', 'severity': 'Low'},
    'URL.openStream': {'description': 'Network - open URL', 'severity': 'Medium'},
    'URLConnection': {'description': 'Network - URL connection', 'severity': 'Medium'},
    'Socket': {'description': 'Network socket', 'severity': 'Medium'},
    'HttpURLConnection': {'description': 'HTTP - HTTP request', 'severity': 'Medium'},
    'MessageDigest.getInstance("MD5")': {'description': 'Weak crypto - MD5', 'severity': 'Low'},
    'MessageDigest.getInstance("SHA1")': {'description': 'Weak crypto - SHA1', 'severity': 'Low'},
    'Cipher.getInstance("DES")': {'description': 'Weak crypto - DES', 'severity': 'Low'},
    'Statement.executeQuery': {'description': 'SQL execution - possible injection', 'severity': 'High'},
    'Statement.executeUpdate': {'description': 'SQL execution - update', 'severity': 'High'},
    'PreparedStatement': {'description': 'SQL prepared - relatively safe', 'severity': 'Low'},
    'Connection.createStatement': {'description': 'SQL connection - create statement', 'severity': 'Medium'},
    'InitialContext.lookup': {'description': 'JNDI injection - remote lookup', 'severity': 'Critical'},
    'Context.lookup': {'description': 'JNDI injection - context lookup', 'severity': 'Critical'},
    'Thread.start': {'description': 'Thread start - concurrency risk', 'severity': 'Low'},
    'System.loadLibrary': {'description': 'Native library loading - JNI', 'severity': 'Medium'},
    'System.load': {'description': 'Native library loading - load lib', 'severity': 'Medium'},
}


DOTNET_DANGEROUS_METHODS = {
    'BinaryFormatter.Deserialize': {'description': 'Deserialization vuln - BinaryFormatter RCE', 'severity': 'Critical'},
    'Type.InvokeMember': {'description': 'Dynamic invocation - reflection bypass', 'severity': 'High'},
    'XmlSerializer.Deserialize': {'description': 'Deserialization vuln - XmlSerializer', 'severity': 'High'},
    'DataContractSerializer.ReadObject': {'description': 'Deserialization vuln - DataContractSerializer', 'severity': 'High'},
    'JavaScriptSerializer.Deserialize': {'description': 'Deserialization vuln - JavaScriptSerializer', 'severity': 'High'},
    'Type.GetType': {'description': 'Dynamic loading - get type', 'severity': 'Medium'},
    'Assembly.Load': {'description': 'Dynamic loading - load assembly', 'severity': 'Medium'},
    'Activator.CreateInstance': {'description': 'Dynamic creation - reflection instance', 'severity': 'Medium'},
    'MethodInfo.Invoke': {'description': 'Dynamic invocation - reflection call', 'severity': 'Medium'},
    'Process.Start': {'description': 'Command execution - execute system command', 'severity': 'Critical'},
    'File.OpenRead': {'description': 'File operation - file read', 'severity': 'Low'},
    'File.OpenWrite': {'description': 'File operation - file write', 'severity': 'Low'},
    'File.ReadAllText': {'description': 'File operation - read text', 'severity': 'Low'},
    'File.WriteAllText': {'description': 'File operation - write text', 'severity': 'Low'},
    'WebClient.DownloadString': {'description': 'Network - download string', 'severity': 'Medium'},
    'WebClient.DownloadFile': {'description': 'Network - download file', 'severity': 'Medium'},
    'HttpClient.GetString': {'description': 'HTTP - get string', 'severity': 'Medium'},
    'HttpWebRequest.Create': {'description': 'HTTP - create request', 'severity': 'Medium'},
    'MD5.Create': {'description': 'Weak crypto - MD5', 'severity': 'Low'},
    'SHA1.Create': {'description': 'Weak crypto - SHA1', 'severity': 'Low'},
    'SqlCommand.ExecuteReader': {'description': 'SQL execution - possible injection', 'severity': 'High'},
    'SqlCommand.ExecuteNonQuery': {'description': 'SQL execution - update', 'severity': 'High'},
    'SqlConnection.Open': {'description': 'SQL connection - DB connection', 'severity': 'Low'},
}


class ManagedCodeType(StrEnum):
    UNKNOWN = 'unknown'
    DOTNET = 'dotnet'
    JAVA = 'java'


@dataclass
class MethodInfo:
    name: str
    class_name: str = ''
    namespace: str = ''
    signature: str = ''
    is_public: bool = False
    is_static: bool = False
    is_dangerous: bool = False
    danger_type: str = ''
    danger_reasons: list = field(default_factory=list)
    il_code: str = ''
    bytecode: bytes = b''
    instructions: list = field(default_factory=list)
    parameters: list = field(default_factory=list)
    return_type: str = ''


@dataclass
class ClassInfo:
    name: str
    namespace: str = ''
    methods: list = field(default_factory=list)
    fields: list = field(default_factory=list)
    base_class: str = ''
    interfaces: list = field(default_factory=list)
    is_public: bool = False
    is_dangerous: bool = False
    danger_reasons: list = field(default_factory=list)
    attributes: list = field(default_factory=list)


@dataclass
class ManagedCodeAnalysisResult:
    file_path: str = ''
    code_type: ManagedCodeType = ManagedCodeType.UNKNOWN
    classes: list = field(default_factory=list)
    dangerous_methods: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    decompiled_code: str = ''
    metadata: dict = field(default_factory=dict)
    summary: str = ''
    error: str = None


class ManagedCodeAnalyzer:
    """托管代码分析器——覆盖.NET与Java字节码审计。

    能力集：文件格式识别、类与方法提取、漏洞模式匹配、反编译输出。
    """

    DOTNET_DANGEROUS_METHODS = {
        'BinaryFormatter.Deserialize': 'Deserialization vuln - BinaryFormatter RCE',
        'BinaryFormatter.UnsafeDeserialize': 'Deserialization vuln - UnsafeDeserialize',
        'JavaScriptSerializer.Deserialize': 'Deserialization vuln - JavaScriptSerializer',
        'DataContractSerializer.ReadObject': 'Deserialization vuln - DataContractSerializer',
        'XmlSerializer.Deserialize': 'Deserialization vuln - XmlSerializer type confusion',
        'NetDataContractSerializer.ReadObject': 'Deserialization vuln - NetDataContractSerializer',
        'ObjectStateFormatter.Deserialize': 'Deserialization vuln - ViewState parsing',
        'Type.InvokeMember': 'Dynamic invocation - reflection bypass',
        'MethodInfo.Invoke': 'Dynamic invocation - reflection call',
        'Activator.CreateInstance': 'Dynamic creation - may create dangerous types',
        'Assembly.Load': 'Dynamic loading - load arbitrary assembly',
        'Assembly.LoadFrom': 'Dynamic loading - load from path',
        'Assembly.LoadFile': 'Dynamic loading - load file assembly',
        'Process.Start': 'Command execution - execute arbitrary commands',
        'ProcessStartInfo': 'Command execution - process start config',
        'File.Open': 'File operation - file read/write',
        'File.ReadAllText': 'File operation - read file content',
        'File.WriteAllText': 'File operation - write file',
        'FileStream': 'File operation - file stream',
        'Directory.GetFiles': 'File operation - directory traversal',
        'WebClient.DownloadFile': 'Network - download arbitrary file',
        'HttpClient': 'Network - HTTP request',
        'Socket': 'Network socket - network communication',
        'MD5': 'Weak crypto - MD5 insecure',
        'SHA1': 'Weak crypto - SHA1 insecure',
        'DES': 'Weak crypto - DES insecure',
        'RC2': 'Weak crypto - RC2 insecure',
        'Unsafe': 'Unsafe code - unsafe block',
        'SqlCommand': 'SQL operation - possible injection',
        'SqlConnection': 'SQL connection - DB connection',
        'ExecuteNonQuery': 'SQL execution - execute SQL',
        'ExecuteReader': 'SQL execution - execute query',
    }

    JAVA_DANGEROUS_METHODS = {
        'ObjectInputStream.readObject': 'Deserialization vuln - ObjectInputStream RCE',
        'ObjectInputStream.readUnshared': 'Deserialization vuln - readUnshared',
        'XMLDecoder.readObject': 'Deserialization vuln - XMLDecoder high risk',
        'Yaml.load': 'Deserialization vuln - YAML parsing',
        'SnakeYaml.load': 'Deserialization vuln - SnakeYAML',
        'JSON.parseObject': 'Deserialization vuln - FastJSON',
        'Class.forName': 'Dynamic loading - load arbitrary class',
        'ClassLoader.loadClass': 'Dynamic loading - class loader',
        'Method.invoke': 'Dynamic invocation - reflection call',
        'Constructor.newInstance': 'Dynamic creation - reflection instance',
        'getMethod': 'Reflection - get method',
        'Runtime.exec': 'Command execution - execute system command',
        'ProcessBuilder.start': 'Command execution - ProcessBuilder',
        'FileInputStream': 'File operation - input stream',
        'FileOutputStream': 'File operation - output stream',
        'FileReader': 'File operation - file reader',
        'FileWriter': 'File operation - file writer',
        'Files.readAllBytes': 'File operation - read bytes',
        'Files.write': 'File operation - write file',
        'URL.openStream': 'Network - open URL',
        'URLConnection': 'Network - URL connection',
        'Socket': 'Network socket',
        'HttpURLConnection': 'HTTP - HTTP request',
        'MessageDigest.getInstance("MD5")': 'Weak crypto - MD5',
        'MessageDigest.getInstance("SHA1")': 'Weak crypto - SHA1',
        'Cipher.getInstance("DES")': 'Weak crypto - DES',
        'Statement.executeQuery': 'SQL execution - possible injection',
        'Statement.executeUpdate': 'SQL execution - update',
        'PreparedStatement': 'SQL prepared - relatively safe',
        'Connection.createStatement': 'SQL connection - create statement',
        'InitialContext.lookup': 'JNDI injection - remote lookup',
        'Context.lookup': 'JNDI injection - context lookup',
        'Thread.start': 'Thread start - concurrency risk',
        'System.loadLibrary': 'Native library loading - JNI',
        'System.load': 'Native library loading - load lib',
    }

    def __init__(self, file_path=None, output_dir=None, use_ai=True):
        self.file_path = file_path
        if output_dir is not None:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(Config.REPORTS_DIR, 'managed_analysis')
        self.use_ai = use_ai

        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except Exception as e:
                logger.warning(f"Failed to create output directory: {e}")

        self.code_type = ManagedCodeType.UNKNOWN
        self.classes = []
        self.dangerous_methods = []
        self.vulnerabilities = []

        self._check_dependencies()

    def _check_dependencies(self):
        """检测分析依赖工具可用性。"""
        self.ilspy_available = False
        self.cfr_available = False
        self.procyon_available = False

        try:
            result = subprocess.run(
                ['ilspy', '--help'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self.ilspy_available = True
                logger.info("[Managed] ILSpy available")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[Managed] ILSpy not installed, using built-in parser")

        try:
            result = subprocess.run(
                ['java', '-jar', 'cfr.jar', '--help'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self.cfr_available = True
                logger.info("[Managed] CFR available")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[Managed] CFR not installed, using built-in parser")

    def analyze(self, file_path=None):
        """执行完整托管代码分析流程。"""
        if file_path is not None:
            target_path = file_path
        else:
            target_path = self.file_path

        if not target_path or not isinstance(target_path, str):
            target = str(target_path) if target_path else ''
            return ManagedCodeAnalysisResult(
                file_path=target,
                code_type=ManagedCodeType.UNKNOWN,
                error='File not found'
            )

        if not self._is_safe_path(target_path):
            return ManagedCodeAnalysisResult(
                file_path=target_path,
                code_type=ManagedCodeType.UNKNOWN,
                error='Invalid file path'
            )

        if not os.path.exists(target_path):
            return ManagedCodeAnalysisResult(
                file_path=target_path,
                code_type=ManagedCodeType.UNKNOWN,
                error='File not found'
            )

        self.file_path = target_path
        logger.info(f"[Managed] Starting analysis: {self.file_path}")

        self.code_type = self._detect_code_type()

        if self.code_type == ManagedCodeType.UNKNOWN:
            logger.warning(f"[Managed] Cannot identify file type: {self.file_path}")
            return ManagedCodeAnalysisResult(
                file_path=self.file_path,
                code_type=ManagedCodeType.UNKNOWN,
                summary='Cannot identify file type'
            )

        if self.code_type == ManagedCodeType.DOTNET:
            self._analyze_dotnet()
        elif self.code_type == ManagedCodeType.JAVA:
            self._analyze_java()

        self._detect_vulnerabilities()
        decompiled = self._decompile()
        summary = self._generate_summary()

        return ManagedCodeAnalysisResult(
            file_path=self.file_path,
            code_type=self.code_type,
            classes=self.classes,
            dangerous_methods=self.dangerous_methods,
            vulnerabilities=self.vulnerabilities,
            decompiled_code=decompiled,
            metadata=self._extract_metadata(),
            summary=summary
        )

    def _is_safe_path(self, path):
        if not path:
            return False
        if '..' in path:
            try:
                norm = os.path.normpath(path)
                if norm.startswith('..') or '/../' in norm or '\\..\\' in norm:
                    return False
            except Exception:
                return False
        return True

    def _detect_code_type(self, file_path=None):
        """检测托管代码类型。"""
        if file_path is not None:
            target_path = file_path
        else:
            target_path = self.file_path
        if not target_path or not os.path.exists(target_path):
            return ManagedCodeType.UNKNOWN

        try:
            with open(target_path, 'rb') as f:
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    return ManagedCodeType.UNKNOWN
                magic = struct.unpack('>I', magic_bytes)[0]

                if magic == JAVA_CLASS_MAGIC:
                    logger.info("[Managed] Detected Java class file")
                    return ManagedCodeType.JAVA

                f.seek(0)
                pe_sig = struct.unpack('<H', f.read(2))[0]

                if pe_sig == CLR_PE_SIGNATURE:
                    f.seek(60)
                    pe_header_offset = struct.unpack('<I', f.read(4))[0]

                    f.seek(pe_header_offset + 24 + CLR_DIRECTORY_ENTRY * 8)
                    clr_dir_offset = struct.unpack('<I', f.read(4))[0]
                    clr_dir_size = struct.unpack('<I', f.read(4))[0]

                    if clr_dir_offset != 0 and clr_dir_size != 0:
                        logger.info("[Managed] Detected .NET assembly")
                        return ManagedCodeType.DOTNET

                f.seek(0)
                zip_magic = f.read(4)
                if zip_magic == b'PK\x03\x04':
                    try:
                        with zipfile.ZipFile(target_path, 'r') as zf:
                            namelist = zf.namelist()
                            class_files = [n for n in namelist if n.endswith('.class')]
                            if class_files:
                                logger.info("[Managed] Detected Java JAR file")
                                return ManagedCodeType.JAVA
                    except zipfile.BadZipFile:
                        pass

        except Exception as e:
            logger.error(f"[Managed] File type detection failed: {e}")

        return ManagedCodeType.UNKNOWN

    def _analyze_dotnet(self):
        """解析.NET程序集。"""
        logger.info("[Managed] Analyzing .NET assembly")

        if self.ilspy_available:
            self._analyze_dotnet_with_ilspy()
        else:
            self._analyze_dotnet_builtin()

    def _analyze_dotnet_with_ilspy(self):
        """通过ILSpy反编译.NET程序集。"""
        try:
            result = subprocess.run(
                ['ilspy', '--output', self.output_dir, self.file_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            if result.returncode == 0:
                self._parse_ilspy_output(result.stdout)
            else:
                logger.warning(f"[Managed] ILSpy analysis failed: {result.stderr}")
                self._analyze_dotnet_builtin()

        except subprocess.TimeoutExpired:
            logger.warning("[Managed] ILSpy analysis timeout")
            self._analyze_dotnet_builtin()
        except Exception as e:
            logger.error(f"[Managed] ILSpy analysis error: {e}")
            self._analyze_dotnet_builtin()

    def _parse_ilspy_output(self, stdout):
        """解析ILSpy输出——占位实现。"""
        pass

    def _analyze_dotnet_builtin(self):
        """内置.NET分析引擎。"""
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(0)
                pe_sig = f.read(2)

                if pe_sig != b'MZ':
                    return

                f.seek(60)
                pe_header_offset = struct.unpack('<I', f.read(4))[0]

                f.seek(pe_header_offset)
                pe_sig_check = f.read(4)
                if pe_sig_check != b'PE\x00\x00':
                    return

                f.seek(pe_header_offset + 24 + CLR_DIRECTORY_ENTRY * 8)
                clr_dir_offset = struct.unpack('<I', f.read(4))[0]
                clr_dir_size = struct.unpack('<I', f.read(4))[0]

                if clr_dir_offset == 0:
                    return

                f.seek(clr_dir_offset)
                clr_header = f.read(72)

                cb = struct.unpack('<I', clr_header[0:4])[0]
                runtime_version_major = struct.unpack('<H', clr_header[4:6])[0]
                runtime_version_minor = struct.unpack('<H', clr_header[6:8])[0]
                metadata_offset = struct.unpack('<I', clr_header[8:12])[0]
                metadata_size = struct.unpack('<I', clr_header[12:16])[0]

                strings = self._extract_dotnet_strings(f)
                self._detect_dangerous_from_strings(strings, ManagedCodeType.DOTNET)

                self._extract_metadata()['runtime_version'] = f'{runtime_version_major}.{runtime_version_minor}'

        except Exception as e:
            logger.error(f"[Managed] Built-in .NET analysis failed: {e}")

    def _extract_dotnet_strings(self, f):
        """提取.NET程序集中的字符串常量。"""
        strings = []

        try:
            f.seek(0)
            data = f.read()

            pattern = re.compile(b'[\x01-\x7F]{4,100}')

            matches = list(pattern.finditer(data))
            for match in matches:
                try:
                    s = match.group().decode('utf-8', errors='ignore')
                    if len(s) >= 4 and not s.startswith('\x00'):
                        strings.append(s)
                except UnicodeDecodeError:
                    pass

            strings = strings[:500]

        except Exception as e:
            logger.debug(f"[Managed] String extraction failed: {e}")

        return strings

    def _analyze_java(self):
        """分析Java字节码。"""
        logger.info("[Managed] Analyzing Java bytecode")

        if self.file_path.endswith('.jar'):
            self._analyze_jar()
        else:
            self._analyze_class_file(self.file_path)

    def _analyze_jar(self):
        """解析JAR归档文件。"""
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                namelist = zf.namelist()
                class_files = [n for n in namelist if n.endswith('.class')]

                logger.info(f"[Managed] JAR contains {len(class_files)} class files")

                limit = min(len(class_files), 50)
                for i in range(limit):
                    class_file = class_files[i]
                    try:
                        class_data = zf.read(class_file)
                        self._analyze_class_bytes(class_data, class_file)
                    except Exception as e:
                        logger.debug(f"[Managed] Class file {class_file} analysis failed: {e}")

                if 'META-INF/MANIFEST.MF' in namelist:
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='ignore')
                    self._extract_metadata()['manifest'] = manifest

        except zipfile.BadZipFile as e:
            logger.error(f"[Managed] JAR file parsing failed: {e}")
        except Exception as e:
            logger.error(f"[Managed] JAR analysis failed: {e}")

    def _analyze_class_file(self, file_path):
        """解析单个.class文件。"""
        try:
            with open(file_path, 'rb') as f:
                class_data = f.read()
                self._analyze_class_bytes(class_data, file_path)
        except Exception as e:
            logger.error(f"[Managed] class file analysis failed: {e}")

    def _analyze_class_bytes(self, class_data, source):
        """分析类字节码结构。"""
        try:
            data_len = len(class_data)
            if data_len < 10:
                return
            magic = struct.unpack('>I', class_data[0:4])[0]
            if magic != JAVA_CLASS_MAGIC:
                return

            minor_version = struct.unpack('>H', class_data[4:6])[0]
            major_version = struct.unpack('>H', class_data[6:8])[0]

            constant_pool_count = struct.unpack('>H', class_data[8:10])[0]
            constant_pool, cp_end = self._parse_constant_pool(class_data, constant_pool_count)

            access_flags = struct.unpack('>H', class_data[cp_end:cp_end+2])[0]
            this_class = struct.unpack('>H', class_data[cp_end+2:cp_end+4])[0]
            super_class = struct.unpack('>H', class_data[cp_end+4:cp_end+6])[0]

            class_name = self._get_class_name_from_cp(constant_pool, this_class)
            super_class_name = self._get_class_name_from_cp(constant_pool, super_class)

            methods = self._parse_methods(class_data, cp_end + 6, constant_pool)

            class_name_parts = class_name.split('/')
            if len(class_name_parts) > 0:
                simple_name = class_name_parts[-1]
            else:
                simple_name = class_name
            namespace = '/'.join(class_name_parts[:-1])

            class_info = ClassInfo(
                name=simple_name,
                namespace=namespace,
                methods=methods,
                base_class=super_class_name,
                is_public=(access_flags & 0x0001) != 0
            )

            self.classes.append(class_info)

            for method in methods:
                self._check_java_method_danger(method=method)

        except Exception as e:
            logger.debug(f"[Managed] class bytecode parsing failed ({source}): {e}")

    def _parse_constant_pool(self, class_data=b'', count=None):
        """解析Java常量池。

        两种调用模式：
        1. _parse_constant_pool(class_data, count) -> (list, end_offset)
        2. _parse_constant_pool(pool_data) -> dict（兼容测试）
        """
        if count is None:
            try:
                pool_dict = {}
                data_len = len(class_data)
                if data_len < 3:
                    return pool_dict
                if data_len >= 3:
                    cp_count = struct.unpack('>H', class_data[0:2])[0]
                else:
                    cp_count = 0
                offset = 2

                cp_limit = min(cp_count, 200)
                i = 1
                while i < cp_limit:
                    if offset >= data_len:
                        break
                    tag = class_data[offset]
                    offset += 1
                    if tag == 1:  # CONSTANT_Utf8
                        if offset + 2 > data_len:
                            break
                        length = struct.unpack('>H', class_data[offset:offset+2])[0]
                        offset += 2
                        if offset + length > data_len:
                            break
                        value = class_data[offset:offset+length].decode('utf-8', errors='replace')
                        pool_dict[f'#{i}'] = {'tag': 'Utf8', 'value': value}
                        offset += length
                    elif tag == 7:  # CONSTANT_Class
                        if offset + 2 > data_len:
                            break
                        name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                        pool_dict[f'#{i}'] = {'tag': 'Class', 'name_index': name_index}
                        offset += 2
                    else:
                        break
                    i += 1
                return pool_dict
            except Exception as e:
                logger.debug(f"[Managed] Simplified constant pool parsing failed: {e}")
                return {}

        constant_pool = [None]
        offset = 10

        i = 1
        while i < count:
            data_len = len(class_data)
            if offset >= data_len:
                break

            tag = class_data[offset]
            offset += 1

            entry = None

            if tag == 7:
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('Class', name_index)
                offset += 2
            elif tag == 9:
                class_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('Fieldref', class_index, name_and_type_index)
                offset += 4
            elif tag == 10:
                class_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('Methodref', class_index, name_and_type_index)
                offset += 4
            elif tag == 11:
                class_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('InterfaceMethodref', class_index, name_and_type_index)
                offset += 4
            elif tag == 8:
                string_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('String', string_index)
                offset += 2
            elif tag == 3:
                value = struct.unpack('>I', class_data[offset:offset+4])[0]
                entry = ('Integer', value)
                offset += 4
            elif tag == 4:
                value = struct.unpack('>f', class_data[offset:offset+4])[0]
                entry = ('Float', value)
                offset += 4
            elif tag == 5:
                value = struct.unpack('>Q', class_data[offset:offset+8])[0]
                entry = ('Long', value)
                offset += 8
                constant_pool.append(None)
            elif tag == 6:
                value = struct.unpack('>d', class_data[offset:offset+8])[0]
                entry = ('Double', value)
                offset += 8
                constant_pool.append(None)
            elif tag == 12:
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                descriptor_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('NameAndType', name_index, descriptor_index)
                offset += 4
            elif tag == 1:
                length = struct.unpack('>H', class_data[offset:offset+2])[0]
                value = class_data[offset+2:offset+2+length].decode('utf-8', errors='replace')
                entry = ('Utf8', value)
                offset += 2 + length
            elif tag == 15:
                reference_kind = class_data[offset]
                reference_index = struct.unpack('>H', class_data[offset+1:offset+3])[0]
                entry = ('MethodHandle', reference_kind, reference_index)
                offset += 3
            elif tag == 16:
                descriptor_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('MethodType', descriptor_index)
                offset += 2
            elif tag == 17:
                bootstrap_method_attr_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('Dynamic', bootstrap_method_attr_index, name_and_type_index)
                offset += 4
            elif tag == 18:
                bootstrap_method_attr_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_and_type_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                entry = ('InvokeDynamic', bootstrap_method_attr_index, name_and_type_index)
                offset += 4
            elif tag == 19:
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('Module', name_index)
                offset += 2
            elif tag == 20:
                name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                entry = ('Package', name_index)
                offset += 2
            else:
                entry = ('Unknown', tag)
                offset += 1

            constant_pool.append(entry)
            i += 1

        return constant_pool, offset

    def _get_class_name_from_cp(self, constant_pool, class_index):
        """从常量池解析类名。"""
        pool_len = len(constant_pool)
        if class_index == 0 or class_index >= pool_len:
            return 'Unknown'

        entry = constant_pool[class_index]
        if entry is not None and entry[0] == 'Class':
            name_index = entry[1]
            if name_index < pool_len:
                name_entry = constant_pool[name_index]
                if name_entry is not None and name_entry[0] == 'Utf8':
                    return name_entry[1]

        return 'Unknown'

    def _parse_methods(self, class_data, offset, constant_pool):
        """解析方法表。"""
        methods = []

        try:
            data_len = len(class_data)
            if offset + 2 > data_len:
                return methods
            interfaces_count = struct.unpack('>H', class_data[offset:offset+2])[0]
            offset += 2 + interfaces_count * 2

            if offset + 2 > data_len:
                return methods
            fields_count = struct.unpack('>H', class_data[offset:offset+2])[0]
            offset += 2

            for _ in range(fields_count):
                if offset + 8 > data_len:
                    break
                access_flags = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                descriptor_index = struct.unpack('>H', class_data[offset+4:offset+6])[0]
                attributes_count = struct.unpack('>H', class_data[offset+6:offset+8])[0]
                offset += 8

                for _ in range(attributes_count):
                    if offset + 6 > data_len:
                        break
                    attr_length = struct.unpack('>I', class_data[offset+2:offset+6])[0]
                    offset += 6 + attr_length

            if offset + 2 > data_len:
                return methods
            methods_count = struct.unpack('>H', class_data[offset:offset+2])[0]
            offset += 2

            for _ in range(methods_count):
                if offset + 8 > data_len:
                    break
                access_flags = struct.unpack('>H', class_data[offset:offset+2])[0]
                name_index = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                descriptor_index = struct.unpack('>H', class_data[offset+4:offset+6])[0]
                attributes_count = struct.unpack('>H', class_data[offset+6:offset+8])[0]
                offset += 8

                method_name = 'Unknown'
                pool_len = len(constant_pool)
                if name_index < pool_len:
                    name_entry = constant_pool[name_index]
                    if name_entry is not None and name_entry[0] == 'Utf8':
                        method_name = name_entry[1]

                method_signature = 'Unknown'
                if descriptor_index < pool_len:
                    desc_entry = constant_pool[descriptor_index]
                    if desc_entry is not None and desc_entry[0] == 'Utf8':
                        method_signature = desc_entry[1]

                bytecode = b''
                instructions = []

                for _ in range(attributes_count):
                    if offset + 6 > data_len:
                        break
                    attr_name_index = struct.unpack('>H', class_data[offset:offset+2])[0]
                    attr_length = struct.unpack('>I', class_data[offset+2:offset+6])[0]
                    offset += 6

                    attr_name = ''
                    if attr_name_index < pool_len:
                        attr_entry = constant_pool[attr_name_index]
                        if attr_entry is not None and attr_entry[0] == 'Utf8':
                            attr_name = attr_entry[1]

                    if attr_name == 'Code':
                        if offset + 8 > data_len:
                            break
                        max_stack = struct.unpack('>H', class_data[offset:offset+2])[0]
                        max_locals = struct.unpack('>H', class_data[offset+2:offset+4])[0]
                        code_length = struct.unpack('>I', class_data[offset+4:offset+8])[0]

                        code_end = offset + 8 + code_length
                        if code_end <= data_len:
                            bytecode = class_data[offset+8:code_end]
                            instructions = self._parse_bytecode_instructions(bytecode)

                        offset += 8 + code_length

                        if offset + 2 > data_len:
                            break
                        exception_table_length = struct.unpack('>H', class_data[offset:offset+2])[0]
                        offset += 2 + exception_table_length * 8

                        if offset + 2 > data_len:
                            break
                        code_attributes_count = struct.unpack('>H', class_data[offset:offset+2])[0]
                        offset += 2

                        for _ in range(code_attributes_count):
                            if offset + 6 > data_len:
                                break
                            ca_length = struct.unpack('>I', class_data[offset+2:offset+6])[0]
                            offset += 6 + ca_length
                    else:
                        offset += attr_length

                class_name_from_cp = ''
                if data_len > 10:
                    this_class_idx = struct.unpack('>H', class_data[8:10])[0]
                    class_name_from_cp = self._get_class_name_from_cp(constant_pool, this_class_idx)

                method_info = MethodInfo(
                    name=method_name,
                    class_name=class_name_from_cp,
                    signature=method_signature,
                    is_public=(access_flags & 0x0001) != 0,
                    is_static=(access_flags & 0x0008) != 0,
                    bytecode=bytecode,
                    instructions=instructions
                )
                methods.append(method_info)

        except Exception as e:
            logger.debug(f"[Managed] Method parsing failed: {e}")

        return methods

    def _parse_bytecode_instructions(self, bytecode):
        """解析字节码指令序列。"""
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
            offset = 0
            bc_len = len(bytecode)
            while offset < bc_len:
                opcode = bytecode[offset]
                name = opcode_names.get(opcode, f'unknown_{opcode:02x}')

                if opcode == 0x10:  # bipush
                    if offset + 1 < bc_len:
                        param = bytecode[offset + 1]
                        instructions.append(f'{name} {param}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0x11:  # sipush
                    if offset + 2 < bc_len:
                        param = struct.unpack('>h', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} {param}')
                        offset += 3
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0x12:  # ldc
                    if offset + 1 < bc_len:
                        param = bytecode[offset + 1]
                        instructions.append(f'{name} #{param}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x84):
                    if offset + 1 < bc_len:
                        param = bytecode[offset + 1]
                        instructions.append(f'{name} {param}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xc6, 0xc7):
                    if offset + 2 < bc_len:
                        param = struct.unpack('>h', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} {param}')
                        offset += 3
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1):
                    if offset + 2 < bc_len:
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} #{param}')
                        offset += 3
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0xb9:  # invokeinterface
                    if offset + 4 < bc_len:
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        param_count = bytecode[offset + 3]
                        instructions.append(f'{name} #{param} {param_count}')
                        offset += 5
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0xba:  # invokedynamic
                    if offset + 2 < bc_len:
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        instructions.append(f'{name} #{param}')
                        offset += 4
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0xbc:  # newarray
                    if offset + 1 < bc_len:
                        atype = bytecode[offset + 1]
                        type_names = {4: 'boolean', 5: 'char', 6: 'float', 7: 'double', 8: 'byte', 9: 'short', 10: 'int', 11: 'long'}
                        type_name = type_names.get(atype, str(atype))
                        instructions.append(f'{name} {type_name}')
                        offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0xc4:  # wide
                    if offset + 1 < bc_len:
                        sub_opcode = bytecode[offset + 1]
                        if offset + 3 < bc_len:
                            index = struct.unpack('>H', bytecode[offset+2:offset+4])[0]
                            sub_name = opcode_names.get(sub_opcode, "unknown")
                            instructions.append(f'{name} {sub_name} {index}')
                            offset += 4
                        else:
                            instructions.append(name)
                            offset += 2
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode == 0xc5:  # multianewarray
                    if offset + 3 < bc_len:
                        param = struct.unpack('>H', bytecode[offset+1:offset+3])[0]
                        dimensions = bytecode[offset + 3]
                        instructions.append(f'{name} #{param} {dimensions}')
                        offset += 4
                    else:
                        instructions.append(name)
                        offset += 1
                elif opcode in (0xc8, 0xc9):  # goto_w, jsr_w
                    if offset + 4 < bc_len:
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
            logger.debug(f"[Managed] Bytecode instruction parsing failed: {e}")

        return instructions

    def _check_java_method_danger(self, bytecode='', method_name='', method=None):
        """检查Java方法危险性。

        两种调用模式：
        1. _check_java_method_danger(bytecode, method_name) -> (is_dangerous, reasons)
        2. _check_java_method_danger(method=MethodInfo) -> (is_dangerous, reasons)
        """
        is_dangerous = False
        reasons = []

        if method is not None and isinstance(method, MethodInfo):
            bytecode_str = method.bytecode or b''
            if isinstance(bytecode_str, bytes):
                try:
                    bc_str = bytecode_str.decode('utf-8', errors='replace')
                except Exception:
                    bc_str = ''
            else:
                bc_str = str(bytecode_str)
            mname = method.name or ''

            for pattern, danger_info in JAVA_DANGEROUS_METHODS.items():
                if pattern in mname or pattern.split('.')[-1] in bc_str:
                    if not is_dangerous:
                        is_dangerous = True
                        method.is_dangerous = True
                        if isinstance(danger_info, dict):
                            desc = danger_info.get('description', str(danger_info))
                        else:
                            desc = str(danger_info)
                        reasons.append(desc)
                        method.danger_type = desc
            return is_dangerous, reasons

        for pattern, danger_info in JAVA_DANGEROUS_METHODS.items():
            if isinstance(danger_info, dict):
                desc = danger_info.get('description', str(danger_info))
            else:
                desc = str(danger_info)
            if pattern in bytecode:
                is_dangerous = True
                reasons.append(desc)
                continue
            if method_name and (pattern in method_name or pattern.split('.')[-1] in method_name):
                is_dangerous = True
                reasons.append(desc)
                continue
            if method_name and method_name in pattern:
                is_dangerous = True
                reasons.append(desc)

        return is_dangerous, reasons

    def _check_dotnet_method_danger(self, il_code='', method_name=''):
        """检查.NET方法危险性。"""
        is_dangerous = False
        reasons = []

        for pattern, danger_info in DOTNET_DANGEROUS_METHODS.items():
            if isinstance(danger_info, dict):
                desc = danger_info.get('description', str(danger_info))
            else:
                desc = str(danger_info)
            if pattern in il_code:
                is_dangerous = True
                reasons.append(desc)
                continue
            if method_name and (pattern in method_name or pattern.split('.')[-1] in method_name):
                is_dangerous = True
                reasons.append(desc)
                continue
            if method_name and method_name in pattern:
                is_dangerous = True
                reasons.append(desc)

        return is_dangerous, reasons

    def get_danger_summary(self, result=None):
        """获取危险方法摘要。"""
        if result is None:
            result = ManagedCodeAnalysisResult(
                code_type=self.code_type,
                classes=self.classes,
                dangerous_methods=self.dangerous_methods,
                vulnerabilities=self.vulnerabilities
            )

        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        danger_methods = result.dangerous_methods

        for method in danger_methods:
            method_name = method.name
            found = False

            for pattern, danger_info in JAVA_DANGEROUS_METHODS.items():
                if method_name in pattern or pattern.split('.')[-1] in method_name:
                    if isinstance(danger_info, dict):
                        sev = danger_info.get('severity', 'Medium')
                        if sev in severity_count:
                            severity_count[sev] = severity_count[sev] + 1
                    found = True
                    break

            if not found:
                for pattern, danger_info in DOTNET_DANGEROUS_METHODS.items():
                    if method_name in pattern or pattern.split('.')[-1] in method_name:
                        if isinstance(danger_info, dict):
                            sev = danger_info.get('severity', 'Medium')
                            if sev in severity_count:
                                severity_count[sev] = severity_count[sev] + 1
                        found = True
                        break

        code_type_str = str(result.code_type)
        if hasattr(result.code_type, 'value'):
            code_type_str = result.code_type.value

        vuln_count = 0
        if isinstance(result.vulnerabilities, list):
            vuln_count = len(result.vulnerabilities)

        danger_names = []
        limit = min(len(danger_methods), 10)
        for i in range(limit):
            danger_names.append(danger_methods[i].name)

        return {
            'code_type': code_type_str,
            'total_classes': len(result.classes),
            'dangerous_methods': len(result.dangerous_methods),
            'vulnerabilities': vuln_count,
            'severity_count': severity_count,
            'file_path': result.file_path,
            'error': result.error,
            'dangerous_method_names': danger_names,
        }

    def _detect_dangerous_from_strings(self, strings, code_type):
        """从字符串列表检测危险方法。"""
        if code_type == ManagedCodeType.DOTNET:
            dangerous_patterns = self.DOTNET_DANGEROUS_METHODS
        else:
            dangerous_patterns = self.JAVA_DANGEROUS_METHODS

        for s in strings:
            for pattern, danger_desc in dangerous_patterns.items():
                if pattern in s:
                    method = MethodInfo(
                        name=s,
                        class_name='',
                        is_dangerous=True,
                        danger_type=danger_desc
                    )
                    self.dangerous_methods.append(method)
                    logger.warning(f"[Managed] Dangerous pattern found in string: {s} - {danger_desc}")
                    break

    def _detect_vulnerabilities(self):
        """检测安全漏洞。"""
        for method in self.dangerous_methods:
            vuln_type = method.danger_type

            severity = 'high'
            if 'Command execution' in vuln_type or 'command execution' in vuln_type.lower():
                severity = 'critical'
            elif 'Deserialization' in vuln_type:
                severity = 'critical'
            elif 'Weak crypto' in vuln_type or 'Weak crypto' in vuln_type.lower():
                severity = 'medium'
            elif 'SQL' in vuln_type:
                severity = 'high'
            elif 'JNDI' in vuln_type:
                severity = 'critical'

            vulnerability = {
                'type': vuln_type,
                'severity': severity,
                'location': f'{method.class_name}.{method.name}',
                'description': f'Dangerous method call detected: {method.name}',
                'recommendation': self._get_recommendation(vuln_type)
            }

            self.vulnerabilities.append(vulnerability)

    def _get_recommendation(self, vuln_type):
        """获取漏洞修复建议。"""
        recommendations = {
            'Deserialization': 'Avoid unsafe deserialization methods, use allowlist for input types',
            'Command execution': 'Avoid direct user input execution, use parameterized commands',
            'Dynamic invocation': 'Limit reflection call type scope, use allowlist',
            'Dynamic loading': 'Limit loadable classes/assemblies, use sandbox isolation',
            'Weak crypto': 'Use secure crypto algorithms (AES-256, SHA-256, RSA-2048)',
            'SQL': 'Use parameterized queries, avoid SQL concatenation',
            'JNDI injection': 'Avoid remote JNDI lookup, limit lookup targets',
            'File operation': 'Validate file paths, use allowlist for access scope',
            'Network': 'Validate URL sources, limit network access scope',
        }

        for key, rec in recommendations.items():
            if key in vuln_type:
                return rec

        return 'Review the call context, ensure input is validated'

    def _decompile(self):
        """反编译代码。"""
        if self.use_ai and self.classes:
            return self._decompile_with_ai()

        return self._generate_pseudocode()

    def _decompile_with_ai(self):
        """通过AI辅助反编译。"""
        try:
            context_classes = []
            class_limit = min(len(self.classes), 10)
            for i in range(class_limit):
                c = self.classes[i]
                meth_list = []
                method_limit = min(len(c.methods), 10)
                for j in range(method_limit):
                    m = c.methods[j]
                    insts = m.instructions[:50]
                    meth_list.append({
                        'name': m.name,
                        'signature': m.signature,
                        'instructions': insts
                    })
                context_classes.append({
                    'name': c.name,
                    'namespace': c.namespace,
                    'methods': meth_list
                })

            context = {
                'file_path': self.file_path,
                'code_type': self.code_type.value,
                'classes': context_classes
            }

            from prompts import MANAGED_CODE_DECOMPILE_TEMPLATE

            result = call_ai_with_retry(
                model=get_current_ai_model(),
                messages=[
                    {"role": "system", "content": MANAGED_CODE_DECOMPILE_TEMPLATE},
                    {"role": "user", "content": json.dumps(context, ensure_ascii=False, indent=2)}
                ],
                temperature=0.2,
                max_tokens=4000
            )
            return result

        except Exception as e:
            logger.error(f"[Managed] AI decompilation failed: {e}")
            return self._generate_pseudocode()

    def _generate_pseudocode(self):
        """生成伪代码。"""
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

            method_limit = min(len(cls.methods), 20)
            for j in range(method_limit):
                method = cls.methods[j]
                method_access = 'public' if method.is_public else 'private'
                static_kw = 'static ' if method.is_static else ''
                danger_marker = ' // [DANGER]' if method.is_dangerous else ''

                lines.append(f'{indent}    {method_access} {static_kw}{method.name}({method.signature}){danger_marker}')

                if method.instructions:
                    lines.append(f'{indent}    {{')
                    inst_limit = min(len(method.instructions), 10)
                    for k in range(inst_limit):
                        lines.append(f'{indent}        {method.instructions[k]}')
                    lines.append(f'{indent}    }}')

            lines.append(f'{indent}}}')

            if cls.namespace:
                lines.append('}')

            lines.append('')

        return '\n'.join(lines)

    def _extract_metadata(self):
        """提取元数据。"""
        total_methods = 0
        for cls in self.classes:
            total_methods += len(cls.methods)

        metadata = {
            'file_path': self.file_path,
            'code_type': self.code_type.value,
            'class_count': len(self.classes),
            'method_count': total_methods,
            'dangerous_method_count': len(self.dangerous_methods),
            'vulnerability_count': len(self.vulnerabilities)
        }

        return metadata

    def _generate_summary(self):
        """生成分析摘要。"""
        summary_lines = [
            f'Managed code analysis result ({self.code_type.value})',
            f'File: {os.path.basename(self.file_path)}',
            f'Found {len(self.classes)} classes',
            f'Found {len(self.dangerous_methods)} dangerous methods',
            f'Found {len(self.vulnerabilities)} potential vulnerabilities'
        ]

        if len(self.vulnerabilities) > 0:
            severity_counts = {}
            for vuln in self.vulnerabilities:
                sev = vuln['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            summary_lines.append('Vulnerability severity distribution:')

            sev_order = ['critical', 'high', 'medium', 'low']
            sorted_keys = sorted(severity_counts.keys(), key=lambda s: sev_order.index(s) if s in sev_order else 99)

            for sev in sorted_keys:
                count = severity_counts[sev]
                summary_lines.append(f'  - {sev}: {count}')

        return '\n'.join(summary_lines)

    def to_dict(self):
        """序列化为字典。"""
        classes_list = []
        for c in self.classes:
            methods_list = []
            for m in c.methods:
                methods_list.append({
                    'name': m.name,
                    'is_dangerous': m.is_dangerous,
                    'danger_type': m.danger_type
                })
            classes_list.append({
                'name': c.name,
                'namespace': c.namespace,
                'methods': methods_list
            })

        danger_methods_list = []
        for m in self.dangerous_methods:
            danger_methods_list.append({
                'name': m.name,
                'class_name': m.class_name,
                'danger_type': m.danger_type
            })

        return {
            'file_path': self.file_path,
            'code_type': self.code_type.value,
            'classes': classes_list,
            'dangerous_methods': danger_methods_list,
            'vulnerabilities': self.vulnerabilities,
            'summary': self._generate_summary()
        }


def analyze_managed_code(file_path, output_dir=None, use_ai=True):
    """托管代码分析入口。"""
    analyzer = ManagedCodeAnalyzer(file_path, output_dir, use_ai)
    return analyzer.analyze()


def detect_managed_code_type(file_path):
    """检测托管代码类型。便捷入口。"""
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
                        namelist = zf.namelist()
                        found = any(n.endswith('.class') for n in namelist)
                        if found:
                            return ManagedCodeType.JAVA
                except zipfile.BadZipFile:
                    pass
    except Exception:
        logger.debug("suppressed", exc_info=True)

    return ManagedCodeType.UNKNOWN
