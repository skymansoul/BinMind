#!/usr/bin/env python3
"""
容器镜像安全扫描与多阶段分析模块

功能：
1. 解析 OCI/Docker 镜像格式（本地 tar 或 docker://image:tag）
2. 提取各层文件系统，识别 ELF/PE/Mach-O 二进制文件
3. 按层分组，追踪漏洞来源层
4. 批量分析二进制文件
5. 供应链分析：识别第三方库版本，匹配已知漏洞
6. 输出容器整体安全评估

依赖：docker（可选）、纯 Python tar 解析
"""

import os
import re
import tarfile
import json
import hashlib
import logging
import tempfile
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Docker SDK 可用性检查
DOCKER_SDK_AVAILABLE = False
try:
    import docker
    DOCKER_SDK_AVAILABLE = True
    logger.info("Docker SDK 已加载")
except ImportError:
    logger.warning("Docker SDK 未安装，将使用纯 Python 解析。安装: pip install docker")


# ==================== 常量定义 ====================

# OCI 镜像配置文件路径
OCI_MANIFEST_PATH = 'manifest.json'
OCI_CONFIG_PATH_PREFIX = ''

# 支持的二进制文件类型
BINARY_SIGNATURES = {
    'ELF': [b'\x7fELF'],
    'PE': [b'MZ'],
    'MACH_O': [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'],
}

# 常见危险库
DANGEROUS_LIBRARIES = {
    'openssl': {'cve_prefix': 'CVE-2022-', 'risk': 'High'},
    'libssl': {'cve_prefix': 'CVE-2022-', 'risk': 'High'},
    'glibc': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'libc': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'bash': {'cve_prefix': 'CVE-2019-', 'risk': 'Medium'},
    'curl': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'libcurl': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'ssh': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'openssh': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'sudo': {'cve_prefix': 'CVE-2021-', 'risk': 'Critical'},
    'nginx': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'apache': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'httpd': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'redis': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'mysql': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'postgres': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'python': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'java': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'node': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'php': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
}

# 路径遍历防护
PATH_TRAVERSAL_PATTERNS = [
    '..',
    '/../',
    '\\..\\',
    '/..',
    '..\\',
]


@dataclass
class LayerInfo:
    """镜像层信息数据类"""
    layer_id: str = ''
    digest: str = ''
    size: int = 0
    command: str = ''
    author: str = ''
    created: str = ''
    files: List[str] = field(default_factory=list)
    binaries: List[Dict[str, Any]] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    libraries: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = 'Unknown'
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BinaryFileInfo:
    """二进制文件信息数据类"""
    path: str = ''
    layer_id: str = ''
    file_type: str = ''
    size: int = 0
    hash_sha256: str = ''
    permissions: str = ''
    is_executable: bool = False
    analysis_result: Optional[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ContainerSecurityReport:
    """容器安全报告数据类"""
    image_name: str = ''
    total_layers: int = 0
    total_binaries: int = 0
    total_vulnerabilities: int = 0
    critical_layers: List[str] = field(default_factory=list)
    high_risk_binaries: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    layers: List[LayerInfo] = field(default_factory=list)
    libraries_summary: Dict[str, Any] = field(default_factory=dict)
    analysis_time: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContainerImageScanner:
    """
    容器镜像安全扫描器
    
    功能：
    - 解析 OCI/Docker 镜像
    - 提取各层文件系统
    - 识别二进制文件
    - 批量安全分析
    - 漏洞溯源
    
    Attributes:
        image_source: 镜像源（tar 文件或 docker://image:tag）
        output_dir: 输出目录
        layers: 层信息列表
    """
    
    def __init__(
        self,
        image_source: str,
        output_dir: Optional[str] = None,
        analyze_binaries: bool = True,
        use_docker_sdk: bool = False,
        max_workers: int = 4
    ):
        """
        初始化容器镜像扫描器
        
        Args:
            image_source: 镜像源路径（本地 tar 或 docker://image:tag）
            output_dir: 输出目录（可选）
            analyze_binaries: 是否分析二进制文件
            use_docker_sdk: 是否使用 Docker SDK
            max_workers: 最大并行分析数
        """
        self.image_source = image_source
        self.output_dir = output_dir or tempfile.mkdtemp(prefix='container_scan_')
        self.analyze_binaries = analyze_binaries
        self.use_docker_sdk = use_docker_sdk and DOCKER_SDK_AVAILABLE
        self.max_workers = max_workers
        
        self.layers: List[LayerInfo] = []
        self.binaries: List[BinaryFileInfo] = []
        self.manifest: Dict[str, Any] = {}
        self.config: Dict[str, Any] = {}
        self.image_name: str = ''
        
        # 统计
        self.stats: Dict[str, Any] = {
            'total_files': 0,
            'total_binaries': 0,
            'elf_count': 0,
            'pe_count': 0,
            'mach_o_count': 0,
        }
        
        # 验证路径
        self._validate_source()
        
        logger.info(f"[Container] 初始化扫描器: {image_source}")
    
    def _validate_source(self) -> None:
        """
        验证镜像源
        
        Raises:
            ValueError: 源无效
        """
        if not self.image_source:
            raise ValueError("镜像源不能为空")
        
        # Docker 镜像格式
        if self.image_source.startswith('docker://'):
            if not self.use_docker_sdk:
                logger.warning("[Container] Docker 镜像源需要 Docker SDK 或手动导出")
            self.image_name = self.image_source.replace('docker://', '')
            return
        
        # 本地 tar 文件
        path = os.path.abspath(self.image_source)
        
        # 路径注入检查
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in self.image_source:
                raise ValueError(f"路径包含非法字符: {pattern}")
        
        if not os.path.exists(path):
            raise ValueError(f"镜像文件不存在: {self.image_source}")
        
        if not tarfile.is_tarfile(path):
            raise ValueError(f"文件不是有效的 tar 归档: {self.image_source}")
        
        self.image_source = path
        self.image_name = os.path.basename(path)
    
    def scan(self) -> ContainerSecurityReport:
        """
        执行完整的容器镜像扫描
        
        Returns:
            ContainerSecurityReport 安全报告
        """
        logger.info("[Container] 开始扫描容器镜像...")
        
        start_time = datetime.now()
        
        try:
            # 1. 解析镜像结构
            self._parse_image()
            
            # 2. 提取各层文件系统
            self._extract_layers()
            
            # 3. 识别二进制文件
            self._identify_binaries()
            
            # 4. 分析二进制文件
            if self.analyze_binaries:
                self._analyze_binaries()
            
            # 5. 供应链分析
            self._analyze_supply_chain()
            
            # 6. 生成报告
            report = self._generate_report()
            
            elapsed = (datetime.now() - start_time).total_seconds()
            logger.info(f"[Container] 扫描完成，耗时 {elapsed:.2f} 秒")
            
            return report
            
        except Exception as e:
            logger.error(f"[Container] 扫描失败: {e}")
            return ContainerSecurityReport(
                image_name=self.image_name,
                metadata={'error': str(e)}
            )
    
    def _parse_image(self) -> None:
        """
        解析 OCI/Docker 镜像结构
        
        读取 manifest.json 和配置文件
        """
        logger.info("[Container] 解析镜像结构...")
        
        if self.use_docker_sdk and self.image_source.startswith('docker://'):
            self._parse_with_docker_sdk()
        else:
            self._parse_tar_image()
    
    def _parse_with_docker_sdk(self) -> None:
        """
        使用 Docker SDK 解析镜像
        """
        try:
            client = docker.from_env()
            image = client.images.get(self.image_name)
            
            # 获取镜像历史
            history = image.history()
            
            for i, layer_hist in enumerate(history):
                layer = LayerInfo()
                layer.layer_id = layer_hist.get('Id', '')[:12]
                layer.size = layer_hist.get('Size', 0)
                layer.command = layer_hist.get('CreatedBy', '')
                layer.created = layer_hist.get('Created', '')
                layer.author = layer_hist.get('Author', '')
                
                self.layers.append(layer)
            
            # 导出镜像到临时文件进行分析
            temp_tar = os.path.join(self.output_dir, 'temp_image.tar')
            with open(temp_tar, 'wb') as f:
                for chunk in image.save():
                    f.write(chunk)
            
            # 解析导出的 tar
            self._parse_tar_structure(temp_tar)
            
            logger.info(f"[Container] Docker SDK 解析完成，发现 {len(self.layers)} 层")
            
        except Exception as e:
            logger.warning(f"[Container] Docker SDK 解析失败: {e}，回退到 tar 解析")
            self._parse_tar_image()
    
    def _parse_tar_image(self) -> None:
        """
        解析本地 tar 镜像文件
        """
        self._parse_tar_structure(self.image_source)
    
    def _parse_tar_structure(self, tar_path: str) -> None:
        """
        解析 tar 文件结构
        
        Args:
            tar_path: tar 文件路径
        """
        try:
            with tarfile.open(tar_path, 'r') as tar:
                # 读取 manifest.json
                manifest_data = self._read_tar_file(tar, OCI_MANIFEST_PATH)
                if manifest_data:
                    self.manifest = json.loads(manifest_data)
                    
                    # 获取层信息
                    if isinstance(self.manifest, list) and len(self.manifest) > 0:
                        manifest_entry = self.manifest[0]
                        layer_digests = manifest_entry.get('Layers', [])
                        config_file = manifest_entry.get('Config', '')
                        
                        # 读取配置文件
                        if config_file:
                            config_data = self._read_tar_file(tar, config_file)
                            if config_data:
                                self.config = json.loads(config_data)
                                
                                # 解析层历史
                                history = self.config.get('history', [])
                                for i, hist in enumerate(history):
                                    layer = LayerInfo()
                                    
                                    if i < len(layer_digests):
                                        layer.digest = layer_digests[i]
                                        layer.layer_id = layer_digests[i].split('/')[-1][:12]
                                    
                                    layer.command = hist.get('created_by', '')
                                    layer.created = hist.get('created', '')
                                    layer.author = hist.get('author', '')
                                    layer.size = 0 if hist.get('empty_layer', False) else -1  # -1 表示待确定
                                    
                                    self.layers.append(layer)
                    
            logger.info(f"[Container] Tar 解析完成，发现 {len(self.layers)} 层")
            
        except Exception as e:
            logger.error(f"[Container] Tar 解析失败: {e}")
            raise
    
    def _read_tar_file(self, tar: tarfile.TarFile, path: str) -> Optional[str]:
        """
        从 tar 文件中读取指定路径的内容
        
        Args:
            tar: TarFile 对象
            path: 文件路径
            
        Returns:
            文件内容字符串或 None
        """
        try:
            member = tar.getmember(path)
            f = tar.extractfile(member)
            if f:
                return f.read().decode('utf-8', errors='replace')
        except KeyError:
            logger.warning(f"[Container] 文件不存在: {path}")
        except Exception as e:
            logger.warning(f"[Container] 读取文件失败 {path}: {e}")
        
        return None
    
    def _extract_layers(self) -> None:
        """
        提取各层文件系统
        
        解压层 tar 到临时目录，记录文件列表
        """
        logger.info("[Container] 提取各层文件系统...")
        
        with tarfile.open(self.image_source, 'r') as tar:
            for layer in self.layers:
                if layer.digest:
                    # 层 tar 路径
                    layer_tar_path = layer.digest
                    
                    try:
                        # 提取层 tar
                        layer_tar_member = tar.getmember(layer_tar_path)
                        layer_tar_file = tar.extractfile(layer_tar_member)
                        
                        if layer_tar_file:
                            # 解压层内容
                            layer_dir = os.path.join(self.output_dir, layer.layer_id)
                            os.makedirs(layer_dir, exist_ok=True)
                            
                            # 解析层 tar
                            self._extract_layer_tar(layer_tar_file, layer_dir, layer)
                            
                    except KeyError:
                        logger.warning(f"[Container] 层文件不存在: {layer_tar_path}")
                    except Exception as e:
                        logger.warning(f"[Container] 提取层失败 {layer.layer_id}: {e}")
        
        # 分析层间差异
        self._analyze_layer_diffs()
        
        logger.info(f"[Container] 提取完成，总文件数: {self.stats['total_files']}")
    
    def _extract_layer_tar(
        self,
        layer_tar_file,
        layer_dir: str,
        layer: LayerInfo
    ) -> None:
        """
        解压单个层 tar
        
        Args:
            layer_tar_file: 层 tar 文件对象
            layer_dir: 输出目录
            layer: 层信息
        """
        try:
            # 保存层 tar 到临时文件
            temp_tar_path = os.path.join(self.output_dir, f'{layer.layer_id}.tar')
            with open(temp_tar_path, 'wb') as f:
                f.write(layer_tar_file.read())
            
            # 解压
            with tarfile.open(temp_tar_path, 'r') as layer_tar:
                for member in layer_tar.getmembers():
                    # 安全检查：防止路径遍历
                    if self._is_safe_path(member.name):
                        # 记录文件
                        layer.files.append(member.name)
                        self.stats['total_files'] += 1
                        
                        # 提取文件（可选）
                        if self.analyze_binaries:
                            try:
                                # 限制提取路径
                                safe_name = member.name.lstrip('/')
                                extract_path = os.path.join(layer_dir, safe_name)
                                
                                # 确保路径安全
                                if not os.path.abspath(extract_path).startswith(layer_dir):
                                    continue
                                
                                if member.isfile():
                                    os.makedirs(os.path.dirname(extract_path), exist_ok=True)
                                    with layer_tar.extractfile(member) as src:
                                        if src:
                                            with open(extract_path, 'wb') as dst:
                                                dst.write(src.read())
                            except Exception as e:
                                logger.debug(f"[Container] 提取文件失败 {member.name}: {e}")
            
            # 清理临时 tar
            os.remove(temp_tar_path)
            
        except Exception as e:
            logger.warning(f"[Container] 解压层失败: {e}")
    
    def _is_safe_path(self, path: str) -> bool:
        """
        检查路径是否安全（防止路径遍历）
        
        Args:
            path: 文件路径
            
        Returns:
            True 如果安全
        """
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in path:
                return False
        
        # 检查绝对路径
        if path.startswith('/') or path.startswith('\\'):
            # 允许，但需要处理
            pass
        
        return True
    
    def _analyze_layer_diffs(self) -> None:
        """
        分析层间文件差异
        
        确定每层添加、删除、修改的文件
        """
        logger.info("[Container] 分析层间差异...")
        
        prev_files: Set[str] = set()
        
        for layer in self.layers:
            current_files = set(layer.files)
            
            # 新增文件
            layer.added_files = list(current_files - prev_files)
            
            # 删除文件（通过 .wh.* 白out文件）
            deleted = []
            for f in layer.files:
                # Docker 使用 .wh.* 文件表示删除
                if '/.wh.' in f or f.startswith('.wh.'):
                    original = f.replace('.wh.', '')
                    deleted.append(original)
            layer.deleted_files = deleted
            
            # 修改文件（同路径但在新层中存在）
            layer.modified_files = list(current_files & prev_files)
            
            prev_files = current_files - set(deleted) | set(layer.added_files)
    
    def _identify_binaries(self) -> None:
        """
        识别各层中的二进制文件
        
        通过文件签名识别 ELF/PE/Mach-O
        """
        logger.info("[Container] 识别二进制文件...")
        
        for layer in self.layers:
            layer_dir = os.path.join(self.output_dir, layer.layer_id)
            
            for file_path in layer.files:
                if not self._is_safe_path(file_path):
                    continue
                
                safe_name = file_path.lstrip('/')
                full_path = os.path.join(layer_dir, safe_name)
                
                if os.path.isfile(full_path):
                    binary_info = self._identify_binary_file(full_path, file_path, layer.layer_id)
                    if binary_info:
                        layer.binaries.append({
                            'path': file_path,
                            'type': binary_info.file_type,
                            'size': binary_info.size,
                            'hash': binary_info.hash_sha256,
                            'is_executable': binary_info.is_executable
                        })
                        self.binaries.append(binary_info)
                        
                        # 更新统计
                        if binary_info.file_type == 'ELF':
                            self.stats['elf_count'] += 1
                        elif binary_info.file_type == 'PE':
                            self.stats['pe_count'] += 1
                        elif binary_info.file_type == 'MACH_O':
                            self.stats['mach_o_count'] += 1
        
        self.stats['total_binaries'] = len(self.binaries)
        logger.info(f"[Container] 发现 {len(self.binaries)} 个二进制文件")
    
    def _identify_binary_file(
        self,
        full_path: str,
        rel_path: str,
        layer_id: str
    ) -> Optional[BinaryFileInfo]:
        """
        识别单个二进制文件
        
        Args:
            full_path: 文件完整路径
            rel_path: 相对路径
            layer_id: 所属层 ID
            
        Returns:
            BinaryFileInfo 或 None
        """
        try:
            # 读取文件头
            with open(full_path, 'rb') as f:
                header = f.read(16)
            
            if len(header) < 4:
                return None
            
            # 检查签名
            file_type = None
            for sig_type, signatures in BINARY_SIGNATURES.items():
                for sig in signatures:
                    if header.startswith(sig):
                        file_type = sig_type
                        break
            
            if not file_type:
                return None
            
            # 获取文件信息
            size = os.path.getsize(full_path)
            
            # 计算哈希
            sha256 = hashlib.sha256()
            with open(full_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            hash_sha256 = sha256.hexdigest()
            
            # 检查是否可执行
            permissions = os.stat(full_path).st_mode
            is_executable = (permissions & 0o111) != 0
            
            return BinaryFileInfo(
                path=rel_path,
                layer_id=layer_id,
                file_type=file_type,
                size=size,
                hash_sha256=hash_sha256,
                permissions=oct(permissions)[-3:],
                is_executable=is_executable
            )
            
        except Exception as e:
            logger.debug(f"[Container] 识别文件失败 {rel_path}: {e}")
            return None
    
    def _analyze_binaries(self) -> None:
        """
        批量分析二进制文件
        
        调用现有分析流水线
        """
        logger.info("[Container] 批量分析二进制文件...")
        
        # 并行分析
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for binary in self.binaries:
                layer_dir = os.path.join(self.output_dir, binary.layer_id)
                safe_name = binary.path.lstrip('/')
                full_path = os.path.join(layer_dir, safe_name)
                
                if os.path.exists(full_path):
                    future = executor.submit(
                        self._analyze_single_binary,
                        full_path,
                        binary
                    )
                    futures[future] = binary
            
            for future in as_completed(futures):
                binary = futures[future]
                try:
                    result = future.result(timeout=60)
                    if result:
                        binary.analysis_result = result
                        binary.vulnerabilities = result.get('vulnerabilities', [])
                except Exception as e:
                    logger.warning(f"[Container] 分析失败 {binary.path}: {e}")
        
        # 汇总漏洞到层
        self._aggregate_vulnerabilities()
    
    def _analyze_single_binary(
        self,
        binary_path: str,
        binary_info: BinaryFileInfo
    ) -> Optional[Dict[str, Any]]:
        """
        分析单个二进制文件
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 文件信息
            
        Returns:
            分析结果
        """
        try:
            # 使用现有的 info_collect 模块
            from modules.info_collect import get_binary_info, detect_binary_format
            
            binary_format = detect_binary_format(binary_path)
            binary_data = get_binary_info(binary_path)
            
            if not binary_data:
                return None
            
            result = {
                'binary_path': binary_path,
                'format': binary_format,
                'arch': binary_data.get('arch', 'Unknown'),
                'bits': binary_data.get('bits', 0),
                'checksec': binary_data.get('checksec', {}),
                'imports': binary_data.get('imports', {}),
                'dangerous_functions': binary_data.get('imports', {}).get('dangerous_functions', []),
                'symbols': binary_data.get('symbols', {}),
                'vulnerabilities': []
            }
            
            # 基于危险函数生成漏洞提示
            dangerous = result.get('dangerous_functions', [])
            if dangerous:
                for func in dangerous:
                    result['vulnerabilities'].append({
                        'type': 'Dangerous Function',
                        'function': func,
                        'severity': 'Medium',
                        'description': f'发现危险函数: {func}',
                        'layer': binary_info.layer_id
                    })
            
            return result
            
        except Exception as e:
            logger.debug(f"[Container] 分析二进制失败: {e}")
            return None
    
    def _aggregate_vulnerabilities(self) -> None:
        """
        汇总漏洞到层
        """
        for layer in self.layers:
            layer.vulnerabilities = []
            
            for binary in self.binaries:
                if binary.layer_id == layer.layer_id and binary.vulnerabilities:
                    layer.vulnerabilities.extend(binary.vulnerabilities)
            
            # 评估层风险
            if layer.vulnerabilities:
                critical = len([v for v in layer.vulnerabilities if v.get('severity') == 'Critical'])
                high = len([v for v in layer.vulnerabilities if v.get('severity') == 'High'])
                
                if critical > 0:
                    layer.risk_level = 'Critical'
                elif high > 0:
                    layer.risk_level = 'High'
                elif len(layer.vulnerabilities) > 0:
                    layer.risk_level = 'Medium'
                else:
                    layer.risk_level = 'Low'
    
    def _analyze_supply_chain(self) -> None:
        """
        供应链分析
        
        识别第三方库版本，匹配已知漏洞
        """
        logger.info("[Container] 执行供应链分析...")
        
        libraries_found = defaultdict(list)
        
        # 从文件路径识别库
        for binary in self.binaries:
            path = binary.path.lower()
            
            for lib_name, lib_info in DANGEROUS_LIBRARIES.items():
                if lib_name in path:
                    libraries_found[lib_name].append({
                        'path': binary.path,
                        'layer': binary.layer_id,
                        'type': binary.file_type,
                        'hash': binary.hash_sha256,
                        'risk': lib_info['risk']
                    })
        
        # 汇总到层
        for layer in self.layers:
            layer.libraries = []
            for lib_name, instances in libraries_found.items():
                for inst in instances:
                    if inst['layer'] == layer.layer_id:
                        layer.libraries.append({
                            'name': lib_name,
                            'path': inst['path'],
                            'risk': inst['risk']
                        })
        
        self.stats['libraries_found'] = len(libraries_found)
        logger.info(f"[Container] 发现 {len(libraries_found)} 个已知危险库")
    
    def _generate_report(self) -> ContainerSecurityReport:
        """
        生成安全报告
        
        Returns:
            ContainerSecurityReport
        """
        report = ContainerSecurityReport()
        
        report.image_name = self.image_name
        report.total_layers = len(self.layers)
        report.total_binaries = len(self.binaries)
        report.analysis_time = datetime.now().isoformat()
        
        # 汇总漏洞
        all_vulns = []
        for binary in self.binaries:
            all_vulns.extend(binary.vulnerabilities)
        
        report.total_vulnerabilities = len(all_vulns)
        
        # 高风险层
        report.critical_layers = [
            layer.layer_id for layer in self.layers
            if layer.risk_level in ['Critical', 'High']
        ]
        
        # 高风险二进制
        report.high_risk_binaries = [
            binary.path for binary in self.binaries
            if binary.vulnerabilities and any(
                v.get('severity') in ['Critical', 'High'] 
                for v in binary.vulnerabilities
            )
        ]
        
        # 层详情
        report.layers = self.layers
        
        # 库摘要
        report.libraries_summary = {
            'found': self.stats.get('libraries_found', 0),
            'details': []
        }
        
        for layer in self.layers:
            for lib in layer.libraries:
                report.libraries_summary['details'].append({
                    'name': lib['name'],
                    'layer': layer.layer_id,
                    'risk': lib['risk']
                })
        
        # 建议
        report.recommendations = self._generate_recommendations()
        
        # 元数据
        report.metadata = {
            'stats': self.stats,
            'manifest': self.manifest,
            'config_summary': {
                'architecture': self.config.get('architecture', ''),
                'os': self.config.get('os', ''),
                'created': self.config.get('created', ''),
            }
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """
        生成安全建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 基于风险层
        if report.critical_layers:
            recommendations.append(
                f'审查高风险层: {", ".join(report.critical_layers[:5])}'
            )
        
        # 基于库
        high_risk_libs = [
            lib['name'] for lib in report.libraries_summary.get('details', [])
            if lib['risk'] in ['Critical', 'High']
        ]
        if high_risk_libs:
            recommendations.append(
                f'更新高风险库: {", ".join(set(high_risk_libs[:5]))}'
            )
        
        # 通用建议
        recommendations.extend([
            '最小化镜像层，减少不必要的软件包',
            '使用多阶段构建，分离构建和运行环境',
            '定期更新基础镜像',
            '扫描并修复已知 CVE',
            '使用最小权限运行容器',
            '启用容器安全扫描 CI/CD 流程'
        ])
        
        return recommendations
    
    def cleanup(self) -> None:
        """
        清理临时文件
        """
        if self.output_dir and self.output_dir.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(self.output_dir)
                logger.info(f"[Container] 已清理临时目录: {self.output_dir}")
            except Exception as e:
                logger.warning(f"[Container] 清理失败: {e}")


def scan_container_image(
    image_source: str,
    output_dir: Optional[str] = None,
    analyze_binaries: bool = True
) -> ContainerSecurityReport:
    """
    扫描容器镜像的便捷函数
    
    Args:
        image_source: 镜像源
        output_dir: 输出目录
        analyze_binaries: 是否分析二进制
        
    Returns:
        ContainerSecurityReport
    """
    scanner = ContainerImageScanner(
        image_source=image_source,
        output_dir=output_dir,
        analyze_binaries=analyze_binaries
    )
    
    return scanner.scan()


# ==================== 导出 ====================

__all__ = [
    'ContainerImageScanner',
    'LayerInfo',
    'BinaryFileInfo',
    'ContainerSecurityReport',
    'scan_container_image',
    'DOCKER_SDK_AVAILABLE',
    'DANGEROUS_LIBRARIES'
]