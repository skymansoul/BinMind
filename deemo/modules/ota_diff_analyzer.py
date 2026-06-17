#!/usr/bin/env python3
"""
固件OTA差分更新分析模块

分析OTA更新包，提取新旧固件差异，检测安全问题。
支持的OTA格式：
- 差分压缩包（zlib、LZMA）
- Google Omaha
- SWUpdate双拷贝
- HDiffPatch
"""

import logging
import os
import re
import shutil
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OTAFormat(Enum):
    """OTA包格式枚举"""
    UNKNOWN = "unknown"
    ZIP = "zip"
    TAR = "tar"
    LZMA = "lzma"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    HDIFF = "hdiff"
    OMAHA = "omaha"
    SWUPDATE = "swupdate"
    BIN = "bin"


class ChangeType(Enum):
    """变更类型枚举"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class OTAPatchChange:
    """
    OTA补丁变更定义
    """
    change_type: ChangeType
    file_name: str
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    size_change: int = 0
    is_binary: bool = False
    suspicious: bool = False


@dataclass
class OTAIssue:
    """
    OTA安全问题定义
    """
    type: str
    description: str
    risk_level: RiskLevel
    file_name: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class OTADiffResult:
    """
    OTA差分分析结果
    """
    ota_path: str
    baseline_path: str = ""
    ota_format: OTAFormat = OTAFormat.UNKNOWN
    changes: List[OTAPatchChange] = field(default_factory=list)
    issues: List[OTAIssue] = field(default_factory=list)
    extracted_files: List[str] = field(default_factory=list)
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'ota_path': self.ota_path,
            'baseline_path': self.baseline_path,
            'ota_format': self.ota_format.value,
            'changes': [
                {
                    'type': change.change_type.value,
                    'file_name': change.file_name,
                    'old_path': change.old_path,
                    'new_path': change.new_path,
                    'size_change': change.size_change,
                    'is_binary': change.is_binary,
                    'suspicious': change.suspicious
                }
                for change in self.changes
            ],
            'issues': [
                {
                    'type': issue.type,
                    'description': issue.description,
                    'risk_level': issue.risk_level.value,
                    'file_name': issue.file_name,
                    'evidence': issue.evidence,
                    'recommendation': issue.recommendation
                }
                for issue in self.issues
            ],
            'extracted_files': self.extracted_files,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message
        }


class OTADiffAnalyzer:
    """
    固件OTA差分更新分析器
    
    分析OTA更新包，提取新旧固件差异，检测安全问题。
    """

    # 危险文件模式
    DANGEROUS_FILES = {
        'init', 'systemd', 'rc.local', 'rc.d',
        'sshd', 'dropbear', 'telnetd',
        'bash', 'sh', 'busybox',
        'iptables', 'firewall',
        'sshd_config', 'ssh_config',
        'passwd', 'shadow', 'group',
        'crontab', 'cron.d',
        'init.d', 'systemd/system',
        'ld.so.preload', 'ld.so.conf'
    }

    # 脚本文件扩展名
    SCRIPT_EXTENSIONS = {'.sh', '.py', '.lua', '.awk', '.sed', '.pl'}

    # 二进制文件扩展名
    BINARY_EXTENSIONS = {'.bin', '.exe', '.so', '.ko', '.elf', '.a', '.o'}

    def __init__(self, ota_path: str, baseline_path: str = ""):
        """
        初始化OTA分析器
        
        Args:
            ota_path: OTA更新包路径
            baseline_path: 基线固件路径（可选）
        """
        self.ota_path = ota_path
        self.baseline_path = baseline_path
        self.extracted_dir = None

    def _validate_path(self, path: str, description: str) -> bool:
        """验证文件路径"""
        if not os.path.exists(path):
            logger.error(f"{description}不存在: {path}")
            return False
        if not os.path.isfile(path):
            logger.error(f"{description}不是有效文件: {path}")
            return False
        return True

    def _detect_ota_format(self, result: OTADiffResult) -> None:
        """检测OTA包格式"""
        filename = os.path.basename(self.ota_path).lower()
        
        if filename.endswith('.zip'):
            result.ota_format = OTAFormat.ZIP
        elif filename.endswith('.tar') or filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            result.ota_format = OTAFormat.TAR
        elif filename.endswith('.lzma') or filename.endswith('.xz'):
            result.ota_format = OTAFormat.LZMA
        elif filename.endswith('.gz'):
            result.ota_format = OTAFormat.GZIP
        elif filename.endswith('.bz2'):
            result.ota_format = OTAFormat.BZIP2
        elif filename.endswith('.hdiff') or filename.endswith('.hpatch'):
            result.ota_format = OTAFormat.HDIFF
        elif 'omaha' in filename:
            result.ota_format = OTAFormat.OMAHA
        elif 'swupdate' in filename:
            result.ota_format = OTAFormat.SWUPDATE
        elif filename.endswith('.bin'):
            result.ota_format = OTAFormat.BIN
        else:
            # 尝试通过文件头检测
            self._detect_format_by_magic(result)
        
        logger.debug(f"检测到OTA格式: {result.ota_format.value}")

    def _detect_format_by_magic(self, result: OTADiffResult) -> None:
        """通过文件头魔数检测格式"""
        try:
            with open(self.ota_path, 'rb') as f:
                header = f.read(16)
            
            if header.startswith(b'\x50\x4B\x03\x04'):
                result.ota_format = OTAFormat.ZIP
            elif header.startswith(b'\x1F\x8B\x08'):
                result.ota_format = OTAFormat.GZIP
            elif header.startswith(b'\x42\x5A\x68'):
                result.ota_format = OTAFormat.BZIP2
            elif header.startswith(b'\xFD\x37\x7A\x58\x5A'):
                result.ota_format = OTAFormat.LZMA
            elif header.startswith(b'\x7F\x45\x4C\x46'):
                result.ota_format = OTAFormat.BIN
            
        except Exception as e:
            logger.debug(f"文件头检测失败: {e}")

    def _extract_ota_content(self, result: OTADiffResult) -> Optional[List[str]]:
        """提取OTA包内容"""
        extracted_files = []
        
        try:
            self.extracted_dir = tempfile.mkdtemp(prefix='ota_extract_')
            logger.debug(f"提取目录: {self.extracted_dir}")
            
            if result.ota_format == OTAFormat.ZIP:
                extracted_files = self._extract_zip(self.ota_path, self.extracted_dir)
            elif result.ota_format == OTAFormat.TAR:
                extracted_files = self._extract_tar(self.ota_path, self.extracted_dir)
            elif result.ota_format == OTAFormat.GZIP:
                extracted_files = self._extract_gzip(self.ota_path, self.extracted_dir)
            elif result.ota_format == OTAFormat.LZMA:
                extracted_files = self._extract_lzma(self.ota_path, self.extracted_dir)
            elif result.ota_format == OTAFormat.BIN:
                extracted_files = self._extract_bin(self.ota_path, self.extracted_dir)
            else:
                extracted_files = self._extract_generic(self.ota_path, self.extracted_dir)
            
            result.extracted_files = extracted_files
            logger.debug(f"提取到 {len(extracted_files)} 个文件")
            
            return extracted_files
            
        except Exception as e:
            logger.error(f"提取OTA内容失败: {e}")
            return None

    def _extract_zip(self, zip_path: str, dest_dir: str) -> List[str]:
        """提取ZIP文件"""
        import zipfile
        files = []
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(dest_dir)
            files = zf.namelist()
        
        return files

    def _extract_tar(self, tar_path: str, dest_dir: str) -> List[str]:
        """提取TAR文件"""
        import tarfile
        files = []
        
        mode = 'r:gz' if tar_path.endswith('.gz') or tar_path.endswith('.tgz') else 'r'
        with tarfile.open(tar_path, mode) as tf:
            tf.extractall(dest_dir)
            files = [m.name for m in tf.getmembers() if m.isfile()]
        
        return files

    def _extract_gzip(self, gz_path: str, dest_dir: str) -> List[str]:
        """提取GZIP文件"""
        import gzip
        import shutil
        
        files = []
        base_name = os.path.basename(gz_path)[:-3]
        output_path = os.path.join(dest_dir, base_name)
        
        with gzip.open(gz_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        files.append(output_path)
        return files

    def _extract_lzma(self, lzma_path: str, dest_dir: str) -> List[str]:
        """提取LZMA文件"""
        try:
            import lzma
        except ImportError:
            logger.warning("lzma模块不可用")
            return []
        
        files = []
        base_name = os.path.basename(lzma_path)[:-4] if lzma_path.endswith('.xz') else os.path.basename(lzma_path)[:-5]
        output_path = os.path.join(dest_dir, base_name)
        
        with lzma.open(lzma_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        files.append(output_path)
        return files

    def _extract_bin(self, bin_path: str, dest_dir: str) -> List[str]:
        """提取BIN文件（直接复制）"""
        files = []
        base_name = os.path.basename(bin_path)
        output_path = os.path.join(dest_dir, base_name)
        
        shutil.copy2(bin_path, output_path)
        files.append(output_path)
        
        return files

    def _extract_generic(self, file_path: str, dest_dir: str) -> List[str]:
        """通用提取方法"""
        files = []
        base_name = os.path.basename(file_path)
        output_path = os.path.join(dest_dir, base_name)
        
        shutil.copy2(file_path, output_path)
        files.append(output_path)
        
        return files

    def _analyze_changes(self, extracted_data: List[str], result: OTADiffResult) -> None:
        """分析变更"""
        changes = []
        
        for filename in extracted_data:
            full_path = os.path.join(self.extracted_dir, filename) if self.extracted_dir else filename
            
            if os.path.isfile(full_path):
                is_binary = self._is_binary_file(filename)
                
                change = OTAPatchChange()
                    change_type=ChangeType.ADDED,
                    file_name=filename,
                    new_path=full_path,
                    is_binary=is_binary,
                    suspicious=self._is_suspicious_file(filename)
                
                changes.append(change)
        
        result.changes = changes
        logger.debug(f"分析到 {len(changes)} 个变更")

    def _is_binary_file(self, filename: str) -> bool:
        """判断是否为二进制文件"""
        lower_name = filename.lower()
        return any(lower_name.endswith(ext) for ext in self.BINARY_EXTENSIONS)

    def _is_suspicious_file(self, filename: str) -> bool:
        """判断文件是否可疑"""
        lower_name = filename.lower()
        basename = os.path.basename(lower_name)
        
        # 检查危险文件名
        if basename in self.DANGEROUS_FILES:
            return True
        
        # 检查路径中的可疑目录
        suspicious_dirs = ['bin', 'sbin', 'etc', 'usr/bin', 'usr/sbin', 'var']
        for dir_name in suspicious_dirs:
            if dir_name in lower_name.split(os.sep):
                return True
        
        return False

    def _detect_security_issues(self, extracted_data: List[str], result: OTADiffResult) -> None:
        """检测安全问题"""
        self._detect_suspicious_scripts(extracted_data, result)
        self._detect_dangerous_binaries(extracted_data, result)
        self._detect_config_changes(extracted_data, result)
        self._detect_backdoor_signatures(extracted_data, result)

    def _detect_suspicious_scripts(self, extracted_data: List[str], result: OTADiffResult) -> None:
        """检测可疑脚本"""
        for filename in extracted_data:
            lower_name = filename.lower()
            
            if any(lower_name.endswith(ext) for ext in self.SCRIPT_EXTENSIONS):
                full_path = os.path.join(self.extracted_dir, filename) if self.extracted_dir else filename
                
                if os.path.exists(full_path):
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # 检查可疑命令
                            suspicious_patterns = [
                                (r'system\(', 'system调用'))
                                (r'exec\(', 'exec调用'))
                                (r'eval\(', 'eval调用'))
                                (r'curl\s+-o', 'curl下载'),
                                (r'wget\s+-O', 'wget下载'),
                                (r'chmod\s+777', '权限设置'),
                                (r'rm\s+-rf', '强制删除'),
                                (r'netcat|nc\s+-e', '反向shell')
                            ]
                            
                            for pattern, desc in suspicious_patterns:
                                if re.search(pattern, content):
                                    issue = OTAIssue()
                                        type='suspicious_script',
                                        description=f"脚本 {filename} 包含可疑命令: {desc}",
                                        risk_level=RiskLevel.HIGH,
                                        file_name=filename,
                                        evidence=f"检测到 {desc} 模式",
                                        recommendation="审查脚本内容，确保无恶意代码"
                                    
                                    result.issues.append(issue)
                                    break
                    except Exception as e:
                        logger.debug(f"读取脚本 {filename} 失败: {e}")

    def _detect_dangerous_binaries(self, extracted_data: List[str], result: OTADiffResult) -> None:
        """检测危险二进制文件"""
        dangerous_binaries = {
            'netcat', 'nc', 'ncat',
            'socat', 'telnet', 'ftp',
            'ssh', 'sshd', 'dropbear',
            'bash', 'sh', 'busybox',
            'python', 'perl', 'ruby',
            'curl', 'wget', 'fetch'
        }
        
        for filename in extracted_data:
            basename = os.path.basename(filename).lower()
            
            if basename in dangerous_binaries:
                issue = OTAIssue()
                    type='dangerous_binary',
                    description=f"检测到危险二进制文件: {filename}",
                    risk_level=RiskLevel.MEDIUM,
                    file_name=filename,
                    evidence=f"文件存在于OTA包中",
                    recommendation="确认该二进制文件的必要性，验证其完整性"
                
                result.issues.append(issue)

    def _detect_config_changes(self, extracted_data: List[str], result: OTADiffResult) -> None:
        """检测配置文件变更"""
        config_files = {
            'sshd_config', 'ssh_config',
            'passwd', 'shadow', 'group',
            'hosts', 'resolv.conf',
            'fstab', 'inittab',
            'crontab', 'cron.d'
        }
        
        for filename in extracted_data:
            basename = os.path.basename(filename).lower()
            
            if basename in config_files:
                issue = OTAIssue()
                    type='config_change',
                    description=f"配置文件变更: {filename}",
                    risk_level=RiskLevel.MEDIUM,
                    file_name=filename,
                    evidence=f"配置文件包含在OTA包中",
                    recommendation="审查配置变更，确认无安全风险"
                
                result.issues.append(issue)

    def _detect_backdoor_signatures(self, extracted_data: List[str], result: OTADiffResult) -> None:
        """检测后门签名"""
        backdoor_patterns = [
            r'backdoor', r'back_door',
            r'reverse_shell', r'revshell',
            r'bind_shell', r'rootkit',
            r'botnet', r'c2', r'c&c',
            r'malware', r'trojan'
        ]
        
        for filename in extracted_data:
            full_path = os.path.join(self.extracted_dir, filename) if self.extracted_dir else filename
            
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'rb') as f:
                        data = f.read()
                        content = data.decode('utf-8', errors='ignore')
                        
                        for pattern in backdoor_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                issue = OTAIssue()
                                    type='backdoor_suspicion',
                                    description=f"文件 {filename} 包含可疑字符串: {pattern}",
                                    risk_level=RiskLevel.CRITICAL,
                                    file_name=filename,
                                    evidence=f"检测到模式: {pattern}",
                                    recommendation="立即审查此文件，确认是否存在后门"
                                
                                result.issues.append(issue)
                                break
                except Exception as e:
                    logger.debug(f"扫描文件 {filename} 失败: {e}")

    def _cleanup(self) -> None:
        """清理临时文件"""
        if self.extracted_dir and os.path.exists(self.extracted_dir):
            try:
                shutil.rmtree(self.extracted_dir)
                logger.debug(f"清理临时目录: {self.extracted_dir}")
            except Exception as e:
                logger.warning(f"清理临时目录失败: {e}")

    def analyze(self) -> OTADiffResult:
        """
        执行OTA差分分析
        
        Returns:
            OTADiffResult 分析结果
        """
        logger.info(f"开始OTA差分分析: {self.ota_path}")
        
        result = OTADiffResult(ota_path=self.ota_path, baseline_path=self.baseline_path)
        
        if not self._validate_path(self.ota_path, "OTA包"):
            result.error_message = f"无效的OTA包路径: {self.ota_path}",
            return result
        
        try:
            self._detect_ota_format(result)
            logger.debug(f"检测到OTA格式: {result.ota_format.value}")
            
            extracted_data = self._extract_ota_content(result)
            if not extracted_data:
                result.error_message = "无法提取OTA包内容",
                return result
            
            self._analyze_changes(extracted_data, result)
            self._detect_security_issues(extracted_data, result)
            
            # 去重
            seen = set()
            unique_issues = []
            for issue in result.issues:
                key = (issue.type, issue.file_name, issue.description)
                if key not in seen:
                    seen.add(key)
                    unique_issues.append(issue)
            result.issues = unique_issues
            
            result.analysis_success = True
            logger.info(f"OTA差分分析完成，发现 {len(result.changes)} 个变更，{len(result.issues)} 个安全问题")
            
        except Exception as e:
            logger.error(f"OTA差分分析失败: {e}")
            result.error_message = str(e)
        finally:
            self._cleanup()
        
        return result

    def generate_report(self, output_path: str = None) -> Optional[str]:
        """
        生成OTA差分分析报告
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            报告内容或保存路径
        """
        result = self.analyze()
        
        if not result.analysis_success:
            return None
        
        lines = []
        lines.append("# OTA差分更新分析报告")
        lines.append("")
        lines.append(f"**OTA包**: `{result.ota_path}`")
        if result.baseline_path:
            lines.append(f"**基线固件**: `{result.baseline_path}`")
        lines.append(f"**OTA格式**: {result.ota_format.value}")
        lines.append(f"**分析时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("## 概览")
        lines.append("")
        lines.append(f"- 提取文件数: {len(result.extracted_files)}")
        lines.append(f"- 变更数: {len(result.changes)}")
        lines.append(f"- 安全问题数: {len(result.issues)}")
        lines.append("")
        
        if result.changes:
            lines.append("## 变更列表")
            lines.append("")
            lines.append("| 类型 | 文件 | 二进制 | 可疑 |")
            lines.append("|------|------|--------|------|")
            
            for change in result.changes:
                lines.append(f"| {change.change_type.value} | `{change.file_name}` | {'是' if change.is_binary else '否'} | {'是' if change.suspicious else '否'} |")
            
            lines.append("")
        
        if result.issues:
            lines.append("## 安全问题")
            lines.append("")
            lines.append("| 类型 | 风险等级 | 文件 | 描述 |")
            lines.append("|------|----------|------|------|")
            
            for issue in result.issues:
                lines.append(f"| {issue.type} | {issue.risk_level.value} | `{issue.file_name}` | {issue.description} |")
            
            lines.append("")
            lines.append("## 问题详情")
            lines.append("")
            
            for issue in result.issues:
                lines.append(f"### {issue.description}")
                lines.append("")
                lines.append(f"**类型**: {issue.type}")
                lines.append(f"**风险等级**: {issue.risk_level.value}")
                lines.append(f"**文件**: `{issue.file_name}`")
                lines.append("")
                lines.append(f"**修复建议**: {issue.recommendation}")
                lines.append("")
        
        report_content = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return output_path
        
        return report_content
