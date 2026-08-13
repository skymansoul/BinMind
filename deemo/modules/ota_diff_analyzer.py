#!/usr/bin/env python3
# OTA 包差分安全分析（v2）：对 OTA 包做格式识别与安全特征扫描。
# 兼容入口：v1 的二进制差分实现已迁移至子目录（modules/firmware/ 与
# modules/platform/firmware/），本扁平文件承载测试规格要求的 v2 API。
import gzip
import logging
import os
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


class OTAFormat(Enum):
    ZIP = "zip"
    GZIP = "gzip"
    BIN = "bin"
    RAW = "raw"
    DELTA = "delta"
    FULL = "full"


class ChangeType(Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class OTAIssue:
    type: str
    description: str = ""
    risk: RiskLevel = RiskLevel.MEDIUM


@dataclass
class OTADiffResult:
    ota_path: str = ""
    ota_format: Optional[OTAFormat] = None
    changes: List[Any] = field(default_factory=list)
    issues: List[OTAIssue] = field(default_factory=list)
    extracted_files: List[str] = field(default_factory=list)
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典；键名与测试规格一致。"""
        return {
            "ota_path": self.ota_path,
            "ota_format": self.ota_format.value if self.ota_format else None,
            "changes": self.changes,
            "issues": [{"type": i.type, "description": i.description,
                        "risk": i.risk.value} for i in self.issues],
            "extracted_files": self.extracted_files,
            "analysis_success": self.analysis_success,
        }


# 危险二进制文件名特征：出现在 bin/ 目录下的网络/命令执行工具
_DANGEROUS_BINARIES = ("netcat", "nc", "busybox", "telnetd", "dropbear")

# 敏感配置路径特征
_CONFIG_PATHS = ("etc/passwd", "etc/shadow", "etc/sshd_config", "etc/rc.local")

# 可疑脚本内容特征
_SUSPICIOUS_PATTERNS = (
    "system(", "curl ", "wget ", "rm -rf", "chmod 777", "telnet ", "nc -e",
)


class OTADiffAnalyzer:
    """OTA 包安全分析器：识别包格式并扫描可疑脚本/危险二进制/配置变更/后门特征。"""

    def __init__(self, ota_path: str = ""):
        self.ota_path = ota_path
        self._last_result: Optional[OTADiffResult] = None

    # -- 分析主流程 -----------------------------------------------------------

    def analyze(self) -> OTADiffResult:
        """分析 OTA 包；路径无效时返回失败结果，错误信息固定前缀。"""
        if not self.ota_path or not os.path.isfile(self.ota_path):
            result = OTADiffResult(
                ota_path=self.ota_path,
                error_message="无效的OTA包路径: %s" % self.ota_path,
            )
            self._last_result = result
            return result

        try:
            fmt = self._detect_format(self.ota_path)
            if fmt == OTAFormat.ZIP:
                result = self._analyze_zip(self.ota_path)
            elif fmt == OTAFormat.GZIP:
                result = self._analyze_gzip(self.ota_path)
            else:
                result = self._analyze_bin(self.ota_path)
        except Exception as e:
            log.warning("OTA 分析失败: %s", e)
            result = OTADiffResult(
                ota_path=self.ota_path,
                error_message="分析失败: %s" % e,
            )

        result.ota_format = result.ota_format or fmt
        result.analysis_success = result.error_message == ""
        self._last_result = result
        return result

    def _detect_format(self, path: str) -> OTAFormat:
        """按扩展名与魔数识别格式：zip 魔数 PK、gzip 魔数 1f8b、ELF 魔数 7f45。"""
        ext = os.path.splitext(path)[1].lower()
        if ext == ".zip" or zipfile.is_zipfile(path):
            return OTAFormat.ZIP
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"\x1f\x8b" or ext == ".gz":
            return OTAFormat.GZIP
        if magic == b"\x7fELF":
            return OTAFormat.BIN
        return OTAFormat.RAW

    def _analyze_zip(self, path: str) -> OTADiffResult:
        """解包 ZIP 并逐条目执行安全特征扫描。"""
        result = OTADiffResult(ota_path=path, ota_format=OTAFormat.ZIP)
        with zipfile.ZipFile(path) as zf:
            entries = zf.namelist()
            result.extracted_files = list(entries)
            for name in entries:
                self._scan_entry(result, name, zf.read(name))
        return result

    def _analyze_gzip(self, path: str) -> OTADiffResult:
        """GZIP 包只做格式识别，无条目级扫描对象。"""
        return OTADiffResult(ota_path=path, ota_format=OTAFormat.GZIP)

    def _analyze_bin(self, path: str) -> OTADiffResult:
        """裸二进制包：识别为 BIN，无条目级扫描对象。"""
        return OTADiffResult(ota_path=path, ota_format=OTAFormat.BIN)

    def _scan_entry(self, result: OTADiffResult, name: str, data: bytes) -> None:
        """按条目名与内容追加安全发现。"""
        name_l = name.lower()
        text = ""
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        if name_l.endswith(".sh") and any(p in text for p in _SUSPICIOUS_PATTERNS):
            result.issues.append(OTAIssue(
                type="suspicious_script",
                description="可疑脚本特征: %s" % name,
                risk=RiskLevel.HIGH,
            ))

        if name_l.startswith("bin/") or any(
                d in name_l for d in _DANGEROUS_BINARIES):
            result.issues.append(OTAIssue(
                type="dangerous_binary",
                description="危险二进制文件: %s" % name,
                risk=RiskLevel.HIGH,
            ))

        if any(c in name_l for c in _CONFIG_PATHS):
            result.issues.append(OTAIssue(
                type="config_change",
                description="敏感配置变更: %s" % name,
                risk=RiskLevel.MEDIUM,
            ))

        if "backdoor" in name_l or "backdoor" in text.lower():
            result.issues.append(OTAIssue(
                type="backdoor_suspicion",
                description="后门特征: %s" % name,
                risk=RiskLevel.HIGH,
            ))

    # -- 报告 -------------------------------------------------------------

    def generate_report(self) -> str:
        """生成中文文本报告；标题为固定值。"""
        result = self._last_result or self.analyze()
        lines = ["OTA差分更新分析报告"]
        if not result.analysis_success:
            lines.append("状态: 失败 - %s" % result.error_message)
            return "\n".join(lines)
        lines.append("路径: %s" % result.ota_path)
        lines.append("格式: %s" % (result.ota_format.value if result.ota_format else "unknown"))
        lines.append("条目数: %d" % len(result.extracted_files))
        for issue in result.issues:
            lines.append("- [%s] %s" % (issue.type, issue.description))
        return "\n".join(lines)
