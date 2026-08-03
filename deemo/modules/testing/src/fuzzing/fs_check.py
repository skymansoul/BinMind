"""固件文件系统检查器——解析 + 完整性校验 + 提取——支持 SquashFS/CramFS/JFFS2/ext 等"""
import os
import re
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from enum import Enum, auto

logger = logging.getLogger(__name__)


class FsType(Enum):
    SQUASHFS = auto()
    CRAMFS = auto()
    JFFS2 = auto()
    YAFFS2 = auto()
    UBIFS = auto()
    EXT2 = auto()
    EXT3 = auto()
    EXT4 = auto()
    ROMFS = auto()
    UNKNOWN = auto()


_FS_MAGICS = {
    b"hsqs": FsType.SQUASHFS,
    b"sqsh": FsType.SQUASHFS,
    b"\x28\xcd\x3d\x45": FsType.CRAMFS,
    b"\xe0\x01": FsType.JFFS2,
    b"\x03\x00\x00\x00": FsType.YAFFS2,
    b"\x31\x18\x10\x06": FsType.UBIFS,
    b"\x53\xef": FsType.EXT2,
    b"-rom1fs-": FsType.ROMFS,
}

EXT_MAGIC_OFFSET = 0x438  # ext 超块魔数偏移


@dataclass
class FsCheckResult:
    fs_type: FsType = FsType.UNKNOWN
    fs_label: str = ""
    integrity_ok: bool = False
    file_count: int = 0
    total_size: int = 0
    issues: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def analyze_fs_image(image_path: str) -> FsCheckResult:
    """文件系统镜像分析——魔数识别 + 类型判定"""
    _result = FsCheckResult()

    try:
        with open(image_path, "rb") as _f:
            _header = _f.read(4096)
        _result.total_size = os.path.getsize(image_path)
    except OSError as _e:
        _result.issues.append(f"Cannot read image: {_e}")
        return _result

    _result.fs_type = _detect_fs_type(_header, image_path)
    _result.fs_label = _result.fs_type.name

    if _result.fs_type == FsType.UNKNOWN:
        _result.issues.append("无法识别的文件系统类型")
        return _result

    return _result


def _detect_fs_type(header: bytes, path: str) -> FsType:
    """魔数字节匹配文件系统类型"""
    for _magic, _fs_type in _FS_MAGICS.items():
        if header[:len(_magic)] == _magic:
            return _fs_type

    if len(header) > EXT_MAGIC_OFFSET + 2:
        _ext_magic = header[EXT_MAGIC_OFFSET:EXT_MAGIC_OFFSET + 2]
        if _ext_magic == b"\x53\xef":
            _features = header[EXT_MAGIC_OFFSET + 92:EXT_MAGIC_OFFSET + 96]
            if _features:
                _feat = int.from_bytes(_features, 'little')
                if _feat & 0x0004:
                    return FsType.EXT4 if _feat & 0x0200 else FsType.EXT3
                return FsType.EXT2

    return FsType.UNKNOWN


def check_integrity(image_path: str) -> Dict[str, Any]:
    """文件系统镜像完整性校验——尺寸检查 + SHA-256 哈希"""
    _result = {"valid": True, "checks": []}

    if not os.path.isfile(image_path):
        _result["valid"] = False
        _result["checks"].append("文件不存在")
        return _result

    _size = os.path.getsize(image_path)
    _result["size"] = _size

    if _size == 0:
        _result["valid"] = False
        _result["checks"].append("镜像为空")
    elif _size < 512:
        _result["checks"].append("镜像异常小 (< 512 字节)")

    _sha = hashlib.sha256()
    try:
        with open(image_path, "rb") as _f:
            while True:
                _chunk = _f.read(65536)
                if not _chunk:
                    break
                _sha.update(_chunk)
    except OSError:
        _result["valid"] = False
        _result["checks"].append("校验和计算时读错误")

    _result["sha256"] = _sha.hexdigest()
    _result["checks"].append("完整性校验通过" if _result["valid"] else "完整性校验失败")
    return _result


def extract_files(image_path: str, output_dir: str) -> List[str]:
    """从固件文件系统提取文件——按类型调用对应工具"""
    _extracted = []
    os.makedirs(output_dir, exist_ok=True)

    _result = analyze_fs_image(image_path)

    if _result.fs_type == FsType.SQUASHFS:
        _extracted = _extract_squashfs(image_path, output_dir)
    elif _result.fs_type == FsType.CRAMFS:
        _extracted = _extract_cramfs(image_path, output_dir)
    elif _result.fs_type in (FsType.EXT2, FsType.EXT3, FsType.EXT4):
        _extracted = _extract_ext(image_path, output_dir)
    else:
        _extracted = _generic_extract(image_path, output_dir)

    return _extracted


def _extract_squashfs(path: str, out: str) -> List[str]:
    import subprocess
    try:
        subprocess.run(["unsquashfs", "-d", out, path], check=True,
                       capture_output=True, timeout=120)
        return _collect_files(out)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _extract_cramfs(path: str, out: str) -> List[str]:
    import subprocess
    try:
        subprocess.run(["cramfsck", "-x", out, path], check=True,
                       capture_output=True, timeout=60)
        return _collect_files(out)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _extract_ext(path: str, out: str) -> List[str]:
    import subprocess
    try:
        _mp = os.path.join(out, "mnt")
        os.makedirs(_mp, exist_ok=True)
        subprocess.run(["sudo", "mount", "-o", "loop,ro", path, _mp], check=True)
        return _collect_files(_mp)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _generic_extract(path: str, out: str) -> List[str]:
    _out_file = os.path.join(out, os.path.basename(path) + ".raw")
    import shutil
    shutil.copy2(path, _out_file)
    return [_out_file]


def _collect_files(directory: str) -> List[str]:
    _files = []
    for _root, _dirs, _fnames in os.walk(directory):
        for _fn in _fnames:
            _files.append(os.path.join(_root, _fn))
    return _files


class FirmwareFileSystemIntegrityChecker:
    """固件安全基线审计——SUID/SGID/world-writable/硬编码凭据/已知 CVE 哈希检测"""

    def __init__(self):
        self.security_baseline: Dict[str, Any] = {}
        self.violations: List[Dict[str, Any]] = []
        self._known_bad_hashes: Dict[str, List[str]] = {}
        self._define_security_baseline()

    def _define_security_baseline(self):
        """安全基线规则定义"""
        self.security_baseline = {
            'no_suid_binaries': True,
            'no_sgid_binaries': True,
            'no_world_writable_files': True,
            'no_empty_passwords': True,
            'no_hardcoded_credentials': True,
            'required_permissions': {
                '/etc/passwd': '0644',
                '/etc/shadow': '0600',
                '/bin': '0755'
            }
        }

    def load_known_vulnerable_hashes(self, hash_to_cve: Dict[str, List[str]]) -> None:
        """加载已知漏洞二进制哈希 -> CVE 映射"""
        self._known_bad_hashes.update(hash_to_cve)

    def _check_known_vulnerable(self, filepath: str) -> Optional[List[str]]:
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            digest = h.hexdigest()
            return self._known_bad_hashes.get(digest)
        except Exception:
            return None

    def check_suid_binaries(self, filesystem_path: str) -> List[Dict[str, Any]]:
        """SUID/SGID 二进制检测——含已知 CVE 匹配"""
        suid_files = []

        try:
            for root, dirs, files in os.walk(filesystem_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        mode = stat_info.st_mode

                        if mode & 0o4000:
                            entry = {
                                'path': file_path,
                                'mode': oct(mode)[-4:],
                                'violation': 'SUID 二进制发现'
                            }
                            cves = self._check_known_vulnerable(file_path)
                            if cves:
                                entry['known_cves'] = cves
                                entry['risk'] = 'critical'
                            suid_files.append(entry)

                        if mode & 0o2000:
                            entry = {
                                'path': file_path,
                                'mode': oct(mode)[-4:],
                                'violation': 'SGID 二进制发现'
                            }
                            cves = self._check_known_vulnerable(file_path)
                            if cves:
                                entry['known_cves'] = cves
                            suid_files.append(entry)

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        except Exception as e:
            logger.warning(f"SUID 检查失败: {e}")

        self.violations.extend(suid_files)
        return suid_files

    def check_world_writable_files(self, filesystem_path: str) -> List[Dict[str, Any]]:
        """全局可写文件检测"""
        writable_files = []

        try:
            for root, dirs, files in os.walk(filesystem_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        mode = stat_info.st_mode

                        if mode & 0o0002:
                            writable_files.append({
                                'path': file_path,
                                'mode': oct(mode)[-4:],
                                'violation': '全局可写文件'
                            })

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        except Exception as e:
            logger.warning(f"全局可写文件检查失败: {e}")

        self.violations.extend(writable_files)
        return writable_files

    def check_hardcoded_credentials(self, filesystem_path: str) -> List[Dict[str, Any]]:
        """硬编码凭据扫描——正则匹配 password/secret/api_key/token 赋值"""
        credential_files = []

        credential_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']'
        ]

        try:
            for root, dirs, files in os.walk(filesystem_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                            for pattern in credential_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    credential_files.append({
                                        'path': file_path,
                                        'violation': '硬编码凭据'
                                    })
                                    break

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        except Exception as e:
            logger.warning(f"凭据检查失败: {e}")

        self.violations.extend(credential_files)
        return credential_files

    def run_full_integrity_check(self, filesystem_path: str) -> Dict[str, Any]:
        """全量完整性检查"""
        result = {
            'filesystem_path': filesystem_path,
            'suid_binaries': self.check_suid_binaries(filesystem_path),
            'world_writable': self.check_world_writable_files(filesystem_path),
            'hardcoded_credentials': self.check_hardcoded_credentials(filesystem_path),
            'compliant': True,
            'violations_count': 0
        }

        result['violations_count'] = len(self.violations)
        result['compliant'] = result['violations_count'] == 0

        return result

    def generate_integrity_report(self) -> str:
        """完整性审计报告"""
        report = '# 固件文件系统完整性报告\n\n'

        report += '## 安全基线检查\n'

        violations_by_type = defaultdict(list)
        for violation in self.violations:
            violations_by_type[violation['violation']].append(violation['path'])

        for violation_type, paths in violations_by_type.items():
            report += f'- {violation_type}: {len(paths)} 处违规\n'

        if self.violations:
            report += '\n## 违规详情\n'
            for violation in self.violations:
                report += f'- {violation["path"]}: {violation["violation"]}\n'
                if 'known_cves' in violation:
                    report += f'  [!!] 已知 CVE: {", ".join(violation["known_cves"])}\n'

        return report
