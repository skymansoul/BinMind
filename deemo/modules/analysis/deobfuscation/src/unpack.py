# 2026-07-28
# Binary 脱壳 加壳器 detection
"""Detection 脱壳 common 可执行文件 加壳器s PyInstaller archives"""

import os
import struct
import logging
import subprocess
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 脱壳器


class Unpacker:
    """检测 脱壳 common 可执行文件 加壳器s (UPX, ASPack, MPRESS, etc.)"""

    # 加壳器 section names
    PACKER_SECTIONS: List[str] = [
        ".UPX0", ".UPX1", ".UPX2",
        ".aspack", ".ASPack",
        ".MPRESS1", ".MPRESS2",
        ".pec", ".pec1", ".pec2",
        ".petite",
        ".tls",
        ".enigma1", ".enigma2",
        ".vmp0", ".vmp1", ".vmp2",
        ".themida",
        ".winlice",
    ]

    # 加壳器 byte-level 签名s
    PACKER_SIGNATURES: Dict[str, List[bytes]] = {
        "UPX": [b"UPX0", b"UPX1", b"UPX!"],
        "ASPack": [b".aspack", b"ASPack"],
        "MPRESS": [b"MPRESS", b"MPRESS1"],
        "FSG": [b"FSG!"],
        "PECompact": [b"PEC2", b"PE\x00C", b"PEC2MO"],
        "Petite": [b"petite", b"PEPetite"],
    }

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def detect_by_sections(self, filepath: str) -> List[Dict[str, Any]]:
        """检测 加壳器 基于 PE section names
        
        Args:
        filepath: Path 可执行文件 file
        
        返回:
        List detection results 加壳器 name confidence
        """
        matches: List[Dict[str, Any]] = []
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._logger.error("Failed to read file %s: %s", filepath, exc)
            return matches

        # Search for section name strings binary
        content = data.decode("ascii", errors="ignore")
        content_lower = content.lower()

        for section in self.PACKER_SECTIONS:
            if section.lower() in content_lower:
                # Map section name 加壳器 name
                packer_name = section.lstrip(".").rstrip("0123456789")
                matches.append({
                    "packer": packer_name,
                    "method": "section_name",
                    "evidence": section,
                    "confidence": 0.70,
                })

        return matches

    def detect_by_entropy(self, filepath: str) -> List[Dict[str, Any]]:
        """检测 packing high-entropy sections
        
        High entropy (>7.0 bits) a strong indicator packed/encrypted data
        
        Args:
        filepath: Path 可执行文件 file
        
        返回:
        List high-entropy findings
        """
        matches: List[Dict[str, Any]] = []
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._logger.error("Failed to read %s: %s", filepath, exc)
            return matches

        file_size = len(data)
        if file_size == 0:
            return matches

        # 计算 entropy 4KB windows
        import math
        from collections import Counter

        window_size = 4096
        high_entropy_windows = 0
        total_windows = 0
        entropy_values: List[float] = []

        for offset in range(0, file_size, window_size):
            chunk = data[offset : offset + window_size]
            if len(chunk) < 256:  # Skip very small tail chunks
                continue
            total_windows += 1

            counter: Dict[int, int] = Counter(chunk)
            n = len(chunk)
            entropy = -sum(
                (c / n) * math.log2(c / n) for c in counter.values() if c > 0
            )
            entropy_values.append(entropy)

            if entropy > 7.0:
                high_entropy_windows += 1

        if total_windows == 0:
            return matches

        avg_entropy = sum(entropy_values) / len(entropy_values)
        high_ratio = high_entropy_windows / total_windows

        if avg_entropy > 7.0 or high_ratio > 0.3:
            matches.append({
                "packer": "Unknown",
                "method": "entropy",
                "evidence": f"avg_entropy={avg_entropy:.2f}, high_ratio={high_ratio:.2f}",
                "confidence": min(avg_entropy / 8.0, 0.85),
            })

        return matches

    def detect_by_signatures(self, filepath: str) -> List[Dict[str, Any]]:
        """检测 加壳器 byte 签名s
        
        Args:
        filepath: Path 可执行文件 file
        
        返回:
        List 签名 匹配
        """
        matches: List[Dict[str, Any]] = []
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._logger.error("Failed to read %s: %s", filepath, exc)
            return matches

        for packer_name, signatures in self.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data:
                    matches.append({
                        "packer": packer_name,
                        "method": "signature",
                        "evidence": sig.hex(),
                        "confidence": 0.85,
                    })
                    break  # One match per 加壳器 enough

        return matches

    def detect_packer(self, filepath: str) -> List[Dict[str, Any]]:
        """运行 detection methods 返回 combined results
        
        Args:
        filepath: Path 可执行文件 file
        
        返回:
        Combined list detections methods
        """
        results: List[Dict[str, Any]] = []
        results.extend(self.detect_by_sections(filepath))
        results.extend(self.detect_by_entropy(filepath))
        results.extend(self.detect_by_signatures(filepath))
        return results

    def unpack_upx(self, filepath: str, output_dir: str) -> bool:
        """Attempt UPX 脱壳 using external upx tool
        
        Args:
        filepath: Path UPX-packed file
        output_dir: Directory for 脱壳ed 输出
        
        返回:
        True 脱壳 succeeded
        """
        output_path = os.path.join(
            output_dir,
            os.path.basename(filepath).replace(".exe", "_unpacked.exe"),
        )

        try:
            import shutil
            shutil.copy2(filepath, output_path)
            result = subprocess.run(
                ["upx", "-d", output_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                self._logger.info("UPX unpacking succeeded: %s", output_path)
                return True
            else:
                self._logger.warning(
                    "UPX unpacking failed: %s", result.stderr.strip()
                )
                # Clean up failed attempt
                if os.path.exists(output_path):
                    os.remove(output_path)
                return False
        except FileNotFoundError:
            self._logger.warning("upx binary not found on PATH")
            return False
        except subprocess.TimeoutExpired:
            self._logger.error("UPX unpacking timed out")
            return False
        except Exception as exc:
            self._logger.error("UPX unpacking error: %s", exc)
            return False

    def unpack(self, filepath: str, output_dir: str) -> Dict[str, Any]:
        """Full detection 脱壳 流水线
        
        Args:
        filepath: Path 可执行文件 file
        output_dir: Directory for 脱壳ed 输出
        
        返回:
        Dict detection results 脱壳 status
        """
        os.makedirs(output_dir, exist_ok=True)

        results = self.detect_packer(filepath)

        best_match: Optional[Dict[str, Any]] = None
        best_conf = 0.0
        for r in results:
            if r["confidence"] > best_conf:
                best_conf = r["confidence"]
                best_match = r

        packer_name = best_match["packer"] if best_match else "Unknown"

        unpacked = False
        output_path = ""

        if packer_name == "UPX":
            unpacked = self.unpack_upx(filepath, output_dir)
            output_path = os.path.join(output_dir, os.path.basename(filepath))

        return {
            "packer": packer_name,
            "confidence": best_conf,
            "detections": results,
            "unpacked": unpacked,
            "output": output_path if unpacked else "",
        }


# PyInstaller脱壳器

# PyInstaller magic numbers - 只处理最新的版本
_PYINSTALLER_MAGIC = b"MEI\x0C\x0D\x0A\x0A\x0D\x0A\x0A"
_PYINSTALLER_MAGIC_ALT = b"MEI\x0B\x0D\x0A\x0A\x0D\x0A\x0A"


class PyInstallerUnpacker:
    """提取 decompile PyInstaller-packaged Python applications"""

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def parse_carchive_header(self, data: bytes) -> Dict[str, Any]:
        """解析 PyInstaller CArchive header
        
        Args:
        data: Raw bytes PyInstaller 可执行文件
        
        返回:
        Dict header fields: magic, cookie_size, toc_offset, toc_length, python_version
        
        Raises:
        ValueError: file doesn't appear a PyInstaller archive
        """
        # 查找 magic bytes
        magic = _PYINSTALLER_MAGIC
        magic_offset = data.find(magic)
        if magic_offset == -1:
            magic = _PYINSTALLER_MAGIC_ALT
            magic_offset = data.find(magic)
            if magic_offset == -1:
                raise ValueError(
                    "Not a valid PyInstaller archive: magic bytes not found"
                )

        header_start = magic_offset + len(magic)

        # CArchive header: cookie_size(4), TOC_length(4), TOC_offset(4), pyver(4)
        try:
            # struct 脱壳 fail truncated data
            header_fields = struct.unpack_from(  # type: ignore[unused-variable]
                "<IIII", data, header_start
            )
            cookie_size, toc_length, toc_offset, py_ver_raw = header_fields
        except struct.error as exc:
            raise ValueError(f"Failed to parse CArchive header: {exc}") from exc

        python_ver = f"{py_ver_raw // 100}.{py_ver_raw % 100}"

        return {
            "magic_offset": magic_offset,
            "cookie_size": cookie_size,
            "toc_offset": toc_offset,
            "toc_length": toc_length,
            "python_version": python_ver,
        }

    def extract_toc(
        self, data: bytes, header: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """提取 Table Contents a PyInstaller archive
        
        Args:
        data: Raw bytes archive
        header: Parsed CArchive header
        
        返回:
        List TOC entries metadata
        """
        toc_offset = header["toc_offset"]  # type: ignore[arg-type]
        toc_length = header["toc_length"]  # type: ignore[arg-type]

        if toc_offset + toc_length > len(data):
            self._logger.warning("TOC exceeds file bounds, truncating")
            toc_length = max(0, len(data) - toc_offset)

        toc_entries: List[Dict[str, Any]] = []
        pos = toc_offset

        # TOC entry a variable-length string-based structure
        # 格式化: entry_size(4) + entry_offset(4) + entry_data_size(4) +
        #         entry_type(b'z'|b's'|b'm'|b'x') + name_len(4) + name
        entry_count = 0
        while pos < toc_offset + toc_length and entry_count < 10000:
            try:
                if pos + 16 > len(data):
                    break

                entry_size_raw = struct.unpack_from("<I", data, pos)[0]
                entry_offset = struct.unpack_from("<I", data, pos + 4)[0]
                entry_data_size = struct.unpack_from("<I", data, pos + 8)[0]
                entry_type_byte = data[pos + 12]  # type: ignore[assignment]

                entry_type_map = {
                    ord(b"z"): "python_module",
                    ord(b"s"): "python_source",
                    ord(b"m"): "data_file",
                    ord(b"x"): "extra_data",
                    ord(b"b"): "binary",
                    ord(b"Z"): "runtime_option",
                }
                entry_type = entry_type_map.get(entry_type_byte, "unknown")
            except struct.error:
                break

            pos += 16
            if pos + 4 > len(data):
                break

            try:
                name_len = struct.unpack_from("<I", data, pos)[0]
            except struct.error:
                break

            pos += 4
            if pos + name_len > len(data):
                break

            name = data[pos : pos + name_len].decode("utf-8", errors="replace")
            pos += name_len

            toc_entries.append({
                "name": name,
                "type": entry_type,
                "offset": entry_offset,
                "size": entry_data_size,
                "entry_size": entry_size_raw,
            })
            entry_count += 1

        return toc_entries

    def extract_pyc_files(
        self,
        data: bytes,
        toc: List[Dict[str, Any]],
        output_dir: str,
    ) -> List[str]:
        """提取.pyc files resources archive
        
        Args:
        data: Raw archive bytes
        toc: Table contents entries
        output_dir: Directory 写入 extracted files
        
        返回:
        List extracted file paths
        """
        os.makedirs(output_dir, exist_ok=True)
        extracted: List[str] = []

        for entry in toc:
            name = entry["name"]
            offset = entry["offset"]
            size = entry["size"]

            safe_name = name.replace("/", os.sep).replace("\\", os.sep)
            # Prevent path traversal
            if safe_name.startswith(os.sep) or ".." in safe_name:
                self._logger.warning("Skipping suspicious path: %s", name)
                continue

            out_path = os.path.join(output_dir, safe_name)
            out_dir = os.path.dirname(out_path)
            os.makedirs(out_dir, exist_ok=True)

            try:
                end_pos = min(offset + size, len(data))
                content = data[offset:end_pos]
                with open(out_path, "wb") as fh:
                    fh.write(content)
                extracted.append(out_path)
            except OSError as exc:
                self._logger.error("Failed to extract %s: %s", name, exc)

        return extracted

    def unpack(self, filepath: str, output_dir: str) -> Dict[str, Any]:
        """Full PyInstaller 脱壳 流水线
        
        Args:
        filepath: Path PyInstaller 可执行文件
        output_dir: Directory for extracted files
        
        返回:
        Dict header info list extracted files
        """
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise ValueError(f"Failed to read file: {exc}") from exc

        try:
            header = self.parse_carchive_header(data)
        except ValueError as exc:
            self._logger.error("Not a PyInstaller archive: %s", exc)
            return {"error": str(exc), "header": None, "files": []}

        toc = self.extract_toc(data, header)
        files = self.extract_pyc_files(data, toc, output_dir)

        return {
            "header": header,
            "toc_entries": len(toc),
            "files": files,
            "file_count": len(files),
        }
