import typing
name: str = ""
address: int = 0
import logging
import os
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class TLSCallback:
    address
    name
    type
    is_malicious = False
    suspicious_score = 0.0

@dataclass
class DetectionResult:
    success
    callbacks

    suspicious_count = 0

class TLSCallbackDetector:
    """解析 PE TLS 目录表与 ELF .init_array/.preinit_array，定位早期执行回调。"""

    SUSPICIOUS_APIS = [
        "CreateThread", "VirtualAlloc", "WriteProcessMemory",
        "WinExec", "ShellExecute", "URLDownloadToFile",
        "socket", "connect", "send", "recv",
        "RegOpenKey", "RegSetValue", "crypt", "decrypt",
    ]

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.callbacks: List[TLSCallback] = []
        self._binary_data: bytes = b""
        self._is_pe: bool = False
        self._is_elf: bool = False

    def _load_binary(self):
        try:
            with open(self.binary_path, "rb") as f:
                self._binary_data = f.read()
            if self._binary_data[:2] == b'MZ':
                self._is_pe = True
            elif self._binary_data[:4] == b'\x7fELF':
                self._is_elf = True
        except Exception:
            logger.debug("suppressed", exc_info=True)

    def _detect_pe_tls(self):
        """遍历 PE 可选头，定位 TLS 目录 RVA 并提取回调地址。"""
        if not self._is_pe:
            return
        try:
            import struct as _st
            # PE 签名字段位于偏移 0x3C
            if len(self._binary_data) < 64:
                return
            pe_offset = _st.unpack_from("<I", self._binary_data, 0x3C)[0]
            # 可选头紧随 COFF 头（24 字节）
            opt_header = pe_offset + 24
            magic = _st.unpack_from("<H", self._binary_data, opt_header)[0]
            is_pe32 = (magic == 0x10b)
            tls_dir_rva = 0
            if is_pe32:
                tls_dir_rva = _st.unpack_from(
                    "<I", self._binary_data, opt_header + 96 + 4 * 9
                )[0]
                tls_dir_size = _st.unpack_from(
                    "<I", self._binary_data, opt_header + 96 + 4 * 9 + 4
                )[0]
            else:
                tls_dir_rva = _st.unpack_from(
                    "<I", self._binary_data, opt_header + 112 + 4 * 9
                )[0]
                tls_dir_size = _st.unpack_from(
                    "<I", self._binary_data, opt_header + 112 + 4 * 9 + 4
                )[0]

            if tls_dir_rva > 0 and tls_dir_size > 0:
                # IMAGE_TLS_DIRECTORY 中 AddressOfCallbacks 偏移：PE32 = +12, PE32+ = +24
                tls_cb_offset = 12 if is_pe32 else 24
                self.callbacks.append(TLSCallback(
                    address=tls_dir_rva,
                    name="PE_TLS_Callbacks",
                    type="PE_TLS",
                    is_malicious=False,
                    suspicious_score=0.0,
                ))
                logger.info(f"定位到 PE TLS 目录: RVA=0x{tls_dir_rva:x}")
        except Exception as e:
            logger.debug(f"PE TLS 解析失败: {e}")

    def _detect_elf_init_array(self):
        """调用 readelf 枚举 .init_array、.preinit_array、.ctors 段。"""
        if not self._is_elf:
            return
        try:
            r = subprocess.run(
                ['readelf', '-S', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            for section_name in ['.init_array', '.preinit_array', '.ctors',
                                  '.fini_array', '.dtors']:
                if section_name in r.stdout:
                    self.callbacks.append(TLSCallback(
                        address=0,
                        name=section_name,
                        type=f"ELF_{section_name.strip('.')}",
                        is_malicious=False,
                        suspicious_score=0.0,
                    ))
                    logger.info(f"发现 ELF 段: {section_name}")
        except Exception as e:
            logger.debug(f"ELF 段解析失败: {e}")

    def detect_callbacks(self) -> List[TLSCallback]:
        """扫描二进制中所有初始化/终止回调注册点。"""
        logger.info("正在扫描 TLS/初始化回调...")
        self._load_binary()

        # PE TLS 目录
        self._detect_pe_tls()

        # ELF 初始化/终止数组
        self._detect_elf_init_array()

        # 兜底：通过 readelf 程序头检测 TLS 段
        try:
            r = subprocess.run(
                ['readelf', '-l', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            if 'TLS' in r.stdout:
                if not any(c.type == 'initialization' for c in self.callbacks):
                    self.callbacks.append(TLSCallback(
                        address=0, name='TLS_INIT', type='initialization'
                    ))
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return self.callbacks

    def analyze_callbacks(self):
        """对每个回调的反汇编代码进行可疑 API 评分。"""
        for cb in self.callbacks:
            cb.suspicious_score = self._analyze_callback(cb)
            if cb.suspicious_score > 0.5:
                cb.is_malicious = True

    def _analyze_callback(self, cb: TLSCallback) -> float:
        """通过 r2 反汇编回调地址；对 SUSPICIOUS_APIS 命中逐项累加分数。"""
        score = 0.0
        try:
            # r2 反汇编回调地址处 64 字节
            if cb.address > 0:
                r = subprocess.run(
                    ['r2', '-q', '-c',
                     f'pD 64 @ {cb.address}; q', self.binary_path],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='replace'
                )
                disasm = r.stdout.lower()
                # r2 pD 输出格式因版本而异；64 字节可能截断长指令，对评分影响有限
                for api in self.SUSPICIOUS_APIS:
                    if api.lower() in disasm:
                        score += 0.2
        except Exception:
            logger.debug("suppressed", exc_info=True)

        # 早期执行入口点本身即具备一定风险
        if cb.type in ('PE_TLS', 'ELF_init_array'):
            score += 0.1

        return min(1.0, score)

    def run(self) -> DetectionResult:
        """完整检测流水线：定位回调、逐一分析、汇总结果。"""
        self.detect_callbacks()
        self.analyze_callbacks()
        suspicious = sum(1 for c in self.callbacks if c.is_malicious)
        high_score = sum(
            1 for c in self.callbacks if c.suspicious_score > 0.5
        )
        logger.info(
            f"TLS 检测完成: {len(self.callbacks)} 个回调, "
            f"{suspicious} 个恶意, {high_score} 个高可疑度"
        )
        return DetectionResult(
            success=True,
            callbacks=self.callbacks,
            suspicious_count=suspicious
        )

def create_tls_detector(binary_path: str) -> TLSCallbackDetector:
    """工厂函数：为指定二进制构造 TLSCallbackDetector 实例。"""
    return TLSCallbackDetector(binary_path)
