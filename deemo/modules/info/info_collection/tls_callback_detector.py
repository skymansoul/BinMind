"""TLS 回调检测 — PE TLS 目录表 + ELF .init_array/.preinit_array 解析。"""
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

@dataclass
class TLSCallback:
    address: int = 0
    name: str = ""
    type: str = ""
    is_malicious: bool = False
    suspicious_score: float = 0.0
    # 新增：反汇编摘要 — 保留前几条指令的助记符序列供人工审查
    disasm_preview: str = ""

@dataclass
class DetectionResult:
    success: bool = False
    callbacks: List[TLSCallback] = field(default_factory=list)
    suspicious_count: int = 0

class TLSCallbackDetector:
    """解析 PE TLS 目录表与 ELF .init_array/.preinit_array，定位早期执行回调。

    增强：
    - PE32/PE32+ 双模式 TLS 回调地址数组解析（不只是目录 RVA，而是遍历
      AddressOfCallbacks 指向的指针数组以获取每个回调地址）。
    - ELF 段解析增加 .fini_array 和 .dtors 覆盖。
    - 反汇编分析增加指令序列模式匹配（非仅 API 名称匹配）。
    """

    SUSPICIOUS_APIS = [
        "CreateThread", "VirtualAlloc", "WriteProcessMemory",
        "WinExec", "ShellExecute", "URLDownloadToFile",
        "socket", "connect", "send", "recv",
        "RegOpenKey", "RegSetValue", "crypt", "decrypt",
    ]

    # 可疑指令序列模式：在 TLS 回调中出现这些指令序列极为可疑
    _SUSPICIOUS_INSTR_SEQ = [
        (r'(?:push|mov).*0x[0-9a-fA-F]{6,}', 0.15),    # 操作大立即数
        (r'(?:call|jmp)\s+\[', 0.2),                     # 间接调用/跳转
        (r'(?:int\s+0x2[de]|syscall|sysenter)', 0.3),    # 系统调用
        (r'(?:pushad|pushfd|popad|popfd)', 0.1),           # 状态保存/恢复
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

    def _rva_to_offset(self, rva: int) -> int:
        """将 PE RVA 转换为文件偏移。遍历节区表找到包含该 RVA 的节。

        无匹配则返回 0。
        """
        if not self._is_pe or len(self._binary_data) < 64:
            return 0
        try:
            import struct as _st
            pe_off = _st.unpack_from("<I", self._binary_data, 0x3C)[0]
            num_sects = _st.unpack_from("<H", self._binary_data, pe_off + 6)[0]
            opt_hdr_size = _st.unpack_from("<H", self._binary_data, pe_off + 20)[0]
            sec_base = pe_off + 24 + opt_hdr_size
            for i in range(num_sects):
                s_off = sec_base + i * 40
                s_va = _st.unpack_from("<I", self._binary_data, s_off + 12)[0]
                s_vsize = _st.unpack_from("<I", self._binary_data, s_off + 8)[0]
                s_raw = _st.unpack_from("<I", self._binary_data, s_off + 20)[0]
                if s_va <= rva < s_va + s_vsize:
                    return rva - s_va + s_raw
        except Exception:
            pass
        return 0

    def _detect_pe_tls(self):
        """遍历 PE 可选头，定位 TLS 目录 RVA 并提取回调地址数组。"""
        if not self._is_pe:
            return
        try:
            import struct as _st
            if len(self._binary_data) < 64:
                return
            pe_offset = _st.unpack_from("<I", self._binary_data, 0x3C)[0]
            # 可选头紧随 COFF 头（24 字节）
            opt_header = pe_offset + 24
            magic = _st.unpack_from("<H", self._binary_data, opt_header)[0]
            is_pe32 = (magic == 0x10b)
            tls_dir_rva = 0
            tls_dir_size = 0
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
                tls_offset = self._rva_to_offset(tls_dir_rva)
                if tls_offset > 0:
                    cb_rva_offset = 12 if is_pe32 else 24
                    callbacks_rva = _st.unpack_from(
                        "<I", self._binary_data, tls_offset + cb_rva_offset
                    )[0]
                    # 遍历回调地址数组（以 NULL 结尾）
                    if callbacks_rva > 0:
                        cb_off = self._rva_to_offset(callbacks_rva)
                        if cb_off > 0:
                            idx = 0
                            while cb_off + 4 * (idx + 1) <= len(self._binary_data):
                                cb_addr = _st.unpack_from(
                                    "<I" if is_pe32 else "<Q",
                                    self._binary_data, cb_off + idx * (4 if is_pe32 else 8)
                                )[0]
                                if cb_addr == 0:
                                    break
                                self.callbacks.append(TLSCallback(
                                    address=cb_addr,
                                    name=f"PE_TLS_Callback_{idx}",
                                    type="PE_TLS",
                                ))
                                idx += 1
                                if idx > 32:  # 安全上限
                                    break
                        # 兜底：即使无法解析回调数组，也记录 TLS 目录本身
                        if not self.callbacks:
                            self.callbacks.append(TLSCallback(
                                address=tls_dir_rva,
                                name="PE_TLS_Directory",
                                type="PE_TLS",
                            ))
                else:
                    self.callbacks.append(TLSCallback(
                        address=tls_dir_rva,
                        name="PE_TLS_Callbacks",
                        type="PE_TLS",
                    ))
                logger.info(f"定位到 PE TLS 目录: RVA=0x{tls_dir_rva:x}, "
                           f"共 {len(self.callbacks)} 个回调")
        except Exception as e:
            logger.debug(f"PE TLS 解析失败: {e}")

    def _detect_elf_init_array(self):
        """调用 readelf 枚举 .init_array、.preinit_array、.ctors、.fini_array、.dtors 段。"""
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
        """对每个回调的反汇编代码进行可疑 API + 指令序列评分。"""
        for cb in self.callbacks:
            cb.suspicious_score = self._analyze_callback(cb)
            if cb.suspicious_score > 0.5:
                cb.is_malicious = True

    def _analyze_callback(self, cb: TLSCallback) -> float:
        """通过 r2 反汇编回调地址；对 SUSPICIOUS_APIS 及指令模式双路径评分。"""
        score = 0.0
        try:
            if cb.address > 0:
                r = subprocess.run(
                    ['r2', '-q', '-c',
                     f'pD 96 @ {cb.address}; q', self.binary_path],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='replace'
                )
                disasm = r.stdout
                disasm_lower = disasm.lower()

                # 保存反汇编预览（取前 3 行非空行）
                preview_lines = [ln for ln in disasm.split('\n') if ln.strip()][:3]
                cb.disasm_preview = '; '.join(preview_lines) if preview_lines else ""

                # 路径一：API 名称匹配
                for api in self.SUSPICIOUS_APIS:
                    if api.lower() in disasm_lower:
                        score += 0.2

                # 路径二：指令序列模式匹配
                for pattern, weight in self._SUSPICIOUS_INSTR_SEQ:
                    if re.search(pattern, disasm, re.IGNORECASE):
                        score += weight

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
        # 回调执行顺序分析 — PE TLS 回调按地址升序执行
        pe_callbacks = [c for c in self.callbacks if c.type == 'PE_TLS']
        exec_order = sorted(pe_callbacks, key=lambda c: c.address)
        order_chains = [
            {'order': i, 'address': hex(c.address), 'score': c.suspicious_score,
             'name': c.name}
            for i, c in enumerate(exec_order)
        ]
        logger.info(
            f"TLS 检测完成: {len(self.callbacks)} 个回调, "
            f"{suspicious} 个恶意, {high_score} 个高可疑度, "
            f"PE 回调执行链: {len(order_chains)} 个"
        )
        result = DetectionResult(
            success=True,
            callbacks=self.callbacks,
            suspicious_count=suspicious
        )
        # runtime 属性 — 不加入 dataclass 字段声明，仅作为补充数据
        result.execution_order = order_chains  # type: ignore[attr-defined]
        return result


def create_tls_detector(binary_path: str) -> TLSCallbackDetector:
    """工厂函数：为指定二进制构造 TLSCallbackDetector 实例。"""
    return TLSCallbackDetector(binary_path)
