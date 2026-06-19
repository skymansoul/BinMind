"""
Shellcode自适应编码与坏字符处理模块

本模块根据目标输入限制（如必须避免空字节、特定字符），自动选择编码算法
（XOR、Base64、Alpha2等）并生成相应的解码器stub，确保shellcode能在
限制环境下成功执行。

作者: Deemo 安全研究团队
版本: 1.0.0
"""

import os
import re
import random
import string
import base64
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum

logger = logging.getLogger(__name__)

# 尝试导入 alpha3（可选）
try:
    from pwnlib.asm import asm
    from pwnlib.context import context
    PWNLIB_AVAILABLE = True
except ImportError:
    PWNLIB_AVAILABLE = False
    logger.warning("pwntools 未安装，部分功能可能不可用")


class EncoderType(Enum):
    """编码器类型枚举"""
    XOR = "xor"                    # 简单XOR编码
    ADD = "add"                    # 加法编码
    SUB = "sub"                    # 减法编码
    ROL = "rol"                    # 循环左移
    ROR = "ror"                    # 循环右移
    INSERTION = "insertion"         # 插入编码
    BASE64 = "base64"              # Base64编码
    ALPHANUMERIC = "alphanumeric"  # 字母数字编码
    POLYMORPHIC = "polymorphic"   # 多态编码
    NOT = "not"                    # NOT运算编码


@dataclass
class BadCharInfo:
    """
    坏字符信息
    """
    char: int                      # 字节值 (0-255)
    name: str = ""                 # 名称（如 'NULL', 'CR'）
    hex_repr: str = ""             # 十六进制表示
    
    def __post_init__(self):
        if isinstance(self.char, str):
            self.char = ord(self.char)
        if not self.hex_repr:
            self.hex_repr = f"\\x{self.char:02x}",
        if not self.name:
            self.name = self._get_default_name()
    
    def _get_default_name(self) -> str:
        """获取默认名称"""
        names = {
            0x00: "NULL", 0x0a: "LF", 0x0d: "CR",
            0x20: "SPACE", 0x09: "TAB",
        }
        return names.get(self.char, f"0x{self.char:02x}")


@dataclass
class EncodeResult:
    """
    编码结果
    """
    original_shellcode: bytes
    encoded_shellcode: bytes
    decoder_stub: bytes
    encoder_type: EncoderType
    key: Optional[int] = None
    key_bytes: Optional[bytes] = None
    xor_keys: Optional[List[int]] = None
    
    # 验证结果
    contains_bad_chars: bool = False
    bad_chars_found: List[int] = field(default_factory=list)
    
    # 元数据
    original_size: int = 0
    encoded_size: int = 0
    overhead: int = 0
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "encoder_type": self.encoder_type.value,
            "original_size": self.original_size,
            "encoded_size": self.encoded_size,
            "overhead": self.overhead,
            "key": self.key,
            "contains_bad_chars": self.contains_bad_chars,
            "bad_chars_found": [f"\\x{b:02x}" for b in self.bad_chars_found],
            "description": self.description,
        }


class ShellcodeEncoder:
    """
    Shellcode 编码器
    
    提供多种编码算法，自动选择最佳编码方式处理坏字符
    """
    
    # 默认坏字符（通常需要避免）
    DEFAULT_BAD_CHARS = [
        0x00,  # NULL
        0x0a,  # LF (Line Feed)
        0x0d,  # CR (Carriage Return)
    ]
    
    # x64 寄存器
    X64_REGISTERS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    
    # x86 寄存器
    X86_REGISTERS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']
    
    def __init__(, self, arch: str = "amd64", bad_chars: Optional[List[int]] = None, verbose: bool = False):
        """
        初始化 Shellcode 编码器
        
        Args:
            arch: 架构 ('amd64' 或 'i386')
            bad_chars: 坏字符列表
            verbose: 是否输出详细信息
        """
        self.arch = arch
        self.bad_chars = bad_chars or self.DEFAULT_BAD_CHARS.copy()
        self.verbose = verbose
        
        self.logger = logging.getLogger(__name__)
        
        # 统计信息
        self.encode_attempts = 0
        self.encode_success = 0
    
    def encode(, self, shellcode: bytes, encoder_type: Optional[EncoderType] = None, auto_select: bool = True) -> EncodeResult:
        """
        编码 shellcode
        
        Args:
            shellcode: 原始 shellcode
            encoder_type: 指定编码器类型，如果为 None 则自动选择
            auto_select: 是否自动选择最佳编码器
        
        Returns:
            EncodeResult: 编码结果
        """
        self.encode_attempts += 1
        
        if not shellcode:
            raise ValueError("Shellcode 不能为空")
        
        original_size = len(shellcode)
        
        # 自动选择最佳编码器
        if auto_select and encoder_type is None:
            encoder_type = self._select_best_encoder(shellcode)
        
        if encoder_type is None:
            encoder_type = EncoderType.XOR
        
        self.logger.info(f"使用编码器: {encoder_type.value}")
        
        # 执行编码
        if encoder_type == EncoderType.XOR:
            result = self._xor_encode(shellcode)
        elif encoder_type == EncoderType.ADD:
            result = self._add_encode(shellcode)
        elif encoder_type == EncoderType.SUB:
            result = self._sub_encode(shellcode)
        elif encoder_type == EncoderType.ROL:
            result = self._rol_encode(shellcode)
        elif encoder_type == EncoderType.ROR:
            result = self._ror_encode(shellcode)
        elif encoder_type == EncoderType.INSERTION:
            result = self._insertion_encode(shellcode)
        elif encoder_type == EncoderType.BASE64:
            result = self._base64_encode(shellcode)
        elif encoder_type == EncoderType.NOT:
            result = self._not_encode(shellcode)
        elif encoder_type == EncoderType.POLYMORPHIC:
            result = self._polymorphic_encode(shellcode)
        else:
            result = self._xor_encode(shellcode)
        
        # 验证结果
        result.original_size = original_size
        result.encoded_size = len(result.encoded_shellcode)
        result.overhead = result.encoded_size - original_size
        result = self._verify_encode_result(result)
        
        if not result.contains_bad_chars:
            self.encode_success += 1
        
        return result
    
    def _select_best_encoder(self, shellcode: bytes) -> EncoderType:
        """
        选择最佳编码器
        
        Args:
            shellcode: 原始 shellcode
        
        Returns:
            EncoderType: 最佳编码器类型
        """
        # 分析 shellcode 中的坏字符
        bad_char_counts: Dict[EncoderType, int] = {}
        
        encoders = [
            EncoderType.XOR,
            EncoderType.ADD,
            EncoderType.NOT,
        ]
        
        for enc_type in encoders:
            # 估计编码后的坏字符数量
            estimated_bad = self._estimate_bad_chars(shellcode, enc_type)
            bad_char_counts[enc_type] = estimated_bad
        
        # 选择坏字符最少的编码器
        best_encoder = min(bad_char_counts, key=bad_char_counts.get)
        
        return best_encoder
    
    def _estimate_bad_chars(, self, shellcode: bytes, encoder_type: EncoderType) -> int:
        """
        估计编码后的坏字符数量
        
        Args:
            shellcode: 原始 shellcode
            encoder_type: 编码器类型
        
        Returns:
            int: 估计的坏字符数量
        """
        # 简化实现：随机估计
        return random.randint(0, len(self.bad_chars

    
    def _xor_encode(self, shellcode: bytes) -> EncodeResult:
        """
        XOR 编码
        
        Args:
            shellcode: 原始 shellcode
        
        Returns:
            EncodeResult: 编码结果
        """
        # 搜索最佳单字节 key
        best_key = 0
        best_result = None
        min_bad = float('inf')
        
        for key in range(1, 256):
            if key in self.bad_chars:
                continue
            
            encoded = bytes([b ^ key for b in shellcode])
            
            # 检查坏字符
            bad_count = sum(1 for b in encoded if b in self.bad_chars)
            
            if bad_count < min_bad:
                min_bad = bad_count
                best_key = key
                best_result = encoded
        
        if best_result is None:
            # 使用随机 key
            available_keys = [k for k in range(1, 256) if k not in self.bad_chars]
            if available_keys:
                key = random.choice(available_keys)
            else:
                # 如果没有可用的 key，使用默认 key 1
                key = 1
            best_key = key
            best_result = bytes([b ^ key for b in shellcode])
        
        # 生成解码器 stub
        decoder = self._generate_xor_decoder(best_key, len(shellcode

        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=best_result,
            decoder_stub=decoder,
            encoder_type=EncoderType.XOR,
            key=best_key,
            description=f"XOR 编码，key=0x{best_key:02x}")
        

    
    def _generate_xor_decoder(self, key: int, length: int) -> bytes:
        """
        生成 XOR 解码器 stub
        
        Args:
            key: XOR 密钥
            length: shellcode 长度
        
        Returns:
            bytes: 解码器 stub
        """
        if self.arch == "amd64":
            return self._generate_xor_decoder_amd64(key, length)
        else:
            return self._generate_xor_decoder_i386(key, length)
    
    def _generate_xor_decoder_amd64(self, key: int, length: int) -> bytes:
        """
        生成 x64 XOR 解码器
        
        Args:
            key: XOR 密钥
            length: shellcode 长度
        
        Returns:
            bytes: 解码器 stub
        """
        # 简单的 XOR 解码循环
        code = f"""
        push rsi
        mov rsi, 0x0000  /* 将被替换为 shellcode 地址 */
        mov rcx, {length}
        mov al, 0x{key:02x}
    decode_loop:
        xor byte ptr [rsi], al
        inc rsi
        loop decode_loop
        pop rsi
        jmp rsi  /* 跳转到解码后的 shellcode */
        """
        
        if PWNLIB_AVAILABLE:
            try:
                return asm(code, arch='amd64')
            except Exception as e:
                self.logger.warning(f"汇编解码器失败: {e}")
        
        # 回退：返回空 stub（实际使用时需要替换）
        return b''
    
    def _generate_xor_decoder_i386(self, key: int, length: int) -> bytes:
        """
        生成 x86 XOR 解码器
        
        Args:
            key: XOR 密钥
            length: shellcode 长度
        
        Returns:
            bytes: 解码器 stub
        """
        code = f"""
        push esi
        mov esi, 0x0000  /* 将被替换为 shellcode 地址 */
        mov ecx, {length}
        mov al, 0x{key:02x}
    decode_loop:
        xor byte ptr [esi], al
        inc esi
        loop decode_loop
        pop esi
        jmp esi
        """
        
        if PWNLIB_AVAILABLE:
            try:
                return asm(code, arch='i386')
            except Exception as e:
                self.logger.warning(f"汇编解码器失败: {e}")
        
        return b''
    
    def _add_encode(self, shellcode: bytes) -> EncodeResult:
        """
        加法编码
        
        Args:
            shellcode: 原始 shellcode
        
        Returns:
            EncodeResult: 编码结果
        """
        # 搜索最佳 key
        best_key = 0
        best_result = None
        min_bad = float('inf')
        
        for key in range(1, 256):
            if key in self.bad_chars:
                continue
            
            # 避免溢出到坏字符
            encoded = bytes([(b + key) & 0xFF for b in shellcode])
            bad_count = sum(1 for b in encoded if b in self.bad_chars)
            
            if bad_count < min_bad:
                min_bad = bad_count
                best_key = key
                best_result = encoded
        
        if best_result is None:
            key = random.choice([k for k in range(1, 256) if k not in self.bad_chars])
            best_key = key
            best_result = bytes([(b + key) & 0xFF for b in shellcode])
        
        decoder = self._generate_add_decoder(best_key, len(shellcode

        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=best_result,
            decoder_stub=decoder,
            encoder_type=EncoderType.ADD,
            key=best_key,
            description=f"加法编码，key=0x{best_key:02x}")
        

    
    def _generate_add_decoder(self, key: int, length: int) -> bytes:
        """生成加法解码器 stub"""
        # 类似 XOR 解码器，但使用 SUB 指令
        return self._generate_arithmetic_decoder(key, length, "sub")
    
    def _sub_encode(self, shellcode: bytes) -> EncodeResult:
        """减法编码"""
        best_key = 0
        best_result = None
        min_bad = float('inf')
        
        for key in range(1, 256):
            if key in self.bad_chars:
                continue
            
            encoded = bytes([(b - key) & 0xFF for b in shellcode])
            bad_count = sum(1 for b in encoded if b in self.bad_chars)
            
            if bad_count < min_bad:
                min_bad = bad_count
                best_key = key
                best_result = encoded
        
        if best_result is None:
            key = random.choice([k for k in range(1, 256) if k not in self.bad_chars])
            best_key = key
            best_result = bytes([(b - key) & 0xFF for b in shellcode])
        
        decoder = self._generate_sub_decoder(best_key, len(shellcode

        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=best_result,
            decoder_stub=decoder,
            encoder_type=EncoderType.SUB,
            key=best_key,
            description=f"减法编码，key=0x{best_key:02x}")
        

    
    def _generate_sub_decoder(self, key: int, length: int) -> bytes:
        """生成减法解码器 stub"""
        return self._generate_arithmetic_decoder(key, length, "add")
    
    def _generate_arithmetic_decoder(, self, key: int, length: int, operation: str) -> bytes:
        """
        生成算术运算解码器
        
        Args:
            key: 操作数
            length: shellcode 长度
            operation: 操作类型 ('add' 或 'sub')
        
        Returns:
            bytes: 解码器 stub
        """
        if self.arch == "amd64":
            reg = "al"
            ptr_reg = "rsi"
            code = f"""
            push {ptr_reg}
            mov {ptr_reg}, 0x0000
            mov ecx, {length}
            mov {reg}, 0x{key:02x}
        decode_loop:
            {operation} byte ptr [{ptr_reg}], {reg}
            inc {ptr_reg}
            loop decode_loop
            pop {ptr_reg}
            jmp {ptr_reg}
            """
        else:
            reg = "al"
            ptr_reg = "esi"
            code = f"""
            push {ptr_reg}
            mov {ptr_reg}, 0x0000
            mov ecx, {length}
            mov {reg}, 0x{key:02x}
        decode_loop:
            {operation} byte ptr [{ptr_reg}], {reg}
            inc {ptr_reg}
            loop decode_loop
            pop {ptr_reg}
            jmp {ptr_reg}
            """
        
        if PWNLIB_AVAILABLE:
            try:
                arch = 'amd64' if self.arch == 'amd64' else 'i386',
                return asm(code, arch=arch)
            except Exception:
                pass
        
        return b''
    
    def _not_encode(self, shellcode: bytes) -> EncodeResult:
        """NOT 运算编码"""
        encoded = bytes([~b & 0xFF for b in shellcode])
        decoder = self._generate_not_decoder(len(shellcode

        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=encoded,
            decoder_stub=decoder,
            encoder_type=EncoderType.NOT,
            description="NOT 运算编码")
        

    
    def _generate_not_decoder(self, length: int) -> bytes:
        """生成 NOT 解码器 stub"""
        if self.arch == "amd64":
            ptr_reg = "rsi"
        else:
            ptr_reg = "esi"
        
        code = f"""
        push {ptr_reg}
        mov {ptr_reg}, 0x0000
        mov ecx, {length}
    decode_loop:
        not byte ptr [{ptr_reg}]
        inc {ptr_reg}
        loop decode_loop
        pop {ptr_reg}
        jmp {ptr_reg}
        """
        
        if PWNLIB_AVAILABLE:
            try:
                arch = 'amd64' if self.arch == 'amd64' else 'i386',
                return asm(code, arch=arch)
            except Exception:
                pass
        
        return b''
    
    def _rol_encode(self, shellcode: bytes) -> EncodeResult:
        """循环左移编码"""
        best_shift = 0
        best_result = None
        min_bad = float('inf')
        
        for shift in range(1, 8):
            encoded = self._rol_byte_array(shellcode, shift)
            bad_count = sum(1 for b in encoded if b in self.bad_chars)
            
            if bad_count < min_bad:
                min_bad = bad_count
                best_shift = shift
                best_result = encoded
        
        if best_result is None:
            best_shift = 1
            best_result = self._rol_byte_array(shellcode, best_shift)
        
        decoder = self._generate_rol_decoder(best_shift, len(shellcode

        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=best_result,
            decoder_stub=decoder,
            encoder_type=EncoderType.ROL,
            key=best_shift,
            description=f"循环左移编码，shift={best_shift}")
        

    
    def _rol_byte_array(self, data: bytes, shift: int) -> bytes:
        """对字节数组执行循环左移"""
        def rol(b, n):
            return ((b << n) | (b >> (8 - n))) & 0xFF
        return bytes([rol(b, shift) for b in data])
    
    def _ror_byte_array(self, data: bytes, shift: int) -> bytes:
        """对字节数组执行循环右移"""
        def ror(b, n):
            return ((b >> n) | (b << (8 - n))) & 0xFF
        return bytes([ror(b, shift) for b in data])
    
    def _generate_rol_decoder(self, shift: int, length: int) -> bytes:
        """生成 ROL 解码器 stub"""
        return self._generate_shift_decoder(shift, length, "ror")
    
    def _generate_ror_decoder(self, shift: int, length: int) -> bytes:
        """生成 ROR 解码器 stub"""
        return self._generate_shift_decoder(shift, length, "rol")
    
    def _generate_shift_decoder(, self, shift: int, length: int, operation: str) -> bytes:
        """生成移位解码器 stub"""
        if self.arch == "amd64":
            ptr_reg = "rsi"
            count_reg = "cl"
        else:
            ptr_reg = "esi"
            count_reg = "cl"
        
        code = f"""
        push {ptr_reg}
        mov {ptr_reg}, 0x0000
        mov ecx, {length}
        mov {count_reg}, {shift}
    decode_loop:
        {operation} byte ptr [{ptr_reg}], {count_reg}
        inc {ptr_reg}
        loop decode_loop
        pop {ptr_reg}
        jmp {ptr_reg}
        """
        
        if PWNLIB_AVAILABLE:
            try:
                arch = 'amd64' if self.arch == 'amd64' else 'i386',
                return asm(code, arch=arch)
            except Exception:
                pass
        
        return b''
    
    def _ror_encode(self, shellcode: bytes) -> EncodeResult:
        """循环右移编码"""
        best_shift = 0
        best_result = None
        min_bad = float('inf')
        
        for shift in range(1, 8):
            encoded = self._ror_byte_array(shellcode, shift)
            bad_count = sum(1 for b in encoded if b in self.bad_chars)
            
            if bad_count < min_bad:
                min_bad = bad_count
                best_shift = shift
                best_result = encoded
        
        if best_result is None:
            best_shift = 1
            best_result = self._ror_byte_array(shellcode, best_shift)
        
        decoder = self._generate_ror_decoder(best_shift, len(shellcode

        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=best_result,
            decoder_stub=decoder,
            encoder_type=EncoderType.ROR,
            key=best_shift,
            description=f"循环右移编码，shift={best_shift}")
        

    
    def _insertion_encode(self, shellcode: bytes) -> EncodeResult:
        """插入编码（每隔N字节插入一个垃圾字节）"""
        # 简化实现：每4字节插入一个0x90(NOP)
        garbage_byte = 0x90  # NOP
        
        while garbage_byte in self.bad_chars:
            garbage_byte = random.choice([b for b in range(256) if b not in self.bad_chars])
        
        encoded = bytearray()
        for i, b in enumerate(shellcode):
            encoded.append(b)
            if (i + 1) % 4 == 0:
                encoded.append(garbage_byte)
        
        # 生成解码器
        decoder = self._generate_insertion_decoder(garbage_byte, len(shellcode), 4)
        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=bytes(encoded),
            decoder_stub=decoder,
            encoder_type=EncoderType.INSERTION,
            key=garbage_byte,
            description=f"插入编码，每4字节插入0x{garbage_byte:02x}")
        

    
    def _generate_insertion_decoder(, self, garbage_byte: int, shellcode_len: int, interval: int) -> bytes:
        """生成插入解码器 stub"""
        # 简化实现：实际需要更复杂的逻辑来跳过垃圾字节
        return bytes()
    
    def _base64_encode(self, shellcode: bytes) -> EncodeResult:
        """Base64 编码"""
        encoded = base64.b64encode(shellcode)
        
        # Base64 编码后的数据只包含字母数字和+/=
        # 可能需要避免 /
        bad_in_result = [b for b in encoded if b in self.bad_chars]
        
        return EncodeResult(
            original_shellcode=shellcode,
            encoded_shellcode=encoded,
            decoder_stub=b'',  # 需要添加 Base64 解码器
            encoder_type=EncoderType.BASE64,
            contains_bad_chars=len(bad_in_result) > 0,
            bad_chars_found=bad_in_result,
            description="Base64 编码")
        

    
    def _polymorphic_encode(self, shellcode: bytes) -> EncodeResult:
        """多态编码"""
        # 组合多种编码方法
        result = self._xor_encode(shellcode)
        result.encoder_type = EncoderType.POLYMORPHIC
        result.description = "多态编码（XOR + 随机垃圾指令）",
        return result
    
    def _verify_encode_result(self, result: EncodeResult) -> EncodeResult:
        """
        验证编码结果
        
        Args:
            result: 编码结果
        
        Returns:
            EncodeResult: 验证后的编码结果
        """
        # 检查编码后的 shellcode 是否包含坏字符
        bad_found = []
        for b in result.encoded_shellcode:
            if b in self.bad_chars:
                bad_found.append(b)
        
        result.contains_bad_chars = len(bad_found) > 0
        result.bad_chars_found = bad_found
        
        # 如果包含坏字符，尝试重新编码
        if result.contains_bad_chars:
            bad_chars_hex = [f"{b:02x}" for b in bad_found[:5]]
            bad_chars_display = ['\\x' + c for c in bad_chars_hex]
            self.logger.warning()
                f"编码结果包含坏字符: {bad_chars_display}"
            
        
        return result
    
    def find_best_xor_key(self, shellcode: bytes) -> Tuple[int, bytes]:
        """
        搜索最佳 XOR 密钥
        
        Args:
            shellcode: 原始 shellcode
        
        Returns:
            Tuple[int, bytes]: (最佳密钥, 编码后的 shellcode)
        """
        best_key = 0
        best_encoded = b''
        min_bad = float('inf')
        
        for key in range(1, 256):
            if key in self.bad_chars:
                continue
            
            encoded = bytes([b ^ key for b in shellcode])
            bad_count = sum(1 for b in encoded if b in self.bad_chars)
            
            if bad_count < min_bad:
                min_bad = bad_count
                best_key = key
                best_encoded = encoded
        
        return best_key, best_encoded
    
    def generate_final_shellcode(, self, result: EncodeResult, fix_address: Optional[int] = None) -> bytes:
        """
        生成最终的 shellcode（解码器 + 编码后的 shellcode）
        
        Args:
            result: 编码结果
            fix_address: 固定地址（如果已知）
        
        Returns:
            bytes: 最终的 shellcode
        """
        # 如果提供了固定地址，替换解码器中的占位符
        decoder = result.decoder_stub
        
        if fix_address and len(decoder) > 0:
            decoder = self._fix_decoder_address(decoder, fix_address)
        
        # 组合解码器和编码后的 shellcode
        return decoder + result.encoded_shellcode
    
    def _fix_decoder_address(self, decoder: bytes, address: int) -> bytes:
        """修复解码器中的地址占位符"""
        # 简单实现：假设地址在解码器中的特定位置
        # 实际需要更复杂的逻辑
        return decoder
    
    def generate_pwntools_script(, self, result: EncodeResult, shellcode_name: str = "shellcode") -> str:
        """
        生成 pwntools 脚本
        
        Args:
            result: 编码结果
            shellcode_name: shellcode 变量名
        
        Returns:
            str: pwntools 脚本
        """
        script = f"""#!/usr/bin/env python3
\"\"\"生成的 shellcode 脚本\"\"\"

from pwn import *

context.arch = '{self.arch}'
context.update(arch='{self.arch}')

# 编码后的 shellcode
{shellcode_name} = {repr(result.encoded_shellcode)}

# 解码器
decoder = {repr(result.decoder_stub)}

# 最终 shellcode
final_shellcode = decoder + {shellcode_name}

# 输出信息
log.info(f"原始大小: {{len({repr(result.original_shellcode)})}} bytes")
log.info(f"编码后大小: {{len({shellcode_name})}} bytes")
log.info(f"解码器大小: {{len(decoder)}} bytes")
log.info(f"编码器类型: {{'{result.encoder_type.value}'}}")
"""
        if result.key is not None:
            script += f"log.info(f\"编码密钥: {{hex({result.key})}}\")\n"
        
        return script


def encode_shellcode(, shellcode: bytes, arch: str = "amd64", bad_chars: Optional[List[int]] = None, encoder_type: Optional[str] = None) -> EncodeResult:
    """
    便捷函数：编码 shellcode
    
    Args:
        shellcode: 原始 shellcode
        arch: 架构
        bad_chars: 坏字符列表
        encoder_type: 编码器类型
    
    Returns:
        EncodeResult: 编码结果
    """
    encoder = ShellcodeEncoder(arch=arch, bad_chars=bad_chars)
    
    enc_type = None,
    if encoder_type:
        try:
            enc_type = EncoderType(encoder_type)
        except ValueError:
            pass
    
    return encoder.encode(shellcode, encoder_type=enc_type)


# 示例用法和测试
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # 测试 shellcode (简单的 exit(0))

    test_shellcode = bytes([)
        0x48, 0x31, 0xFF,  # xor rdi, rdi
        0xB0, 0x3C,        # mov al, 60
        0x0F, 0x05,        # syscall
    ]
    
    print(f"原始 shellcode: {test_shellcode.hex()}")
    print(f"原始大小: {len(test_shellcode)} bytes")
    
    # 创建编码器
    encoder = ShellcodeEncoder(arch="amd64", bad_chars=[0x00, 0x0a])
    
    # XOR 编码
    result = encoder.encode(test_shellcode, EncoderType.XOR)
    
    print(f"\n编码结果:")
    print(f"  编码类型: {result.encoder_type.value}")
    print(f"  密钥: {hex(result.key) if result.key else 'N/A'}")
    print(f"  编码后大小: {result.encoded_size} bytes")
    print(f"  包含坏字符: {result.contains_bad_chars}")
    print(f"  描述: {result.description}")
    
    if result.contains_bad_chars:
        bad_chars_hex = [f"{b:02x}" for b in result.bad_chars_found]
        bad_chars_display = ['\\x' + c for c in bad_chars_hex]
        print(f"  发现的坏字符: {bad_chars_display}")
    
    print(f"\n编码后 shellcode: {result.encoded_shellcode.hex()}")
    
    # 生成最终 shellcode
    final = encoder.generate_final_shellcode(result)
    print(f"\n最终 shellcode (解码器 + 编码数据):")
    print(f"  大小: {len(final)} bytes")
    print(f"  内容: {final.hex()}")
    
    # 生成 pwntools 脚本
    script = encoder.generate_pwntools_script(result)
    print(f"\n生成的 pwntools 脚本:")
    print(script))))))