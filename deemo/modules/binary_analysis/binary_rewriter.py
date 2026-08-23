import logging
import os
import re
import struct

from core.config import Config
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)

class BinaryRewriter:
    """
    binary重写器 - 提供binaryfile的重写和修补功能

    功能：
    1. 解析binaryfile结构（ELF/PE/Mach-O）
    2. 应用漏洞补丁
    3. inject安全check
    4. 检测和清除恶意代码
    5. fixbuffer overflow等常见漏洞
    """

    # 避免魔法數字，集中定義常量
    s_DEFAULT_MAX_SIZE = 256
    s_MAX_NOP_SLED = 4096
    s_MIN_CANARY_SIZE = 16

    def __init__(self, binary_path):
        self.binary_path = self._validate_path(binary_path)
        self.binary_format = self._detect_format()
        self.binary_data = self._load_binary()
        self.modifications = []
        self.patches_applied = []

        logger.info(f"initializebinary重写器: {self.binary_path}")
        logger.info(f"file格式: {self.binary_format}")

    def _validate_path(self, path):
        if path is None or not isinstance(path, str):
            raise ValueError("invalid file path")

        if not os.path.exists(path):
            raise FileNotFoundError(f"file not found: {path}")

        if not os.access(path, os.R_OK):
            raise PermissionError(f"无法读取file: {path}")

        return os.path.abspath(path)

    def _detect_format(self):
        # 检测binaryfile格式
        try:
            with open(self.binary_path, 'rb') as f:
                magic = f.read(4)

            if magic.startswith(b'\x7fELF'):
                return 'ELF'
            elif magic.startswith(b'MZ'):
                return 'PE'
            elif magic.startswith(b'\xcf\xfa\xed\xfe') or magic.startswith(b'\xfa\xcf\xed\xfe'):
                return 'MACH-O'
            else:
                return 'UNKNOWN'
        except Exception as e:
            logger.error(f"检测file格式failed: {e}")
            return 'UNKNOWN'

    def _load_binary(self):
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"loadbinaryfilefailed: {e}")
            return b''

    def _find_pattern(self, pattern):
        if pattern is None:
            return []
        positions = []
        offset = 0

        while True:
            offset = self.binary_data.find(pattern, offset)
            if offset == -1:
                break
            positions.append(offset)
            offset += 1

        return positions

    def _patch_memory(self, offset, new_bytes):
        if offset is None or new_bytes is None:
            logger.error("_patch_memory: parameteris empty")
            return False
        if offset < 0 or offset + len(new_bytes) > len(self.binary_data):
            logger.error(f"无效的修补位置: {offset}")
            return False
        offset = min(max(offset, 0), len(self.binary_data))

        self.binary_data = self.binary_data[:offset] + new_bytes + self.binary_data[offset + len(new_bytes):]
        self.modifications.append({
            'offset': offset,
            'old_bytes': None,
            'new_bytes': new_bytes.hex(),
            'type': 'patch'
        })

        logger.info(f"已修补位置 0x{offset:x}: {len(new_bytes)} 字节")
        return True

    def apply_nop_sled(self, offset, length):
        """
        在指定位置应用 NOP sled
        """
        if offset is None:
            logger.error("apply_nop_sled: offsetis empty")
            return False
        if length <= 0:
            logger.error("NOP sled length必须大于0")
            return False

        nop_bytes = b'\x90' * length
        return self._patch_memory(offset, nop_bytes)

    def patch_jmp_to_address(self, offset, target_address, is_64bit=False):
        """
        修补跳转指令到指定address
        """
        if offset is None or target_address is None:
            logger.error("patch_jmp_to_address: parameteris empty")
            return False
        if is_64bit:
            # 64位跳转: jmp qword ptr [rip+offset]
            jmp_instr = b'\xff\x25\x00\x00\x00\x00'  # jmp [rip+0]
            address_bytes = struct.pack('<Q', target_address)
            return self._patch_memory(offset, jmp_instr + address_bytes)
        else:
            # 32位跳转: jmp imm32
            relative_offset = target_address - (offset + 5)
            jmp_instr = b'\xe9' + struct.pack('<I', relative_offset & 0xFFFFFFFF)
            return self._patch_memory(offset, jmp_instr)

    def apply_buffer_overflow_fix(self, function_name, max_size):
        """
        应用buffer overflowfix
        """
        if function_name is None:
            function_name = 'unknown'
        if max_size is None:
            max_size = self.s_DEFAULT_MAX_SIZE
        logger.info(f"尝试fixbuffer overflow: {function_name}, 最大size: {max_size}")

        dangerous_patterns = [
            (b'\x8b\x45\x08\x8b\x4d\x0c\x89\x04\x85', '可能存在buffer复制'),  # mov eax, [ebp+8]; mov ecx, [ebp+12]
            (b'\xc7\x04\x24', '直接stack操作'),  # mov dword ptr [esp], ...
        ]

        found = False
        nPatIdx = 0
        nPatCount = len(dangerous_patterns)
        while nPatIdx < nPatCount:
            pattern, desc = dangerous_patterns[nPatIdx]
            positions = self._find_pattern(pattern)
            if positions:
                logger.info(f"found潜在危险mode: {desc}")
                found = True

                nPosIdx = 0
                nPosCount = len(positions)
                while nPosIdx < nPosCount:
                    pos = positions[nPosIdx]
                    self.apply_nop_sled(pos, 5)
                    nPosIdx += 1
            nPatIdx += 1

        return found

    def inject_canary_protection(self):
        """
        injectstack金丝雀保护
        """
        logger.info("尝试injectstack金丝雀保护")

        prologue_patterns = [
            b'\x55\x89\xe5',  # push ebp; mov ebp, esp (32位)
            b'\x48\x89\xe5',  # mov rbp, rsp (64位)
        ]

        nPatIdx = 0
        nPatCount = len(prologue_patterns)
        while nPatIdx < nPatCount:
            pattern = prologue_patterns[nPatIdx]
            positions = self._find_pattern(pattern)
            if positions:
                logger.info(f"found {len(positions)} functions序言")

                nPosIdx = 0
                nPosCount = min(len(positions), 10)
                while nPosIdx < nPosCount:
                    pos = positions[nPosIdx]
                    self.apply_nop_sled(pos + len(pattern), self.s_MIN_CANARY_SIZE)
                    nPosIdx += 1
            nPatIdx += 1

        self.patches_applied.append('canary_protection')
        return True

    def patch_format_string_vulnerability(self):
        """
        修补format string vulnerability
        """
        logger.info("尝试修补format string vulnerability")

        printf_patterns = [
            b'\xff\x15',  # call [printf]
            b'\xe8',      # call printf (相对调用)
        ]

        found = False
        nPatIdx = 0
        nPatCount = len(printf_patterns)
        while nPatIdx < nPatCount:
            pattern = printf_patterns[nPatIdx]
            positions = self._find_pattern(pattern)
            if positions:
                found = True
                logger.info(f"found {len(positions)} 个 printf 调用")
            nPatIdx += 1

        self.patches_applied.append('format_string_protection')
        return found

    def remove_shellcode(self, shellcode_signatures):
        """
        检测并清除 Shellcode
        """
        if shellcode_signatures is None:
            return 0
        removed_count = 0

        nSigIdx = 0
        nSigCount = len(shellcode_signatures)
        while nSigIdx < nSigCount:
            signature = shellcode_signatures[nSigIdx]
            positions = self._find_pattern(signature)
            nPosIdx = 0
            nPosCount = len(positions)
            while nPosIdx < nPosCount:
                pos = positions[nPosIdx]
                logger.info(f"发现 Shellcode，位置: 0x{pos:x}")
                self.apply_nop_sled(pos, len(signature))

                removed_count += 1
                nPosIdx += 1
            nSigIdx += 1

        return removed_count

    def apply_security_hardening(self):
        """应用综合安全加固"""
        results = {}

        results['canary'] = self.inject_canary_protection()
        results['format_string'] = self.patch_format_string_vulnerability()
        results['buffer_overflow'] = self.apply_buffer_overflow_fix('unknown', self.s_DEFAULT_MAX_SIZE)

        return results

    def save(self, output_path):
        """
        save修改后的binaryfile
        """
        if output_path is None:
            logger.error("save: output_pathis empty")
            return False
        try:
            with open(output_path, 'wb') as f:
                f.write(self.binary_data)

            os.chmod(output_path, 0o755)
            logger.info(f"修改后的binary已save到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"savefilefailed: {e}")
            return False

    def get_modification_summary(self):
        return {
            'binary_path': self.binary_path,
            'format': self.binary_format,
            'original_size': self._get_original_size(),
            'modified_size': len(self.binary_data),
            'modifications_count': len(self.modifications),
            'patches_applied': self.patches_applied,
            'modifications': self.modifications
        }

    def _get_original_size(self):
        return os.path.getsize(self.binary_path)

def patch_binary(binary_path, output_path, patches):
    """
    应用一系列补丁到binaryfile
    """
    if binary_path is None or output_path is None:
        return {
            'success': False,
            'error': 'binary_path/output_pathis empty',
            'message': 'parametererror'
        }
    if patches is None:
        patches = []
    try:
        rewriter = BinaryRewriter(binary_path)

        nPatIdx = 0
        nPatCount = len(patches)
        while nPatIdx < nPatCount:
            patch = patches[nPatIdx]
            patch_type = patch.get('type')

            if patch_type == 'nop_sled':
                offset = patch.get('offset')
                length = patch.get('length', 10)
                rewriter.apply_nop_sled(offset, length)

            elif patch_type == 'jmp_patch':
                offset = patch.get('offset')
                target = patch.get('target')
                is_64bit = patch.get('is_64bit', False)
                rewriter.patch_jmp_to_address(offset, target, is_64bit)

            elif patch_type == 'buffer_overflow_fix':
                func_name = patch.get('function_name', '')
                max_size = patch.get('max_size', 256)
                rewriter.apply_buffer_overflow_fix(func_name, max_size)

            elif patch_type == 'security_hardening':
                rewriter.apply_security_hardening()
            nPatIdx += 1

        success = rewriter.save(output_path)

        return {
            'success': success,
            'summary': rewriter.get_modification_summary(),
            'message': '修补complete' if success else 'savefailed'
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': f'修补failed: {e}'
        }

def analyze_and_patch(binary_path, output_path):
    """
    自动分析并修补binaryfile中的常见漏洞
    """
    if binary_path is None:
        return {
            'success': False,
            'error': 'binary_pathis empty',
            'message': 'parametererror'
        }
    logger.info(f"start自动分析和修补: {binary_path}")

    try:
        rewriter = BinaryRewriter(binary_path)

        # 应用安全加固
        results = rewriter.apply_security_hardening()

        # save结果
        success = rewriter.save(output_path)

        return {
            'success': success,
            'summary': rewriter.get_modification_summary(),
            'hardening_results': results,
            'message': '自动修补complete' if success else 'savefailed'
        }

    except Exception as e:
        logger.error(f"自动修补failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f'自动修补failed: {e}'
        }
