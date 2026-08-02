# 2026-07-16
# ---- 字节级变异策略集：AFL式浩劫、拼接杂交、字典注入、魔数/有趣值替换 ----
# 参考AFL++ havoc stage & custom mutator，每条策略独立可组合
# 全部操作在bytes上原地或copy进行，不做文件IO

import random
import struct

# ===== 内部工具 =====

def _xor_bytes(data: bytearray, key: int) -> None:
    """原地XOR每个字节"""
    kb = key & 0xFF
    for i in range(len(data)):
        data[i] ^= kb


# ===== Havoc: AFL风格随机多轮变异 =====

class HavocMutator:
    """多策略随机组合变异，模拟AFL havoc stage"""

    def __init__(self, seed=None):
        self.rng = random.Random(seed)

    # ---- 位翻转 ----
    @staticmethod
    def _flip_bit(b: int) -> int:
        pos = random.randint(0, 7)
        return b ^ (1 << pos)

    # ---- 字节翻转 ----
    @staticmethod
    def _flip_byte(b: int) -> int:
        return b ^ random.randint(1, 255)

    # ---- 算术变换 ----
    @staticmethod
    def _arith(b: int, delta: int) -> int:
        v = b + delta
        return v & 0xFF

    # ---- 主变异循环 ----

    def mutate(self, data: bytes, iterations: int = 1) -> bytes:
        """浩劫入口：每一轮随机选操作 → 修改随机位置 → 返回新bytes"""
        buf = bytearray(data)
        if not buf:
            return bytes(buf)

        ops = ["bit_flip", "byte_flip", "arith_inc", "arith_dec", "block_swap", "xor_byte"]

        for _ in range(iterations):
            op = self.rng.choice(ops)
            idx = self.rng.randrange(len(buf))

            if op == "bit_flip":
                buf[idx] = self._flip_bit(buf[idx])

            elif op == "byte_flip":
                buf[idx] = self._flip_byte(buf[idx])

            elif op == "arith_inc":
                delta = self.rng.randint(1, 35)
                buf[idx] = self._arith(buf[idx], delta)

            elif op == "arith_dec":
                delta = -self.rng.randint(1, 35)
                buf[idx] = self._arith(buf[idx], delta)

            elif op == "block_swap":
                # 交换两个等长block
                blen = min(self.rng.randint(1, 16), len(buf) // 2)
                if blen < 1:
                    continue
                a = self.rng.randrange(len(buf) - blen + 1)
                b = self.rng.randrange(len(buf) - blen + 1)
                buf[a:a+blen], buf[b:b+blen] = buf[b:b+blen], buf[a:a+blen]

            elif op == "xor_byte":
                key = self.rng.randint(1, 255)
                _xor_bytes(buf, key)

        return bytes(buf)


# ===== Splice: 二体杂交 =====

class SpliceStrategy:
    """两样本交叉拼接"""

    @staticmethod
    def splice(a: bytes, b: bytes, ratio: float = 0.5) -> bytes:
        """在随机切点拼接a的前部+b的后部"""
        if not a:
            return b
        if not b:
            return a

        # 切点：ratio控制大约比例
        cut_a = int(len(a) * ratio) + random.randint(-len(a)//10, len(a)//10)
        cut_a = max(0, min(len(a), cut_a))
        cut_b = int(len(b) * ratio) + random.randint(-len(b)//10, len(b)//10)
        cut_b = max(0, min(len(b), cut_b))

        return a[:cut_a] + b[cut_b:]


# ===== DictInsert: 字典token注入 =====

class DictInsertMutator:
    """在随机位置插入字典条目（如常见magic bytes/协议token）"""

    def __init__(self, dictionary: list = None):
        self.dict = dictionary or []
        self.rng = random.SystemRandom() if not dictionary else random.Random()

    def mutate(self, data: bytes, max_inserts: int = 3) -> bytes:
        """在随机偏移处逐个插入字典条目"""
        if not self.dict:
            return data

        buf = bytearray(data)
        n_inserts = self.rng.randint(1, max(min(max_inserts, len(self.dict)), 1))

        for _ in range(n_inserts):
            entry = self.rng.choice(self.dict)
            if not entry:
                continue
            pos = self.rng.randint(0, len(buf))
            buf[pos:pos] = entry if isinstance(entry, bytes) else entry.encode("utf-8", errors="surrogateescape")

        return bytes(buf)


# ===== MagicNumberFlip: 魔数替换 =====

_MAGIC_NUMBERS = {
    0x7F454C46: b"\x7F\x45\x4C\x46",  # ELF
    0x4D5A:     b"\x4D\x5A",          # PE/MZ
    0xFEEDFACE: b"\xFE\xED\xFA\xCE",  # Mach-O (32)
    0xFEEDFACF: b"\xFE\xED\xFA\xCF",  # Mach-O (64)
    0xCAFEBABE: b"\xCA\xFE\xBA\xBE",  # Java class
    0xDEADBEEF: b"\xDE\xAD\xBE\xEF",  # 常用sentinel
    0xBEEF:     b"\xBE\xEF",          # mini magic
    0x1F8B:     b"\x1F\x8B",          # gzip
    0x504B0304: b"\x50\x4B\x03\x04",  # ZIP
    0x89504E47: b"\x89\x50\x4E\x47",  # PNG
    0xFFD8FF:   b"\xFF\xD8\xFF",       # JPEG
}


class MagicNumberFlip:
    """探测已知魔数并替换为变体，用于解析器鲁棒性测试"""

    def __init__(self):
        self.magic_table = _MAGIC_NUMBERS
        self.rng = random.Random()

    def mutate(self, data: bytes) -> bytes:
        """扫描并替换首个匹配的魔数"""
        buf = bytearray(data)

        # 按长度降序扫描，优先匹配长魔数
        sorted_magics = sorted(self.magic_table.items(), key=lambda x: -len(x[1]))

        for magic_val, magic_bytes in sorted_magics:
            idx = buf.find(magic_bytes)
            if idx < 0:
                continue

            # 选另一个魔数做替换
            other = [(v, b) for v, b in sorted_magics if v != magic_val and len(b) == len(magic_bytes)]
            if not other:
                # 无同长度候选 → 翻转前几个字节
                for o in range(min(4, len(magic_bytes))):
                    buf[idx + o] ^= self.rng.randint(1, 255)
                return bytes(buf)

            _, replacement = self.rng.choice(other)
            buf[idx : idx + len(replacement)] = replacement
            return bytes(buf)  # 只替换一处

        return bytes(buf)


# ===== InterestingValue: AFL式有趣值注入 =====

_INTERESTING_8 = [
    0, 1,
    0x7F, 0xFF,           # INT8 边界
    0x80, 0x00,           # INT8 最小
]

_INTERESTING_16 = [
    0, 1, 2,
    0x7F, 0xFF,
    0x80, 0x00,
    0x7FFF, 0xFFFF,       # INT16 边界
    0x8000, 0x0000,       # INT16 最小
    0x0100, 0x00FF,       # 字节序边界
]

_INTERESTING_32 = [
    0, 1, 2,
    0x7F, 0xFF,
    0x80, 0x00,
    0x7FFFFFFF, 0xFFFFFFFF,  # INT32 边界
    0x80000000, 0x00000000,  # INT32 最小
    0x01000000, 0x00FFFFFF,  # 字节序
    0xFFFF0000, 0x0000FFFF,
]


class InterestingValueMutator:
    """用AFL有趣值替换随机偏移的几个字节"""

    def __init__(self):
        self.v8 = _INTERESTING_8
        self.v16 = _INTERESTING_16
        self.v32 = _INTERESTING_32
        self.rng = random.Random()

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data

        buf = bytearray(data)

        # 随机选宽度: 1, 2, or 4字节
        width = self.rng.choice([1, 2, 4])

        if width == 1:
            pool = self.v8
            fmt = "<B"
        elif width == 2:
            pool = self.v16
            fmt = "<H"
        else:
            pool = self.v32
            fmt = "<I"

        val = self.rng.choice(pool)
        try:
            packed = struct.pack(fmt, val)
        except struct.error:
            packed = struct.pack("<B", val & 0xFF)

        # 随机写入位置
        if len(buf) >= len(packed):
            pos = self.rng.randrange(len(buf) - len(packed) + 1)
            buf[pos : pos + len(packed)] = packed

        return bytes(buf)
