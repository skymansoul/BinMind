from enum import Enum
import random


class FileFormatType(Enum):
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach_o"


class FuzzerType(Enum):
    LIBFUZZER = "libfuzzer"
    AFL = "afl"
    HONGGFUZZ = "honggfuzz"


class MutationStrategy(Enum):
    RANDOM = "random"
    SMART = "smart"
    DICTIONARY = "dictionary"


# 各文件格式的魔数，供 SMART/DICTIONARY 策略识别边界
_MAGIC = {
    FileFormatType.ELF: b'\x7fELF',
    FileFormatType.PE: b'MZ',
    FileFormatType.MACH_O: b'\xfe\xed\xfa\xce',
}

# 常见解析入口 API，DICTIONARY 策略注入的关键字
_DICTIONARY = {
    FileFormatType.ELF: (b'.text', b'.data', b'symtab', b'strtab'),
    FileFormatType.PE: (b'.text', b'.data', b'.rdata', b'Import Table'),
    FileFormatType.MACH_O: (b'__TEXT', b'__DATA', b'LC_SEGMENT', b'symtab'),
}


class FormatField:
    """格式字段: 名称/偏移/大小/类型, 支持嵌套子字段"""

    def __init__(self, name="", offset=0, size=0, ftype="uint32", children=None):
        self.name = name
        self.offset = offset
        self.size = size
        self.ftype = ftype
        self.children = children or []


class FormatStructure:
    """格式结构: 格式类型 + 顶层字段列表"""

    def __init__(self, format_type=None, fields=None, name=""):
        self.format_type = format_type
        self.fields = fields or []
        self.name = name or (format_type.value if format_type else "custom")


class FuzzerConfig:
    """fuzz 配置: 变异策略/迭代上限/单样本大小上限/种子"""

    def __init__(self, strategy=MutationStrategy.RANDOM,
                 iterations=1000, max_len=4096, seed=0):
        self.strategy = strategy
        self.iterations = iterations
        self.max_len = max_len
        self.seed = seed


class FuzzerHarness:
    """fuzz 执行入口: 输入字节流 + 配置 -> 变异 -> 输出用例"""

    def __init__(self, config=None):
        self.config = config or FuzzerConfig()
        self._rng = random.Random(self.config.seed)
        self._magic = b''
        self._keywords = ()

    def bind_format(self, fmt):
        """绑定格式结构, 提取魔数与字典"""
        self._magic = _MAGIC.get(fmt.format_type, b'')
        self._keywords = _DICTIONARY.get(fmt.format_type, ())

    def mutate(self, data):
        """按策略变异一个样本, 返回变异后的字节"""
        if not data:
            data = self._magic or b'\x00' * 4
        data = bytearray(data)
        if self.config.strategy == MutationStrategy.DICTIONARY:
            # 字典策略: 在随机偏移插入词典 token
            tok = self._rng.choice(self._keywords)
            idx = self._rng.randrange(0, len(data) + 1)
            data[idx:idx] = tok
        elif self.config.strategy == MutationStrategy.SMART:
            # 智能策略: 保魔数不变, 只改其后内容
            keep = min(len(self._magic), len(data))
            data = data[:keep] + bytearray(
                self._rng.getrandbits(8) for _ in range(len(data) - keep))
        else:
            # 随机策略: 翻转/插入/删除随机字节
            if self._rng.random() < 0.5:
                for _ in range(self._rng.randrange(1, 4)):
                    if data:
                        i = self._rng.randrange(len(data))
                        data[i] = self._rng.getrandbits(8)
            if self._rng.random() < 0.3:
                i = self._rng.randrange(len(data) + 1)
                data.insert(i, self._rng.getrandbits(8))
            if self._rng.random() < 0.2 and len(data) > 1:
                i = self._rng.randrange(len(data))
                del data[i]
        return bytes(data[:self.config.max_len])

    def generate(self, seed_inputs):
        """迭代生成变异样本流"""
        for _ in range(self.config.iterations):
            base = self._rng.choice(seed_inputs) if seed_inputs else self._magic
            yield self.mutate(base)

    def run(self, seed_inputs, target_fn):
        """执行变异并用目标函数验证, 返回 (新样本, 目标函数返回值) 流"""
        for sample in self.generate(seed_inputs):
            try:
                ret = target_fn(sample)
            except Exception as e:
                ret = type(e).__name__
            yield sample, ret


class TestCase:
    """单条测试用例: 数据 + 派生它的变异策略"""

    def __init__(self, data=b"", strategy="random"):
        self.data = data
        self.strategy = strategy


class FormatFuzzerGenerator:
    """按格式结构生成 fuzz 用例集与 harness"""

    def __init__(self, config=None):
        self.config = config or FuzzerConfig()
        self._rng = random.Random(self.config.seed)

    def generate_cases(self, fmt, count=10):
        """依据格式字段构造合法骨架样本, 字段边界值随机化"""
        cases = []
        base = bytearray(self._magic.get(fmt.format_type, b''))
        size_hint = sum(f.size for f in fmt.fields) or 64
        base.extend(b'\x00' * size_hint)
        for _ in range(count):
            data = bytearray(base)
            for f in fmt.fields:
                off = min(f.offset, max(0, len(data) - f.size or 0))
                val = self._rng.choice([0, 1, 0x7fffffff, 0x80000000,
                                        0xffffffff, size_hint])
                try:
                    data[off:off + f.size] = val.to_bytes(f.size, 'little')
                except (ValueError, OverflowError):
                    data[off:off + f.size] = b'\xff' * f.size
            cases.append(TestCase(data=data, strategy="structure"))
        return cases

    def build_harness(self):
        """产出可直接运行的 FuzzerHarness 实例"""
        return FuzzerHarness(self.config)


def generate_format_fuzzer(fmt):
    """按格式类型生成 fuzzer 入口"""
    gen = FormatFuzzerGenerator()
    harness = gen.build_harness()
    harness.bind_format(fmt)
    return harness


def generate_test_corpus(fmt, count=10):
    """按格式结构生成初始语料"""
    gen = FormatFuzzerGenerator()
    return gen.generate_cases(fmt, count)


ELF_STRUCTURE = FormatStructure(FileFormatType.ELF)
PE_STRUCTURE = FormatStructure(FileFormatType.PE)
MACH_O_STRUCTURE = FormatStructure(FileFormatType.MACH_O)