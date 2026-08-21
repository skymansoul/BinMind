# 结构保持模式，未提供TypeAwareStructureInferer时退化为纯ddmin
# 块级缩减时字段边界对齐修复
# token-level缩减策略 (文本类输入按分隔符分块)

# 结构感知的测试用例最小化器 - 基于加权delta debugging的输入缩减
#
# 设计动机:
#   Fuzzing产出的崩溃输入通常含大量无关字节。最小化到触发崩溃的最小
#   子集有助于根因分析。传统ddmin将所有字节视为等价
#   原子单元，对二进制格式输入效率低且可能破坏格式有效性。
#
# 核心方法:
#   阶段1 — 若提供了TypeAwareStructureInferer的字段推断结果（或等价
#     field map），按字段优先级分批缩减:
#       raw/padding字段: 缩减粒度1字节，激进删除
#       string字段: 按token (分隔符) 或逐字节删除
#       magic/length/checksum: 不缩减（保持格式有效性）
#   阶段2 — 对阶段1结果执行块级ddmin，块大小从N/2开始二分。
#     每个候选提交给predicate(data)-bool验证。
#
#   无结构信息时退化为标准ddmin+字节级渐进缩减。
#
# 文献:
#   WDD: Weighted Delta Debugging
#     - 提出按输入元素大小加权分区，大块优先检测，减少测试次数。
#     本项目借鉴其加权思想但替换为字段类型优先级-类型敏感缩减
#     比纯大小加权在二进制格式上更高效。
#   GReduce
#     - 通过生成器trace缩减保持输入有效性。本项目取其结构保持缩减
#       思想，但以推断字段边界而非生成器trace作为结构来源。
#     - ddmin原始算法，本项目阶段2的退化路径。
import math
import time
from typing import Callable, Dict, List, Optional, Tuple


# 字段优先级: 值越小越优先被缩减
# raw/padding优先删，magic/checksum保留到最后
_FIELD_REDUCE_PRIORITY = {
    "raw": 0, "padding": 0,
    "string": 1,
    "counter": 2, "enum_flags": 2, "timestamp": 2,
    "type": 3, "length": 4,
    "magic": 5, "checksum": 5,
}


def _field_priority(field_type: str) -> int:
    return _FIELD_REDUCE_PRIORITY.get(field_type, 3)


class InputMinimizer:
    """结构感知的测试用例最小化器。

    典型用法:
        minimizer = InputMinimizer()
        result = minimizer.minimize(crash_input, predicate=lambda d: crashes(d))
        # result即为保持崩溃属性的最小输入

    predicate(data: bytes) - bool:
        返回True表示data仍保持目标属性 (如触发同一崩溃/覆盖同一路径)。
    """

    def __init__(self,
                 field_map: Optional[List[Dict]] = None,
                 max_iterations: int = 500):
        """
        field_map: TypeAwareStructureInferer.field_summary()的输出,
                   每项含offset/size/type/confidence。
                   为None时退化为无结构感知的纯ddmin。
        max_iterations: 单次minimize()的最大谓词调用次数。
        """
        self._fields = field_map or []
        self._max_iter = max_iterations
        self._predicate_calls = 0

    # 主入口
    def minimize(self, data: bytes,
                 predicate: Callable[[bytes], bool],
                 timeout_s: float = 30.0) -> bytes:
        """对data执行结构感知缩减，返回最小化结果。

        流程:
          1. 字段级缩减 (若有结构信息)
          2. Token级缩减 (对string字段，语义保持)
          3. ddmin块级缩减 (通用，始终执行)
          4. 字节级精细缩减 (逐字节尝试删除，最后5%打磨)
        """
        self._predicate_calls = 0
        deadline = time.monotonic() + timeout_s
        current = data

        # 阶段1: 字段感知缩减
        if self._fields:
            current = self._field_aware_reduce(current, predicate, deadline)

        # 阶段2: token级缩减 (对可识别分隔符的文本段)
        current = self._token_level_reduce(current, predicate, deadline)

        # 阶段3: 块级ddmin
        current = self._ddmin_reduce(current, predicate, deadline)

        # 阶段4: 逐字节打磨
        current = self._byte_level_reduce(current, predicate, deadline)

        return current

    # 阶段实现
    def _field_aware_reduce(self, data: bytes,
                            predicate: Callable[[bytes], bool],
                            deadline: float) -> bytes:
        """按字段优先级从低到高尝试将字段内容归零/截断。"""
        sorted_fields = sorted(self._fields,
                               key=lambda f: _field_priority(
                                   f.get("type", "raw")))
        current = data

        for field in sorted_fields:
            if time.monotonic() > deadline or self._predicate_calls >= self._max_iter:
                break

            offset = field.get("offset", 0)
            size = field.get("size", 0)
            ftype = field.get("type", "raw")

            if offset + size > len(current):
                continue

            # magic/checksum不缩减
            if ftype in ("magic", "checksum"):
                continue

            # 尝试1: 字段归零 (仅对raw/padding)
            if ftype in ("raw", "padding"):
                candidate = bytearray(current)
                for i in range(offset, offset + size):
                    candidate[i] = 0
                candidate = bytes(candidate)
                if self._test(predicate, candidate):
                    current = candidate
                    continue

            # 尝试2: 截断字段后所有内容 (仅对raw且为最后字段时)
            remaining_fields = [f for f in sorted_fields
                                if f.get("offset", 0) > offset]
            if not remaining_fields and ftype in ("raw", "string"):
                candidate = current[:offset]
                if self._test(predicate, candidate):
                    current = candidate
                    continue

            # 尝试3: 对字段内容做二分缩减
            if ftype in ("raw", "string") and size >= 4:
                current = self._field_ddmin(current, offset, size,
                                            predicate, deadline)

        return current

    def _field_ddmin(self, data: bytes, offset: int, size: int,
                     predicate: Callable[[bytes], bool],
                     deadline: float) -> bytes:
        """在单个字段内做ddmin缩减。保护字段边界不被越过。"""
        current = data
        # 字段尾部可能提前截断
        for end in range(offset + size, offset, -1):
            if time.monotonic() > deadline or self._predicate_calls >= self._max_iter:
                break
            candidate = bytearray(current[:end])
            candidate.extend(current[offset + size:])
            # 补齐候选长度
            if len(candidate) < len(current):
                candidate.extend(b'\x00' * (len(current) - len(candidate)))
            candidate = bytes(candidate)
            if self._test(predicate, bytes(current[:end])):
                # 可以从此处截断
                current = current[:end]
                break
        return current

    def _token_level_reduce(self, data: bytes,
                            predicate: Callable[[bytes], bool],
                            deadline: float) -> bytes:
        """对可识别分隔符的文本段按token删除。

        分隔符: 空格、换行、制表符、冒号、逗号、分号等。
        仅在输入主要为可打印ASCII时执行token缩减。
        """
        # 仅在输入主要为可打印ASCII时执行
        printable_ratio = sum(1 for b in data if 0x20 <= b <= 0x7E) / max(1, len(data))
        if printable_ratio < 0.6:
            return data

        text = data.decode("utf-8", errors="replace")
        # 按分隔符分token
        import re
        tokens = re.split(r'([\s:;,=\{\}\[\]\(\)\"\'\n\r\t]+)', text)
        # tokens中偶数下标为内容token，奇数下标为分隔符

        current = text
        for i in range(0, len(tokens), 2):
            if time.monotonic() > deadline or self._predicate_calls >= self._max_iter:
                break
            if i >= len(tokens):
                break
            # 尝试删除此token及其相邻分隔符
            removed = "".join(tokens[:i] + tokens[i + 2:])
            candidate = removed.encode("utf-8", errors="replace")
            if self._test(predicate, candidate):
                tokens = tokens[:i] + tokens[i + 2:]
                current = removed
                i -= 2  # 回退以检查合并后的相邻token

        return current.encode("utf-8", errors="replace")

    def _ddmin_reduce(self, data: bytes,
                      predicate: Callable[[bytes], bool],
                      deadline: float) -> bytes:
        """标准ddmin: 将输入分为2^k块，尝试删除各块。

        分块数从2开始翻倍，直到达到字节级粒度。
        """
        current = data
        n = 2  # 分块数
        while n <= len(current):
            if time.monotonic() > deadline or self._predicate_calls >= self._max_iter:
                break
            block_size = max(1, len(current) // n)
            improved = False
            for i in range(n):
                start = i * block_size
                end = start + block_size if i < n - 1 else len(current)
                candidate = current[:start] + current[end:]
                if self._test(predicate, candidate):
                    current = candidate
                    improved = True
                    break  # 重新从n=2开始
            if improved:
                n = 2
            else:
                n *= 2  # 减小粒度
        return current

    def _byte_level_reduce(self, data: bytes,
                           predicate: Callable[[bytes], bool],
                           deadline: float) -> bytes:
        """逐字节尝试删除（最后5%打磨）。

        仅对连续零字节区域和尾部非零字节执行。
        """
        current = bytearray(data)

        # 扫描连续零字节区域
        i = 0
        while i < len(current):
            if time.monotonic() > deadline or self._predicate_calls >= self._max_iter:
                break
            if current[i] == 0:
                # 找到连续零区域
                j = i + 1
                while j < len(current) and current[j] == 0:
                    j += 1
                if j - i >= 4:
                    candidate = bytes(current[:i] + current[j:])
                    if self._test(predicate, candidate):
                        current = bytearray(candidate)
                        continue
                i = j
            else:
                i += 1

        # 尾部缩减: 从末尾逐字节删除
        while len(current) > 1:
            if time.monotonic() > deadline or self._predicate_calls >= self._max_iter:
                break
            candidate = bytes(current[:-1])
            if self._test(predicate, candidate):
                current = bytearray(candidate)
            else:
                break

        return bytes(current)

    # 内部
    def _test(self, predicate: Callable[[bytes], bool],
              data: bytes) -> bool:
        """调用谓词并更新计数器。"""
        self._predicate_calls += 1
        if not data:
            return False
        try:
            return predicate(data)
        except Exception:
            # 谓词异常 -> 候选无效
            return False

    @property
    def stats(self) -> Dict:
        return {
            "predicate_calls": self._predicate_calls,
            "fields_used": len(self._fields),
        }
