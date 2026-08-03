"""差分测试输入生成 — 随机、结构化、基于变异的fuzzing输入及能量调度。"""

import hashlib
import json
import random
import struct
from typing import Optional, Set, List, Tuple


class InputGenerator:
    """差分测试输入生成器。

    支持的输入类型:
    - 随机字节流
    - 结构化数据
    - 边界值
    - 基于变异的fuzzing
    """

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.generated_hashes: Set[str] = set()
        # 能量调度 -> 有收益的种子获得更多变异轮次
        self._seed_pool: List[Tuple[bytes, float]] = []
        self._total_selections = 0

    def generate_random(self, min_size: int = 1, max_size: int = 1024) -> bytes:
        size = self.rng.randint(min_size, max_size)
        data = bytes(self.rng.randint(0, 255) for _ in range(size))

        data_hash = hashlib.sha256(data).hexdigest()
        if data_hash in self.generated_hashes:
            return self.generate_random(min_size, max_size)

        self.generated_hashes.add(data_hash)
        return data

    def generate_structured(self, format_type: str) -> bytes:
        generators = {
            'http_request': self._generate_http_request,
            'json_data': self._generate_json_data,
            'xml_data': self._generate_xml_data,
            'binary_header': self._generate_binary_header,
            'network_packet': self._generate_network_packet,
        }

        generator = generators.get(format_type, self.generate_random)
        return generator()

    def _generate_http_request(self) -> bytes:
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        paths = ['/', '/api', '/api/v1', '/api/data', '/admin', '/login']
        headers = ['Content-Type', 'User-Agent', 'Accept', 'Authorization']

        method = self.rng.choice(methods)
        path = self.rng.choice(paths)

        request = f"{method} {path} HTTP/1.1\r\n"
        request += "Host: example.com\r\n"

        for _ in range(self.rng.randint(0, 3)):
            header = self.rng.choice(headers)
            if header == 'Content-Type':
                value = self.rng.choice(['application/json', 'text/plain', 'application/x-www-form-urlencoded'])
            else:
                value = f"Test{random.randint(1000, 9999)}"
            request += f"{header}: {value}\r\n"

        request += "\r\n"

        if method in ['POST', 'PUT', 'PATCH']:
            body_size = self.rng.randint(10, 100)
            body = ''.join(chr(self.rng.randint(32, 126)) for _ in range(body_size))
            request += body

        return request.encode('utf-8')

    def _generate_json_data(self) -> bytes:
        structures = [
            {"key": "value"},
            {"name": "test", "id": 123, "active": True},
            {"array": [1, 2, 3], "nested": {"a": "b"}},
        ]

        data = self.rng.choice(structures)

        for _ in range(self.rng.randint(0, 3)):
            key = f"field_{random.randint(1, 100)}"
            value = self.rng.choice([random.randint(1, 1000), self.rng.random(), self.rng.choice(['value1', 'value2', 'value3']), True, None])
            data[key] = value

        return json.dumps(data).encode('utf-8')

    def _generate_xml_data(self) -> bytes:
        root = self.rng.choice(['root', 'data', 'document'])
        elements = ['item', 'entry', 'record']

        xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<{root}>\n'

        for _ in range(self.rng.randint(1, 5)):
            elem = self.rng.choice(elements)
            value = f"Value{random.randint(1, 1000)}"
            xml += f'  <{elem}><![CDATA[{value}]]></{elem}>\n'

        xml += f'</{root}>\n'
        return xml.encode('utf-8')

    def _generate_binary_header(self) -> bytes:
        header = bytearray()

        magic = self.rng.choice([b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'GIF87a', b'GIF89a', b'PK\x03\x04', b'\x7fELF'])
        header.extend(magic)

        header.extend(bytes(self.rng.randint(0, 255) for _ in range(self.rng.randint(10, 50))))

        return bytes(header)

    def _generate_network_packet(self) -> bytes:
        packet = bytearray()

        packet.append(0x45)

        packet.append(self.rng.randint(0, 255))

        length = self.rng.randint(20, 100)
        packet.extend(struct.pack('>H', length))

        packet.extend(struct.pack('>H', self.rng.randint(1, 65535)))

        packet.extend(struct.pack('>H', 0))

        packet.append(self.rng.randint(1, 255))

        packet.append(self.rng.randint(0, 255))

        packet.extend(struct.pack('>H', 0))

        packet.extend(struct.pack('>BBBB', 192, 168, self.rng.randint(1, 254), self.rng.randint(1, 254)))

        packet.extend(struct.pack('>BBBB', 10, self.rng.randint(0, 255), self.rng.randint(0, 255), self.rng.randint(1, 254)))

        payload_size = length - 20
        packet.extend(bytes(self.rng.randint(0, 255) for _ in range(payload_size)))
        return bytes(packet)

    # ---- 能量调度 ----
    def feed_seed(self, seed: bytes, reward: float = 1.0) -> None:
        """存入种子池。reward>1表示该种子触发了新路径。"""
        self._seed_pool.append((seed, reward))
        # 池过大时淘汰低收益种子
        if len(self._seed_pool) > 512:
            self._seed_pool.sort(key=lambda x: x[1])
            self._seed_pool = self._seed_pool[-256:]

    def pick_seed_by_energy(self) -> bytes:
        """轮盘赌选择: 高收益种子更大概率被选中。"""
        if not self._seed_pool:
            return self.generate_random()
        seeds = [s for s, _ in self._seed_pool]
        weights = [max(0.1, e) for _, e in self._seed_pool]
        total = sum(weights)
        if total <= 0:
            return self.rng.choice(seeds)
        r = self.rng.random() * total
        acc = 0.0
        for s, w in zip(seeds, weights):
            acc += w
            if r <= acc:
                self._total_selections += 1
                return s
        return seeds[-1]

    # ---- 变异操作 ----
    def mutate(self, data: bytes, mutations: int = 3) -> bytes:
        mutation_types = [
            self._mutate_bitflip,
            self._mutate_byteflip,
            self._mutate_arithmetic,
            self._mutate_insert,
            self._mutate_delete,
            self._mutate_overwrite,
            self._mutate_splice,
            self._mutate_interesting,
        ]

        result = bytearray(data)

        for _ in range(mutations):
            mutation = self.rng.choice(mutation_types)
            result = mutation(result)

        return bytes(result)

    def _mutate_bitflip(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            return data

        idx = self.rng.randint(0, len(data) - 1)
        data[idx] ^= (1 << self.rng.randint(0, 7))

        return data

    def _mutate_byteflip(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            return data

        idx = self.rng.randint(0, len(data) - 1)
        data[idx] = self.rng.randint(0, 255)
        return data

    def _mutate_arithmetic(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            return data

        idx = self.rng.randint(0, len(data) - 1)
        delta = self.rng.randint(-10, 10)
        data[idx] = max(0, min(255, data[idx] + delta))

        return data

    def _mutate_insert(self, data: bytearray) -> bytearray:
        pos = self.rng.randint(0, len(data))

        byte = self.rng.randint(0, 255)
        data.insert(pos, byte)
        return data

    def _mutate_delete(self, data: bytearray) -> bytearray:
        if len(data) > 1:
            pos = self.rng.randint(0, len(data) - 1)
            del data[pos]
        return data

    def _mutate_overwrite(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            return data

        pos = self.rng.randint(0, len(data) - 1)
        size = min(self.rng.randint(1, 10), len(data) - pos)

        for i in range(size):
            data[pos + i] = self.rng.randint(0, 255)

        return data

    def _mutate_splice(self, data: bytearray) -> bytearray:
        """从种子池中随机选取一段拼接到当前位置，模拟基因重组。"""
        if len(self._seed_pool) < 1 or len(data) < 2:
            return data
        other = self.rng.choice(self._seed_pool)[0]
        if len(other) < 1:
            return data
        src_start = self.rng.randint(0, len(other) - 1)
        src_len = self.rng.randint(1, min(len(other) - src_start, len(data) // 2))
        dst_pos = self.rng.randint(0, len(data) - 1)
        splice = other[src_start:src_start + src_len]
        data[dst_pos:dst_pos] = splice
        return data

    def _mutate_interesting(self, data: bytearray) -> bytearray:
        """将随机位置替换为已知边界值: 0, -1, INT_MAX, INT_MIN等。"""
        if len(data) == 0:
            return data
        interesting = [
            b'\x00', b'\xff', b'\x7f\xff', b'\x80\x00',
            b'\xff\xff\xff\xff', b'\x00\x00\x00\x00',
            b'\x7f\xff\xff\xff', b'\x80\x00\x00\x00',
        ]
        val = self.rng.choice(interesting)
        pos = self.rng.randint(0, max(0, len(data) - len(val)))
        for i, b in enumerate(val):
            if pos + i < len(data):
                data[pos + i] = b
        return data
