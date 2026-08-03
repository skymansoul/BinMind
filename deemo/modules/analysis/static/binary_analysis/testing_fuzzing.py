from __future__ import annotations

class TestFuzzer:
    def generate(self, seed: bytes, count: int = 100) -> list[bytes]:
        return [seed + bytes([i % 256]) for i in range(count)]
