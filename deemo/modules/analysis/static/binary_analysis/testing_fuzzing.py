from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


class TestFuzzer:
    def generate(self, seed: bytes, count: int = 100) -> list[bytes]:
        return [seed + bytes([i % 256]) for i in range(count)]


@dataclass
class FuzzerConfig:
    """模糊测试运行参数。"""
    timeout: int = 60
    max_len: int = 4096
    max_total_time: int = 600
    corpus_dir: str = ""
    seed_dir: str = ""


class AFLHarnessGen:
    """生成目标函数的 AFL 插桩 harness 模板。"""

    _TEMPLATE = (
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "#include <unistd.h>\n\n"
        "int main(void) {{\n"
        "    uint8_t buf[{max_len}];\n"
        "    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));\n"
        "    if (n < 0) return 1;\n"
        "    target_func(buf, (size_t)n);\n"
        "    return 0;\n"
        "}}\n"
    )

    def generate(self, target_type: str = "file_parser",
                 max_len: int = 4096) -> str:
        """按目标类型生成 harness 源码字符串。"""
        return self._TEMPLATE.format(max_len=max_len)


class LibFuzzerRunner:
    """libFuzzer 运行器封装：组装命令行并执行。"""

    def __init__(self, target_binary: str, config: Optional[FuzzerConfig] = None):
        self.target_binary = target_binary
        self.config = config if config is not None else FuzzerConfig()

    def build_command(self, corpus_dir: str, extra_args: Optional[List[str]] = None) -> List[str]:
        cmd = [self.target_binary]
        if corpus_dir:
            cmd.append(corpus_dir)
        cmd.append(f"-timeout={self.config.timeout}")
        cmd.append(f"-max_len={self.config.max_len}")
        cmd.extend(extra_args or [])
        return cmd

    def run(self, corpus_dir: str = "", extra_args: Optional[List[str]] = None) -> int:
        """同步运行 fuzzer，返回退出码。"""
        import subprocess
        cmd = self.build_command(corpus_dir, extra_args)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.max_total_time)
        return proc.returncode
