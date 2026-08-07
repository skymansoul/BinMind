# 漏洞样本自动编译模块 — 支持 gcc/clang, 多架构, 多优化级别.
# 创建: 2026-06-13

import os, sys, subprocess, glob
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class BuildConfig:
    compiler: str = "gcc"
    arch: str = "x86_64"
    opt_level: str = "O0"
    extra_flags: List[str] = None

    def flags(self) -> List[str]:
        f = [f"-{self.opt_level}", f"-m{self.arch.split('_')[0]}" if "64" in self.arch else "-m32"]
        if self.extra_flags: f.extend(self.extra_flags)
        return f

class SampleBuilder:
    """编译C漏洞样本, 支持批量编译 + 多配置矩阵."""

    DEFAULT_CONFIGS = [
        BuildConfig("gcc", "x86_64", "O0"),
        BuildConfig("gcc", "x86_64", "O2"),
        BuildConfig("clang", "x86_64", "O0"),
    ]

    def __init__(self, samples_dir: str, output_dir: str):
        self._samples = samples_dir
        self._output = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def build_all(self, configs: List[BuildConfig] = None) -> dict:
        if configs is None: configs = self.DEFAULT_CONFIGS
        results = {"built": 0, "failed": 0, "skipped": 0, "binaries": []}
        for sample_dir in sorted(os.listdir(self._samples)):
            sample_path = os.path.join(self._samples, sample_dir)
            if not os.path.isdir(sample_path): continue
            src_files = glob.glob(os.path.join(sample_path, "*.c"))
            if not src_files:
                results["skipped"] += 1; continue
            for cfg in configs:
                out_name = f"{sample_dir}_{cfg.compiler}_{cfg.arch}_{cfg.opt_level}"
                out_path = os.path.join(self._output, out_name)
                ok = self._compile(src_files, out_path, cfg, sample_dir)
                if ok:
                    results["built"] += 1; results["binaries"].append(out_path)
                else:
                    results["failed"] += 1
        return results

    def _compile(self, srcs: List[str], output: str,
                  cfg: BuildConfig, sample_name: str) -> bool:
        cmd = [cfg.compiler] + cfg.flags() + srcs + ["-o", output, "-w"]
        # 需要额外链接的库
        if "openssl" in sample_name.lower():
            cmd.extend(["-lssl", "-lcrypto"])
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

if __name__ == "__main__":
    builder = SampleBuilder(
        os.path.join(os.path.dirname(__file__), "samples"),
        os.path.join(os.path.dirname(__file__), "binaries"))
    results = builder.build_all()
    print(f"Built {results['built']}, failed {results['failed']}, skipped {results['skipped']}")
    for b in results["binaries"]: print(f"  {b}")
