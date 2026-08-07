# 样本编译模块: 自动编译samples/下所有C源文件为ELF
# 决策: 使用subprocess调用gcc而非内联编译, 保持与构建系统的独立性
#   Makefile已定义编译规则, 此模块仅做批量调度
import subprocess, sys, os, json, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CompilationResult:
    sample_dir: str
    success: bool
    binary_path: str = ""
    compile_time_ms: float = 0
    error_msg: str = ""
    binary_size: int = 0


class SampleCompiler:
    """样本批量编译器.

    扫描samples/目录, 对每个包含Makefile的子目录执行make.
    输出编译结果列表.
    """

    def __init__(self, samples_root: str):
        self._root = Path(samples_root)
        self._make = self._detect_make()
        if not self._root.exists():
            raise FileNotFoundError(f"Samples root not found: {samples_root}")

    @staticmethod
    def _detect_make() -> str:
        """探测可用的 make: 优先 make, 回退 mingw32-make (Windows)."""
        import shutil
        for cand in ("make", "mingw32-make", "gmake"):
            if shutil.which(cand):
                return cand
        return "make"

    def discover_samples(self) -> List[Path]:
        """发现所有包含Makefile的样本目录, 按名称排序."""
        dirs = sorted(
            [d for d in self._root.iterdir()
             if d.is_dir() and (d / "Makefile").exists()],
            key=lambda d: d.name)
        return dirs

    def compile_one(self, sample_dir: Path) -> CompilationResult:
        """编译单个样本."""
        t0 = time.perf_counter()
        try:
            result = subprocess.run(
                [self._make, "-C", str(sample_dir), "all"],
                capture_output=True, text=True,
                timeout=30,
                env={**os.environ, "CFLAGS": "-g -O0 -fno-stack-protector"})
            elapsed = (time.perf_counter() - t0) * 1000
            if result.returncode != 0:
                return CompilationResult(
                    sample_dir=sample_dir.name, success=False,
                    compile_time_ms=elapsed,
                    error_msg=result.stderr[:500])
            # 检测生成的二进制文件
            binary = self._find_binary(sample_dir)
            if binary is None:
                return CompilationResult(
                    sample_dir=sample_dir.name, success=False,
                    compile_time_ms=elapsed,
                    error_msg="make成功但未找到二进制文件")
            bin_size = binary.stat().st_size if binary else 0
            return CompilationResult(
                sample_dir=sample_dir.name, success=True,
                binary_path=str(binary), compile_time_ms=elapsed,
                binary_size=bin_size)
        except subprocess.TimeoutExpired:
            elapsed = (time.perf_counter() - t0) * 1000
            return CompilationResult(
                sample_dir=sample_dir.name, success=False,
                compile_time_ms=elapsed, error_msg="编译超时(30s)")
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return CompilationResult(
                sample_dir=sample_dir.name, success=False,
                compile_time_ms=elapsed, error_msg=str(e))

    def compile_all(self) -> List[CompilationResult]:
        """编译所有样本, 返回结果列表."""
        dirs = self.discover_samples()
        results = []
        for d in dirs:
            result = self.compile_one(d)
            results.append(result)
            status = "OK" if result.success else "FAIL"
            print(f"  [{status}] {result.sample_dir} "
                  f"({result.compile_time_ms:.0f}ms)")
            if not result.success:
                print(f"    Error: {result.error_msg[:120]}")
        return results

    def _find_binary(self, dir_path: Path) -> Optional[Path]:
        """在目录中查找编译生成的ELF二进制."""
        # 先找Makefile中TARGET定义
        target = "demo"  # 默认
        makefile = dir_path / "Makefile"
        if makefile.exists():
            content = makefile.read_text()
            for line in content.split('\n'):
                if line.strip().startswith('TARGET='):
                    target = line.split('=')[1].strip()
                    break
        # Windows 下 gcc 会追加 .exe 后缀
        for cand_name in (target, target + '.exe'):
            candidate = dir_path / cand_name
            if candidate.exists() and candidate.stat().st_size > 0:
                return candidate
        # 备选: 查找任何可执行文件 (排除源码/文档/中间文件)
        _EXCLUDE_SUFFIX = {'.c', '.h', '.md', '.txt', '.o', '.obj'}
        _EXCLUDE_NAMES = {'Makefile', 'README.md', 'main.c'}
        for f in dir_path.iterdir():
            if f.name in _EXCLUDE_NAMES:
                continue
            if f.suffix in _EXCLUDE_SUFFIX:
                continue
            if f.stat().st_size < 512:
                continue  # 源码/文档通常小于 512B, 排除误判
            if os.access(str(f), os.X_OK):
                return f
        return None

    def summary(self, results: List[CompilationResult]) -> Dict:
        ok = sum(1 for r in results if r.success)
        total_time = sum(r.compile_time_ms for r in results)
        return {
            "total": len(results), "success": ok,
            "failed": len(results) - ok,
            "total_compile_time_ms": total_time,
            "success_rate": f"{ok}/{len(results)}",
        }
