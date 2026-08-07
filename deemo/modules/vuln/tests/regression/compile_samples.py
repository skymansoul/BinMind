"""样本编译模块 — 自动发现并编译 C 漏洞样本为 ELF.

用法: python compile_samples.py <samples_dir> <output_dir>
  或作为库: from compile_samples import compile_all; compile_all(...)

编译策略:
  - x86_64: gcc -m64 -O0 -fno-stack-protector -z execstack -no-pie
  - 同时生成未加壳 (plain) 和 UPX 加壳 (packed) 版本
  - 保留调试符号 (-g) 以辅助 ground truth 标注
"""

import os
import sys
import subprocess
import json
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Sample:
    """一个 CVE 样本的编译信息."""
    sample_id: str              # 目录名
    cve_id: str                 # CVE 编号
    source_files: List[str]     # 源文件路径
    makefile_path: str          # Makefile 路径
    description: str = ""
    vuln_type: str = "heap_overflow"
    # 编译产物
    elf_plain: str = ""         # 未加壳 ELF 路径
    elf_packed: str = ""        # UPX 加壳 ELF 路径
    compiled: bool = False
    error: str = ""


class SampleCompiler:
    """编译所有 C 漏洞样本."""

    TOOLCHAIN = {
        'cc': 'gcc',
        # -z execstack 是 ELF linker flag, PE/MinGW 不识别; 用 -Wl,--disable-nxcompat 替代
        'cflags': ['-m64', '-O0', '-g', '-fno-stack-protector',
                   '-no-pie', '-Wno-implicit-function-declaration'],
    }

    def __init__(self, samples_dir: str, output_dir: str):
        self._samples_dir = os.path.abspath(samples_dir)
        self._output_dir = os.path.abspath(output_dir)
        self._samples: List[Sample] = []

    def discover(self) -> List[Sample]:
        """扫描 samples_dir, 发现所有包含 Makefile 的子目录."""
        self._samples = []
        if not os.path.isdir(self._samples_dir):
            print(f"[!] Samples directory not found: {self._samples_dir}")
            return []

        for entry in sorted(os.listdir(self._samples_dir)):
            subdir = os.path.join(self._samples_dir, entry)
            if not os.path.isdir(subdir):
                continue

            makefile = os.path.join(subdir, 'Makefile')
            if not os.path.isfile(makefile):
                # 无 Makefile: 尝试自动发现 .c 文件
                sources = [os.path.join(subdir, f)
                          for f in os.listdir(subdir)
                          if f.endswith('.c')]
                if sources:
                    makefile = ''  # 后续用内置编译
                else:
                    continue

            # 读取 README 获取 CVE 信息
            readme = os.path.join(subdir, 'README.md')
            cve_id = entry
            desc = ""
            if os.path.isfile(readme):
                with open(readme, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # 提取 CVE 编号
                    import re
                    m = re.search(r'CVE-\d{4}-\d{4,}', content)
                    if m:
                        cve_id = m.group(0)
                    desc = content.split('\n')[0].lstrip('#').strip()[:120] if content else ""

            sources = [os.path.join(subdir, f)
                      for f in os.listdir(subdir) if f.endswith('.c')]

            self._samples.append(Sample(
                sample_id=entry,
                cve_id=cve_id,
                source_files=sources,
                makefile_path=makefile,
                description=desc,
                vuln_type='heap_overflow',
            ))

        print(f"[+] Discovered {len(self._samples)} samples")
        return self._samples

    def compile_all(self) -> Dict[str, Sample]:
        """编译所有已发现的样本, 返回 {sample_id: Sample}.

        编译策略: 优先用 Makefile; make 不可用或失败时回退到直接 gcc.
        """
        result = {}
        os.makedirs(self._output_dir, exist_ok=True)

        for s in self._samples:
            print(f"  compiling {s.sample_id} ({s.cve_id}) ...")
            plain_dir = os.path.join(self._output_dir, s.sample_id, 'plain')
            packed_dir = os.path.join(self._output_dir, s.sample_id, 'packed')
            os.makedirs(plain_dir, exist_ok=True)
            os.makedirs(packed_dir, exist_ok=True)

            compiled = False

            # 方式1: 使用样本自带的 Makefile
            if s.makefile_path and os.path.isfile(s.makefile_path):
                rc = self._run_make(s.makefile_path, plain_dir, 'plain')
                if rc == 0:
                    s.elf_plain = self._find_elf(plain_dir)
                    if s.elf_plain:
                        compiled = True
                    else:
                        print(f"    [i] make succeeded but no ELF found, falling back to gcc")
                else:
                    print(f"    [i] make failed (rc={rc}), falling back to gcc")

            # 方式2/回退: 直接编译 .c 文件 (make 不可用或失败时)
            if not compiled and s.source_files:
                elf_out = os.path.join(plain_dir, f'{s.sample_id}.exe')
                # 在 Windows 上添加 .exe 后缀
                ext = '.exe' if os.name == 'nt' else ''
                elf_out = os.path.join(plain_dir, f'{s.sample_id}{ext}')
                rc = self._compile_sources(s.source_files, elf_out)
                if rc == 0:
                    s.elf_plain = elf_out
                    compiled = True

            # packed variant
            if compiled and s.elf_plain:
                s.compiled = True
                packed_ext = '.exe' if os.name == 'nt' else ''
                packed_elf = os.path.join(packed_dir, f'{s.sample_id}_packed{packed_ext}')
                if self._pack_with_upx(s.elf_plain, packed_elf):
                    s.elf_packed = packed_elf

            if not compiled:
                s.error = f"Failed to compile {s.sample_id}"

            result[s.sample_id] = s

        # 输出 manifest
        self._write_manifest(result)
        return result

    def _compile_sources(self, sources: List[str], output: str) -> int:
        """直接编译 C 源码."""
        cmd = [self.TOOLCHAIN['cc']] + self.TOOLCHAIN['cflags'] + sources + ['-o', output]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=60,
                                  encoding='utf-8', errors='ignore')
            if proc.returncode != 0:
                print(f"    [!] gcc error: {proc.stderr[:200]}")
            return proc.returncode
        except Exception as e:
            print(f"    [!] Exception: {e}")
            return -1

    def _run_make(self, makefile: str, output_dir: str, target: str) -> int:
        """在样本目录中运行 make."""
        workdir = os.path.dirname(makefile)
        env = os.environ.copy()
        env['OUTDIR'] = output_dir
        try:
            proc = subprocess.run(
                ['make', '-f', os.path.basename(makefile), target],
                cwd=workdir, env=env, capture_output=True, timeout=120,
                encoding='utf-8', errors='ignore')
            return proc.returncode
        except Exception as e:
            print(f"    [!] make error: {e}")
            return -1

    @staticmethod
    def _find_elf(dirpath: str) -> str:
        """在目录中查找可执行文件 (ELF 或 PE)."""
        for f in os.listdir(dirpath):
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp) and os.access(fp, os.X_OK):
                try:
                    with open(fp, 'rb') as fh:
                        magic = fh.read(4)
                        # ELF: \x7fELF  or  PE: MZ
                        if magic[:2] == b'MZ' or magic == b'\x7fELF':
                            return fp
                except Exception:
                    pass
        # 放宽: 任何可执行文件
        for f in os.listdir(dirpath):
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp) and (f.endswith('.exe') or f.endswith('.elf')):
                return fp
        return ""

    @staticmethod
    def _pack_with_upx(elf_path: str, output_path: str) -> bool:
        """用 UPX 加壳."""
        if not elf_path or not os.path.isfile(elf_path):
            return False
        try:
            # 复制原始文件再压缩
            shutil.copy2(elf_path, output_path)
            proc = subprocess.run(
                ['upx', '-q', '-o', output_path, elf_path],
                capture_output=True, text=True, timeout=60)
            return proc.returncode == 0
        except FileNotFoundError:
            print("    [i] UPX not found, skipping packed variant")
            return False
        except Exception:
            return False

    def _write_manifest(self, samples: Dict[str, Sample]) -> None:
        """输出编译清单 JSON."""
        manifest = {}
        for sid, s in samples.items():
            manifest[sid] = {
                'sample_id': s.sample_id,
                'cve_id': s.cve_id,
                'vuln_type': s.vuln_type,
                'description': s.description,
                'elf_plain': s.elf_plain,
                'elf_packed': s.elf_packed,
                'compiled': s.compiled,
                'error': s.error,
            }
        path = os.path.join(self._output_dir, 'manifest.json')
        with open(path, 'w') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        print(f"[+] Manifest written to {path}")

    def summary(self) -> str:
        """编译结果摘要."""
        n_total = len(self._samples)
        n_ok = sum(1 for s in self._samples if s.compiled)
        n_packed = sum(1 for s in self._samples if s.elf_packed)
        lines = [
            f"=== Compilation Summary ===",
            f"  Total samples: {n_total}",
            f"  Compiled OK:   {n_ok}",
            f"  Packed (UPX):  {n_packed}",
            f"  Failed:        {n_total - n_ok}",
        ]
        for s in self._samples:
            if not s.compiled:
                lines.append(f"    FAIL: {s.sample_id} — {s.error}")
        return '\n'.join(lines)


# CLI
if __name__ == '__main__':
    samples_dir = sys.argv[1] if len(sys.argv) > 1 else '../samples'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else '../build'
    compiler = SampleCompiler(samples_dir, output_dir)
    compiler.discover()
    compiler.compile_all()
    print(compiler.summary())
