# coding: utf-8
#
"""
批量编译CVE样本-每个样本独立目录含源码+编译脚本+漏洞说明。
输出统一的可执行ELF到build/子目录，供扫描器消费。
"""

import os
import sys
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SampleMeta:
    cve_id: str
    vuln_type: str            # heap_overflow / uaf / format_string / ...
    source_file: str
    binary_path: str = ""
    compile_success: bool = False
    compile_error: str = ""
    expected_vulnerable: bool = True


def find_samples(samples_root: str) -> List[str]:
    """扫描samples_root目录，返回所有包含Makefile/build.sh的样本目录。"""
    dirs = []
    for entry in sorted(os.listdir(samples_root)):
        full = os.path.join(samples_root, entry)
        if not os.path.isdir(full):
            continue
        has_src = any(f.endswith('.c') for f in os.listdir(full))
        has_build = any(f in ('Makefile', 'build.sh', 'compile.sh')
                        for f in os.listdir(full))
        if has_src and has_build:
            dirs.append(full)
    return dirs


def compile_sample(sample_dir: str, build_dir: str,
                    compiler: str = "gcc") -> SampleMeta:
    """编译单个CVE样本-尝试Makefile，回退到直接gcc编译。

    返回SampleMeta含编译状态。
    """
    os.makedirs(build_dir, exist_ok=True)

    # 读取meta.json获取CVE信息
    meta_path = os.path.join(sample_dir, 'meta.json')
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            meta = json.load(f)

    cve_id = meta.get('cve_id', os.path.basename(sample_dir))
    vuln_type = meta.get('vuln_type', 'unknown')

    # 查找源码
    src_files = [f for f in os.listdir(sample_dir) if f.endswith('.c')]
    if not src_files:
        return SampleMeta(cve_id=cve_id, vuln_type=vuln_type,
                           source_file='', compile_error='无C源文件')

    src_file = os.path.join(sample_dir, src_files[0])
    out_name = os.path.basename(sample_dir)
    out_path = os.path.join(build_dir, out_name)

    # 尝试Makefile
    makefile = os.path.join(sample_dir, 'Makefile')
    build_sh = os.path.join(sample_dir, 'build.sh')

    try:
        if os.path.exists(makefile):
            subprocess.run(['make', '-C', sample_dir,
                            f'OUTPUT={out_path}'],
                           capture_output=True, text=True, timeout=30)
        elif os.path.exists(build_sh):
            subprocess.run(['bash', build_sh, out_path],
                           capture_output=True, text=True, timeout=30)
        else:
            cmd = [compiler, '-g', '-O0', '-o', out_path, src_file,
                   '-fno-stack-protector', '-z', 'execstack',
                   '-no-pie', '-Wno-deprecated-declarations']
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return SampleMeta(cve_id=cve_id, vuln_type=vuln_type,
                           source_file=src_file,
                           compile_error='编译超时(30s)')

    if os.path.exists(out_path):
        return SampleMeta(cve_id=cve_id, vuln_type=vuln_type,
                           source_file=src_file, binary_path=out_path,
                           compile_success=True,
                           expected_vulnerable=meta.get('expected_vulnerable', True))

    return SampleMeta(cve_id=cve_id, vuln_type=vuln_type,
                       source_file=src_file,
                       compile_error='编译失败(输出文件不存在)')


def compile_all(samples_root: str, build_dir: str,
                 compiler: str = "gcc") -> List[SampleMeta]:
    """批量编译所有CVE样本——返回SampleMeta列表。"""
    samples = find_samples(samples_root)
    if not samples:
        print(f"[WARN] 无样本目录: {samples_root}")
        return []

    results = []
    for sd in samples:
        meta = compile_sample(sd, build_dir, compiler)
        results.append(meta)
        status = "OK" if meta.compile_success else f"FAIL: {meta.compile_error}"
        print(f"  [{meta.cve_id}] {status}")

    ok_count = sum(1 for r in results if r.compile_success)
    print(f"\n编译完成: {ok_count}/{len(results)} 成功")
    return results


if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else 'tests/cve_samples'
    out = sys.argv[2] if len(sys.argv) > 2 else 'tests/build'
    compile_all(root, out)
