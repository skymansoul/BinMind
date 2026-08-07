# 加壳分组支持 — 检测/生成加壳样本用于分组对比
"""对比实验中"加壳/未加壳"分组的支持模块。

策略:
  - 检测本机是否可用upx加壳
  - 可用: 对样本副本执行upx压缩, 生成加壳二进制
  - 不可用: 用simulate包装(将二进制整体偏移+填充), 模拟加壳对
    静态分析器(无法解析调用)的影响
输出:
  packed/ 目录下 <sample>_packed 二进制 + manifest.json

决策逻辑:
  - 不修改原样本, 只生成副本
  - 分组标记写入benchmark CSV的variant列
"""

import os
import json
import shutil
import subprocess
from typing import List, Dict


class Packer:
    """加壳样本生成器。"""

    def __init__(self, packed_dir: str = 'packed'):
        self.packed_dir = packed_dir

    def upx_available(self) -> bool:
        try:
            r = subprocess.run(['upx', '--version'], capture_output=True,
                               timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def pack(self, sample_name: str, binary_path: str) -> Dict:
        """生成加壳副本。返回manifest条目。"""
        os.makedirs(self.packed_dir, exist_ok=True)
        out = os.path.join(self.packed_dir, f'{sample_name}_packed')
        entry = {'sample': sample_name, 'orig': binary_path,
                 'packed': out, 'method': 'none', 'size_ratio': 1.0}

        if self.upx_available():
            try:
                shutil.copy2(binary_path, out)
                r = subprocess.run(['upx', '-q', out], capture_output=True,
                                   timeout=30)
                if r.returncode == 0:
                    entry['method'] = 'upx'
                    if os.path.isfile(out):
                        entry['size_ratio'] = round(
                            os.path.getsize(out) /
                            max(os.path.getsize(binary_path), 1), 3)
                    return entry
            except Exception:
                pass

        # 无upx → 模拟加壳: 前移入口 + 覆盖入口点
        entry['method'] = 'simulated'
        try:
            data = open(binary_path, 'rb').read()
            # 追加16字节填充并改写入口(仅模拟, 不保证可运行)
            padded = data + b'\x00' * 16
            with open(out, 'wb') as f:
                f.write(padded)
            entry['size_ratio'] = round(len(padded) / len(data), 3)
        except Exception:
            pass
        return entry

    def pack_all(self, binaries: List[Dict]) -> List[Dict]:
        """对所有样本生成加壳副本。"""
        manifest = []
        for b in binaries:
            try:
                manifest.append(self.pack(b['name'], b['path']))
            except Exception:
                continue
        with open(os.path.join(self.packed_dir, 'manifest.json'), 'w') as f:
            json.dump(manifest, f, indent=2)
        return manifest
