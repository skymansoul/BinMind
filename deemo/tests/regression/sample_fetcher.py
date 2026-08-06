"""
从公开仓库获取已知漏洞样本。

来源:
  mfuchs1984/vulntest — bof/strcpy/format_string/UAF/double_free
  ayeshay1144/memory-exploitation-c-attacks — bo.c (栈溢出) + fs.c (fmt)
  hardik05/Damn_Vulnerable_C_Program — OOB/UAF/堆溢出
"""

import os
import subprocess
import shutil
import hashlib
import urllib.request
from typing import List, Dict

_REPOS: List[Dict] = [
    {
        'url': 'https://raw.githubusercontent.com/mfuchs1984/vulntest/main',
        'files': ['bof.c', 'strcpy.c', 'use_after_free.c', 'double_free.cpp'],
        'dest_dir': 'cve_samples',
    },
    {
        'url': 'https://raw.githubusercontent.com/ayeshay1144/memory-exploitation-c-attacks/main',
        'files': ['bo.c', 'fs.c'],
        'dest_dir': 'cve_samples',
    },
]

_SAMPLE_DIR = os.path.join(os.path.dirname(__file__), 'samples')


def fetch_samples() -> Dict[str, List[str]]:
    """
    从 GitHub raw URL 下载公开样本。

    返回 {repo_name: [local_paths]} 映射。
    """
    fetched: Dict[str, List[str]] = {}
    os.makedirs(_SAMPLE_DIR, exist_ok=True)

    for repo in _REPOS:
        repo_name = repo['url'].split('/')[-2] + '_' + repo['url'].split('/')[-1]
        dest = os.path.join(_SAMPLE_DIR, repo['dest_dir'], repo_name)
        os.makedirs(dest, exist_ok=True)
        fetched[repo_name] = []

        for fname in repo['files']:
            file_url = f"{repo['url']}/{fname}"
            local_path = os.path.join(dest, fname)
            try:
                _download(file_url, local_path)
                fetched[repo_name].append(local_path)
            except Exception as e:
                print(f"  [SKIP] {fname}: {str(e)[:60]}")
        print(f"  [{repo_name}] {len(fetched[repo_name])} files")
    return fetched


def _download(url: str, dest: str) -> None:
    """下载文件到本地, 若已存在且未变更则跳过。"""
    if os.path.exists(dest):
        with open(dest, 'rb') as f:
            existing_hash = hashlib.md5(f.read()).hexdigest()
    else:
        existing_hash = None

    req = urllib.request.Request(url, headers={'User-Agent': 'BinMind/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()

    new_hash = hashlib.md5(data).hexdigest()
    if existing_hash == new_hash:
        return  # 未变更, 跳过

    with open(dest, 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    print("Fetching samples...")
    result = fetch_samples()
    total = sum(len(v) for v in result.values())
    print(f"Done: {total} files from {len(result)} repos")
