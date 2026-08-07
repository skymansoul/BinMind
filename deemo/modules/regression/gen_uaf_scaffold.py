"""
UAF 样本脚手架生成 — Makefile 与 README 批量创建.

决策逻辑:
  samples/uaf 下每个样本目录已有 vuln.c, 本脚本补齐:
    Makefile (gcc -O0, 保留漏洞语义)
    README.md (CVE/触发条件/检测要点)
  已存在文件不覆盖.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
UAF_ROOT = BASE / 'samples' / 'uaf'

MAKEFILE = """CC      = gcc
CFLAGS  = -O0 -fno-stack-protector -fno-pie
TARGET  = vuln.exe

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\tdel /q $(TARGET) 2>nul || rm -f $(TARGET)
"""

DESC = {
    'cve_2017_1000410_timer': ('CVE-2017-1000410', 'ALSA timer UAF',
                               'release_timer 后 use_timer 解引用'),
    'cve_2017_16939_nft': ('CVE-2017-16939', 'nf_tables set UAF',
                           'set 销毁后 rule 仍引用'),
    'cve_2019_2215_binder': ('CVE-2019-2215', 'binder mmap UAF',
                             'mmap 释放后 fd 仍访问'),
    'cve_2020_0041_hidp': ('CVE-2020-0041', 'hidp session UAF',
                           'session 终止后 socket 回调写'),
    'cve_2021_26708_vsock': ('CVE-2021-26708', 'vsock 双锁竞争 UAF',
                             'release 后 pkt 队列仍引用'),
    'cve_2022_2588_cls_route': ('CVE-2022-2588', 'cls_route filter UAF',
                                'filter 释放后链表遍历'),
    'cve_2023_0386_overlayfs': ('CVE-2023-0386', 'overlayfs dentry UAF',
                                'copy_up 释放后 lookup 访问'),
    'cve_2016_6187_apparmor': ('CVE-2016-6187', 'apparmor exec UAF',
                               'exec 完成后 profile 仍访问'),
    'cve_2021_22555_netfilter': ('CVE-2021-22555', 'nf_tables 双引用 UAF',
                                 'set 被两处引用, 释放一次即 UAF'),
    'cve_2022_0847_pipe': ('CVE-2022-0847', 'Dirty Pipe 页缓存 UAF',
                           'splice 后页缓存释放仍写入'),
    'cve_2024_1086_nft': ('CVE-2024-1086', 'nf_tables verdict double-free',
                          'verdict 释放后 data 二次释放'),
    'cve_2023_32233_nft': ('CVE-2023-32233', 'anonymous set 代数 UAF',
                           '匿名 set 销毁后旧代规则引用'),
    'cve_2016_5195_dirtycow': ('CVE-2016-5195', 'Dirty COW 页竞争 UAF',
                               'COW 复制时页释放竞争'),
    'cve_2022_25636_nft': ('CVE-2022-25636', 'nf_tables byteorder UAF',
                           '代数切换后 data 仍被 eval'),
    'safe_01_null_after_free': ('TN', 'free 后置 NULL',
                                '置空 + NULL 检查, 无 UAF'),
    'safe_02_refcount': ('TN', '引用计数正确管理',
                         'refcnt 归零才释放, 无 UAF'),
    'safe_03_no_use': ('TN', '释放后无使用',
                       'free 后作用域结束, 无 UAF'),
}


def gen(name: str) -> None:
    d = UAF_ROOT / name
    if not (d / 'vuln.c').exists():
        return
    mk = d / 'Makefile'
    if not mk.exists():
        mk.write_text(MAKEFILE, encoding='utf-8')
    readme = d / 'README.md'
    if readme.exists():
        return
    info = DESC.get(name, (name, 'UAF 模式', '见源码'))
    readme.write_text(
        f'# {name} — {info[1]}\n\n'
        f'## 概述\n{info[2]}。\n\n'
        f'## CVE / 类别\n{info[0]}\n\n'
        f'## 触发条件\n见 vuln.c 内注释; 编译后直接执行命中漏洞路径。\n\n'
        f'## 检测要点\n'
        f'- free 后指针未被置 NULL\n'
        f'- 释放后存在读/写引用 (UAF)\n'
        f'- 期望: UAF 检出 (或 TN 正确抑制)\n',
        encoding='utf-8')


def main() -> int:
    for d in sorted(UAF_ROOT.iterdir()):
        if d.is_dir():
            gen(d.name)
    print(f'scaffolded {UAF_ROOT}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
