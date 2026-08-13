# -*- coding: utf-8 -*-
"""生成 tests/uaf_samples 各目录的 Makefile 与 README.md."""

import os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = '.exe' if sys.platform == 'win32' else '.elf'

NOTES = {
    'uaf_direct': ('UAF-DIRECT', 'free(buf) 后 printf 解引用 buf',
                   '生命周期: free->use 单函数内'),
    'uaf_double_free': ('UAF-DOUBLE-FREE', 'cleanup 主/错误路径各 free 一次',
                        '双重释放: 同指针两次 free'),
    'uaf_struct_field': ('UAF-STRUCT-FIELD',
                         'delete_node 释放 node 后访问 node->id',
                         '释放后经结构体字段访问'),
    'uaf_realloc_path': ('UAF-REALLOC-PATH',
                         'realloc 移动后 old 指向旧块仍被 strcpy',
                         'realloc 搬运后旧指针使用'),
    'uaf_safe_reinit': ('SAFE-REINIT', 'free(p) 后 p 重新 malloc 再使用',
                        '安全负例: 指针重新初始化'),
    'uaf_safe_null': ('SAFE-NULL', 'free(p) 后置空并判空再访问',
                      '安全负例: 置空+判空分支'),
}

MF = ('CC ?= gcc\n'
      'CFLAGS ?= -std=c11 -O0 -g -Wall\n'
      'TARGET = {name}{ext}\n'
      'all: $(TARGET)\n'
      '$(TARGET): vuln.c\n'
      '\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n'
      'clean:\n'
      '\trm -f $(TARGET)\n')

README = ('# {name}\n'
          '- CVE/漏洞: {cve}\n'
          '- 触发条件: {trigger}\n'
          '- 为何有效: {why}\n'
          '- 类型: Use-After-Free (CWE-416)\n')


def main():
    for name in sorted(os.listdir(ROOT)):
        sub = os.path.join(ROOT, name)
        if not os.path.isdir(sub):
            continue
        cve, trig, why = NOTES.get(name, (name, '', ''))
        with open(os.path.join(sub, 'Makefile'), 'w', encoding='utf-8') as f:
            f.write(MF.format(name=name, ext=EXT))
        with open(os.path.join(sub, 'README.md'), 'w', encoding='utf-8') as f:
            f.write(README.format(name=name, cve=cve, trigger=trig, why=why))
        print('  %s: Makefile + README' % name)
    print('uaf_samples meta done')


if __name__ == '__main__':
    main()
