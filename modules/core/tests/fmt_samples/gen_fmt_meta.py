# -*- coding: utf-8 -*-
"""生成 tests/fmt_samples 各目录的 Makefile 与 README.md."""

import os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = '.exe' if sys.platform == 'win32' else '.elf'

NOTES = {
    'fmt_vuln_user': ('FMT-USER', 'printf(user_input) 直接使用外部参数为格式串',
                      '用户可控格式串 (CWE-134)'),
    'fmt_vuln_pctn': ('FMT-PCTN', 'printf("...%n", &x) 常量串含写说明符',
                      '%n 写说明符 -> 任意写原语'),
    'fmt_safe_const': ('SAFE-CONST', 'printf("hello %d", x) 编译期常量格式串',
                       '常量无 %n, 无写说明符'),
    'fmt_safe_string': ('SAFE-STRING', 'printf("val=%s", argv[1]) 用户数据经参数',
                        '用户数据作为 %s 参数, 非格式串'),
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
          '- 类型: Format String (CWE-134)\n')


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
    print('fmt_samples meta done')


if __name__ == '__main__':
    main()
