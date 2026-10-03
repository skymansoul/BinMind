# coding: utf-8
"""生成 cve_samples_packed 各目录的 Makefile 与 README.md."""

import os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = '.exe' if sys.platform == 'win32' else '.elf'

NOTES = {
    'CVE-2020-29370_packed': ('CVE-2020-29370', '用户可控长度无边界检查', 'True'),
    'CVE-2021-3156_packed': ('CVE-2021-3156', '分配与写入长度变量不一致', 'True'),
    'safe_01_packed': ('SAFE-01', 'malloc(256) >= memcpy(128)', 'False'),
    'fp_internal_copy_packed': ('SAFE-INTERNAL', '双侧内部常量不可控', 'False'),
}

MF = ('CC ?= gcc\n'
      'CFLAGS ?= -std=c11 -O0 -s -Wall\n'
      'TARGET = {name}{ext}\n'
      'all: $(TARGET)\n'
      '$(TARGET): vuln.c\n'
      '\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n'
      'clean:\n'
      '\trm -f $(TARGET)\n')

README = ('# {name}\n'
          '- CVE: {cve}\n'
          '- heap_overflow: {vuln}\n'
          '- 触发条件: {trigger}\n'
          '- 加壳方式: `-s` 剥离符号 (验证不依赖调试信息)\n')


def main():
    for name in os.listdir(ROOT):
        sub = os.path.join(ROOT, name)
        if not os.path.isdir(sub):
            continue
        cve, trig, vuln = NOTES.get(name, (name, 'stripped 变体', '?'))
        with open(os.path.join(sub, 'Makefile'), 'w', encoding='utf-8') as f:
            f.write(MF.format(name=name, ext=EXT))
        with open(os.path.join(sub, 'README.md'), 'w', encoding='utf-8') as f:
            f.write(README.format(name=name, cve=cve, vuln=vuln,
                                  trigger=trig))
        print(f'  {name}: Makefile + README.md')
    print('packed meta done')


if __name__ == '__main__':
    main()
