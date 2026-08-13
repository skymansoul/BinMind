"""
格式化字符串样本脚手架生成 — Makefile 与 README 批量创建.

samples/format_string 下每个样本目录已有 vuln.c, 本脚本补齐:
  Makefile (gcc -O0, 保留漏洞语义)
  README.md (CVE/触发条件/检测要点)
已存在文件不覆盖.
"""

from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
FMT_ROOT = BASE / 'samples' / 'format_string'

MAKEFILE = """CC      = gcc
CFLAGS  = -O0 -fno-stack-protector -fno-pie
TARGET  = vuln.exe

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\tdel /q $(TARGET) 2>nul || rm -f $(TARGET)
"""

DESC = {
    'cve_2015_8612_bluez': ('CVE-2015-8612', 'BlueZ 事件名格式化',
                            'printf(event_name) 用户可控'),
    'cve_2016_9840_zlib': ('CVE-2016-9840', 'zlib 调试格式化',
                           '文件名直接作格式串'),
    'cve_2017_1000369_exim': ('CVE-2017-1000369', 'exim 格式化',
                              'SMTP 头含 %n'),
    'cve_2018_11529_vlc': ('CVE-2018-11529', 'VLC 元数据格式化',
                           '媒体元数据含 % 转换符'),
    'cve_2019_12817_ppc': ('CVE-2019-12817', 'PPC 调试格式化',
                           '调试接口含 %n'),
    'cve_2019_19043_iwl': ('CVE-2019-19043', 'iwlwifi 格式化',
                           'SSID 含 % 转换符'),
    'cve_2020_10757_fuse': ('CVE-2020-10757', 'FUSE 格式化',
                            '挂载路径含 % 转换符'),
    'cve_2020_25656_vt': ('CVE-2020-25656', 'VT 控制台格式化',
                          '终端输入含 %n'),
    'cve_2021_20226_io_uring': ('CVE-2021-20226', 'io_uring 格式化',
                                '注册名含 % 转换符'),
    'cve_2021_33034_usb': ('CVE-2021-33034', 'USB 格式化',
                           '设备序列号含 %n'),
    'cve_2022_0168_cifs': ('CVE-2022-0168', 'CIFS 格式化',
                           'SMB 服务器串含 % 转换符'),
    'cve_2022_26490_ntfs': ('CVE-2022-26490', 'NTFS 格式化',
                            '磁盘卷标含 % 转换符'),
    'cve_2022_32250_nf': ('CVE-2022-32250', 'netfilter 格式化',
                          '规则名含 %n'),
    'cve_2023_27114_r2': ('CVE-2023-27114', 'radare2 格式化',
                          '交互命令含 % 转换符'),
    'cve_2023_34029_kvm': ('CVE-2023-34029', 'KVM 格式化',
                           '虚拟机名含 % 转换符'),
    'safe_01_static_fmt': ('TN', '静态格式串+参数匹配', '无注入面'),
    'safe_02_param_fmt': ('TN', '参数化格式化', 'fmt 无转换符'),
    'safe_03_snprintf': ('TN', 'snprintf 上限', '长度受限+静态串'),
}


def gen(name: str) -> None:
    d = FMT_ROOT / name
    if not (d / 'vuln.c').exists():
        return
    mk = d / 'Makefile'
    if not mk.exists():
        mk.write_text(MAKEFILE, encoding='utf-8')
    readme = d / 'README.md'
    if readme.exists():
        return
    info = DESC.get(name, (name, 'FMT 模式', '见源码'))
    readme.write_text(
        f'# {name} — {info[1]}\n\n'
        f'## 概述\n{info[2]}。\n\n'
        f'## CVE / 类别\n{info[0]}\n\n'
        f'## 触发条件\n见 vuln.c 内注释; 编译后执行命中漏洞路径。\n\n'
        f'## 检测要点\n'
        f'- 格式化参数是否用户可控 (外部输入污点)\n'
        f'- 格式串是否含 %n 或说明符数量 > 实参\n'
        f'- 期望: VULN/LEAK 检出 (或 TN 正确抑制)\n',
        encoding='utf-8')


def main() -> int:
    for d in sorted(FMT_ROOT.iterdir()):
        if d.is_dir():
            gen(d.name)
    print(f'scaffolded {FMT_ROOT}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())