"""格式化字符串漏洞测试样本生成器 — 从 fmt_sample_data.py 读取样本数据并生成文件.

创建: 2024-11-05
用途: 读取 FMT_SAMPLES 数据列表, 为每个样本创建独立目录含 main.c + Makefile + README.
      使用: python gen_fmt_samples.py [output_dir]
"""

import sys
from pathlib import Path
from .fmt_sample_data import FMT_SAMPLES

_OUT = Path(__file__).resolve().parent / 'fmt_samples'


def _write_sample(out_dir: Path, sample: dict) -> None:
    d = out_dir / sample['id']
    d.mkdir(parents=True, exist_ok=True)
    (d / 'main.c').write_text(sample['code'], encoding='utf-8')
    makefile = ('CC := gcc\nCFLAGS := -Wall -Wextra -g -O0\n'
                'TARGET := main\n\nall: $(TARGET)\n\n'
                '$(TARGET): main.c\n\t$(CC) $(CFLAGS) -o $(TARGET) main.c\n\n'
                'clean:\n\trm -f $(TARGET)\n')
    (d / 'Makefile').write_text(makefile, encoding='utf-8')
    readme = (f"# {sample['title']}\n## Pattern: {sample['pattern']}\n"
              f"## Expected: {sample['expected']}\n"
              f"## Trigger: {sample['trigger']}\n"
              f"## Build: make && ./main\n")
    (d / 'README.md').write_text(readme, encoding='utf-8')


def generate(output_dir: str = None) -> Path:
    out = Path(output_dir or _OUT)
    out.mkdir(parents=True, exist_ok=True)
    for s in FMT_SAMPLES:
        _write_sample(out, s)
    tp = sum(1 for s in FMT_SAMPLES if s['expected'] == 'TP')
    tn = sum(1 for s in FMT_SAMPLES if s['expected'] == 'TN')
    print(f'Generated {len(FMT_SAMPLES)} fmt samples in {out}  TP={tp} TN={tn}')
    return out


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else None
    generate(out_dir)
