# 为所有 CVE 样本目录生成 Makefile
import os

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE, 'cve_samples')

count = 0
for d in sorted(os.listdir(SAMPLES)):
    dpath = os.path.join(SAMPLES, d)
    if not os.path.isdir(dpath):
        continue
    vuln = os.path.join(dpath, 'vuln.c')
    if not os.path.isfile(vuln):
        continue
    mf = os.path.join(dpath, 'Makefile')
    with open(mf, 'w') as f:
        f.write('CC=gcc\n')
        f.write('CFLAGS=-O0 -g -fno-stack-protector\n')
        f.write('TARGET=vuln\n')
        f.write('\n')
        f.write('all: $(TARGET)\n')
        f.write('\n')
        f.write('$(TARGET): vuln.c\n')
        f.write('\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n')
        f.write('\n')
        f.write('clean:\n')
        f.write('\trm -f $(TARGET)\n')
    count += 1

print(f'{count} Makefiles written')
