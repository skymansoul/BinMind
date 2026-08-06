# UAF sample — 双目标构建: vuln (回归测试) + sample (对比实验)
CC=gcc
CFLAGS=-O0 -g -fno-stack-protector -no-pie

all: vuln sample

vuln: vuln.c
	$(CC) $(CFLAGS) -o vuln vuln.c

sample: sample.c
	$(CC) $(CFLAGS) -o sample sample.c

clean:
	rm -f vuln sample
