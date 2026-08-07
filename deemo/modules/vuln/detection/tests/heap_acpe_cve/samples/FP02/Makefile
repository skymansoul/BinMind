# clamp_guard_copy — FP02
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
# O2 档保留漏洞逻辑: 禁用死代码消除/存储消除/内联/builtin展开,
# 防止未使用结果的示例代码被整体优化掉 (真实工程结果均为已用)。
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/clamp_guard_copy.exe
packed: bin/packed/clamp_guard_copy.exe

bin/plain/clamp_guard_copy.exe: clamp_guard_copy.c
	$ $(CFLAGS_O0) clamp_guard_copy.c -o $@

bin/packed/clamp_guard_copy.exe: clamp_guard_copy.c
	$ $(CFLAGS_O2) clamp_guard_copy.c -o $@

clean:
	rm -rf bin
