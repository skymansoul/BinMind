# smaller_memmove — FP07
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
# O2 档保留漏洞逻辑: 禁用死代码消除/存储消除/内联/builtin展开,
# 防止未使用结果的示例代码被整体优化掉 (真实工程结果均为已用)。
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/smaller_memmove.exe
packed: bin/packed/smaller_memmove.exe

bin/plain/smaller_memmove.exe: smaller_memmove.c
	$ $(CFLAGS_O0) smaller_memmove.c -o $@

bin/packed/smaller_memmove.exe: smaller_memmove.c
	$ $(CFLAGS_O2) smaller_memmove.c -o $@

clean:
	rm -rf bin
