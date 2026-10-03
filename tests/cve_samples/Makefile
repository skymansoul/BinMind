# 批量编译所有 CVE 堆溢出样本
CC = gcc
CFLAGS = -fno-stack-protector -z execstack -no-pie -g -O0
TARGET_DIR = ../cve_binaries

SOURCES = $(wildcard */vuln.c)
TARGETS = $(patsubst %/vuln.c,$(TARGET_DIR)/%.elf,$(SOURCES))

all: $(TARGET_DIR) $(TARGETS)

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(TARGET_DIR)/%.elf: %/vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(TARGET_DIR)

.PHONY: all clean
