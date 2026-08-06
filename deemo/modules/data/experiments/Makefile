# 横向对比实验 Makefile — 一键运行全部对比
# 用法: make all (编译+扫描+对比+画图)
#       make clean (清理输出)

SHELL := /bin/bash
ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
REG_DIR := $(ROOT)/../tests/regression
OUT_DIR := $(ROOT)/output

.PHONY: all build scan compare plot clean

all: build scan compare plot
	@echo "=== All experiments complete ==="
	@echo "Results: $(OUT_DIR)/"

build:
	@echo "--- Building CVE samples ---"
	cd $(REG_DIR) && python build_samples.py

scan:
	@echo "--- Running our scanner ---"
	cd $(REG_DIR) && python scan_runner.py

compare:
	@echo "--- Running cross-tool comparison ---"
	mkdir -p $(OUT_DIR)
	python $(ROOT)/compare_runner.py

plot:
	@echo "--- Generating charts ---"
	python $(ROOT)/plot_results.py

angr-only:
	@echo "--- Angr comparison only ---"
	for bin in $(REG_DIR)/binaries/*; do \
		echo "Angr on $$bin"; \
		python $(ROOT)/angr_adapter.py "$$bin" 2>/dev/null || echo '{"error":"angr_failed"}'; \
	done

qemu-only:
	@echo "--- QEMU comparison only ---"
	for bin in $(REG_DIR)/binaries/*; do \
		echo "QEMU on $$bin"; \
		python $(ROOT)/qemu_adapter.py "$$bin" 2>/dev/null || echo '{"error":"qemu_failed"}'; \
	done

clean:
	rm -rf $(OUT_DIR) $(REG_DIR)/binaries
	@echo "Cleaned output and binaries"
