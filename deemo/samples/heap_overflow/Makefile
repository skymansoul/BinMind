# 统一编译所有堆溢出样本
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -fno-stack-protector -z execstack
SAMPLES = $(wildcard sample_*)

.PHONY: all clean $(SAMPLES)

all: $(SAMPLES)

sample_%:
	@echo "[BUILD] $@"
	@if [ -f $@/$@.c ]; then \
		$(CC) $(CFLAGS) -o $@/$@ $@/$@.c 2>&1 || echo "[SKIP] $@ compile failed"; \
	fi
	@if [ -f $@/$@.c ] && grep -q "int main" $@/$@.c; then \
		echo "[OK] $@ compiled"; \
	fi

clean:
	@for d in $(SAMPLES); do \
		if [ -f $$d/$$d ]; then rm -f $$d/$$d; echo "[CLEAN] $$d/$$d"; fi; \
	done

list:
	@for d in $(SAMPLES); do \
		if [ -f $$d/README.md ]; then \
			head -3 $$d/README.md | tr '\n' ' '; echo; \
		fi; \
	done
