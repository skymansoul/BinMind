# TP_uaf_clear_violation — 明确Use-After-Free (真阳性)
#
# 场景: free(p)后继续使用*p, 无任何保护
# 预期: UAF检测器应检出

CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(TARGET).exe
