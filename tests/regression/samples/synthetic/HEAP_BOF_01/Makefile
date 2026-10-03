CC := gcc
CFLAGS := -Wall -O0
TARGET := HEAP_BOF_01_default

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

no_mitigation: vuln.c
	$(CC) $(CFLAGS) -fno-stack-protector -z execstack -o HEAP_BOF_01_nomit $<

clean:
	rm -f $(TARGET) HEAP_BOF_01_nomit

.PHONY: all clean no_mitigation
