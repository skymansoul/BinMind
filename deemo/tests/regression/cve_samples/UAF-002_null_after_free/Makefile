CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: $(TARGET)
$(TARGET): UAF-002_null_after_free.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET) *.o
