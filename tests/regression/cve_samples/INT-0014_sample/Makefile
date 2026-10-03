CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: $(TARGET)
$(TARGET): INT-0014_sample.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET) *.o
