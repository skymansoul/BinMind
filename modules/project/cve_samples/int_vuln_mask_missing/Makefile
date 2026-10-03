CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int_vuln_mask_missing

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
