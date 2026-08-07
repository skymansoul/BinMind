CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -fno-stack-protector -z execstack
TARGET = sample

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
