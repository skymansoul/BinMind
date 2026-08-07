CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	$(RM) $(TARGET)
