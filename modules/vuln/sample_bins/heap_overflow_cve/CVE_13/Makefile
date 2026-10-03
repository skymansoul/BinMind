CC = gcc
CFLAGS = -O0 -g -no-pie -fno-stack-protector
TARGET = vuln_CVE13

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
