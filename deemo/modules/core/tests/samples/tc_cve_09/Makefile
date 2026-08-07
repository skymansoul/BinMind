CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = tc_cve_09

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)
