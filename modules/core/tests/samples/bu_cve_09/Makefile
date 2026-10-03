CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = bu_cve_09

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)
