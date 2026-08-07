CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = df_cve_06

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)
