CC = x86_64-w64-mingw32-gcc
CFLAGS = -O0 -g -Wall
TARGET = cve_2022_3602.exe
all: $(TARGET)
$(TARGET): poc.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
