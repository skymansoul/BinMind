CC = gcc
CFLAGS = -g -O0 -fsanitize=address
TARGET = uaf_test

all: $TARGET

$TARGET: uaf_24_double_free_alias.c
	$($CC) $($CFLAGS) -o $@ $<

clean:
	-del /f $TARGET 2>$NUL

