CC = gcc
CFLAGS = -g -O0 -fsanitize=address
TARGET = uaf_test

all: $TARGET

$TARGET: uaf_19_cross_cond_free.c
	$($CC) $($CFLAGS) -o $@ $<

clean:
	-del /f $TARGET 2>$NUL

