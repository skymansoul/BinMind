CC = gcc
CFLAGS = -g -O0 -fsanitize=address
TARGET = uaf_test

all: $TARGET

$TARGET: uaf_17_deep_alias_chain.c
	$($CC) $($CFLAGS) -o $@ $<

clean:
	-del /f $TARGET 2>$NUL

