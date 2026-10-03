CC = gcc
CFLAGS = -g -O0 -fsanitize=address
TARGET = uaf_test

all: $TARGET

$TARGET: uaf_27_same_name_diff_obj.c
	$($CC) $($CFLAGS) -o $@ $<

clean:
	-del /f $TARGET 2>$NUL

