#!/bin/bash
gcc -g -O0 -fno-stack-protector -z execstack -o vuln vuln.c
exit $?
