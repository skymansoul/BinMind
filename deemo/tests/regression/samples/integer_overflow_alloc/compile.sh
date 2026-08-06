#!/bin/bash
gcc -g -O0 -no-pie -fno-stack-protector -z execstack -o vuln vuln.c 2>&1
echo "Compiled: vuln"
