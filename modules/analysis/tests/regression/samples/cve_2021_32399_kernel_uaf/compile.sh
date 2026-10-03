#!/bin/bash
gcc -o vuln vuln.c -no-pie -fno-stack-protector -w 2>&1 && echo OK || echo FAIL
