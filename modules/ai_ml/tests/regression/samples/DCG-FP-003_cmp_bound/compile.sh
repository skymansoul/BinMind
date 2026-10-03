#!/bin/bash
gcc -O0 -o ../build/DCG-FP-003_cmp_bound_O0.exe vuln.c -fno-stack-protector -no-pie
gcc -O2 -o ../build/DCG-FP-003_cmp_bound_O2.exe vuln.c -fno-stack-protector -no-pie
echo "DCG-FP-003 compiled"