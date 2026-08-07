#!/bin/bash
# Compile DCG-FP-001: register chain test
gcc -O0 -o ../build/DCG-FP-001_register_chain_O0.exe vuln.c -fno-stack-protector -no-pie
gcc -O2 -o ../build/DCG-FP-001_register_chain_O2.exe vuln.c -fno-stack-protector -no-pie
echo "DCG-FP-001 compiled"
