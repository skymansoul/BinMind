#!/bin/bash
gcc -std=c99 -O0 -g -o heartbleed_o0 heartbleed.c
gcc -std=c99 -O2 -o heartbleed_o2 heartbleed.c
gcc -std=c99 -O0 -g -fno-stack-protector -z execstack -o heartbleed_no_harden heartbleed.c
echo "CVE-2014-0160 samples built"
