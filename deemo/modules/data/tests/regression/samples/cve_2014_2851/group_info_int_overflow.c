/* CVE-2014-2851 — Linux kernel group_info integer overflow
   Type: integer_overflow   gcc -O0 group_info_int_overflow.c -o group_info_int_overflow
   groups_alloc() used unchecked multiplication for allocation size. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int *groups_alloc(int gidsetsize) {
    /* BUG: gidsetsize * sizeof(int) can overflow */
    int alloc = gidsetsize * sizeof(int);
    int *groups = (int *)malloc(alloc);
    if (!groups) return NULL;
    memset(groups, 0, (unsigned int)(gidsetsize * sizeof(int)));
    return groups;
}
int main() {
    int *g = groups_alloc(0x40000001);  /* overflow: result is small */
    if (g) free(g);
    return 0;
}
