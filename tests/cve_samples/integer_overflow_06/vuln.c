/* int_overflow_06 — 负数转无符号 */
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char**argv){int s=argc>1?atoi(argv[1]):-1;unsigned int us=(unsigned)s;char*p=malloc(us);free(p);return 0;}
