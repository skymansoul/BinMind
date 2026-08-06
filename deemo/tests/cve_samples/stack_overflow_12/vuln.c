/* stack_overflow_12 — memcpy目标在栈上 */
#include <stdio.h>
#include <string.h>
int main(int argc,char**argv){char buf[32];memcpy(buf,argv[1]?argv[1]:"",64);return 0;}
