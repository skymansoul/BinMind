/* CVE-2016-2177 CWE-190: count*size整数溢出导致分配过小 */
#include <stdlib.h>
#include <string.h>
void* alloc(int c, int s) { return malloc(c*s); }
void cp(const char* s, int c) { char* b=alloc(c,4); memcpy(b,s,c*4); free(b); }
int main() { cp("x", 1073741824); return 0; }
