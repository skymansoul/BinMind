/* FMT-15: fwrite前用sprintf格式化到栈——若fmt可控→栈溢出 */
#include <stdio.h>
#include <string.h>
int main(int c,char**v) { char b[64]; sprintf(b,v[1]); fwrite(b,1,strlen(b),stdout); return 0; }
