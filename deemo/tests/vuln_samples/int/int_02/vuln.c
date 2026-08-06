/* CVE-2019-11477 CWE-190: size_t加法溢出导致回绕 */
#include <stdlib.h>
void mg(size_t a,size_t b){size_t t=a+b;char*m=malloc(t);free(m);}
int main(){mg((size_t)-10,20);return 0;}
