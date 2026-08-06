/* CVE-2016-6301 CWE-416: 竞态条件: free和use在不同位置 */
#include <stdlib.h>
#include <string.h>
char*s;
void fi(){free(s);}
void ui(){strcpy(s,"data");}
int main(){s=malloc(256);fi();ui();return 0;}
