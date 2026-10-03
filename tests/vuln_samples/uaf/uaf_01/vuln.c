/* CVE-2021-3801 CWE-416: free后继续使用指针 */
#include <stdlib.h>
typedef struct{int id;char d[64];}I;
void proc(int n){I*items=malloc(n*sizeof(I));for(int i=0;i<n;i++)items[i].id=i;free(items);for(int i=0;i<n;i++)items[i].id=-1;}
int main(int c,char**v){proc(c>1?atoi(v[1]):10);return 0;}
