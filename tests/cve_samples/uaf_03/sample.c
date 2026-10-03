#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF: object reused after async completion frees it */
typedef struct{char*b;int sz;}Req;
Req*active=NULL;
void submit(){active=malloc(sizeof(Req));active->b=strdup("payload");active->sz=7;}
void complete(){if(active){free(active->b);free(active);}}
void process(){if(active)printf("proc:%s",active->b);/* UAF after complete */}
int main(){submit();complete();process();return 0;}