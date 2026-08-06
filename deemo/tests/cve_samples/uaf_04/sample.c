#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF: buffer freed then reused via stale reference */
char*conf=NULL;
void load_conf(){conf=strdup("mode=strict");}
void reload(){free(conf);conf=strdup("mode=permissive");}
void print_old(){if(conf)printf("old:%s",conf);/* UAF if called after free before reload */}
int main(){load_conf();char*saved=conf;free(conf);printf("%s",saved);return 0;}