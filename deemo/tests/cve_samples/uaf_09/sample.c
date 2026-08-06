#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{int fd;char*path;}FDCache;
FDCache*cache=NULL;
void cache_fd(int fd,char*path){cache=malloc(sizeof(FDCache));cache->fd=fd;cache->path=strdup(path);}
void evict_fd(){free(cache->path);free(cache);}
void lookup_fd(){if(cache)printf("fd=%d",cache->fd);}
int main(){cache_fd(3,"/etc/passwd");evict_fd();lookup_fd();return 0;}