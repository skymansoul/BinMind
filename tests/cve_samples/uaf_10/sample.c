#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{int handle;char*data;}GPUBuf;
GPUBuf*gpu=NULL;
void alloc_gpu(){gpu=malloc(sizeof(GPUBuf));gpu->handle=1;gpu->data=strdup("pixels");}
void free_gpu(){free(gpu->data);free(gpu);}
void render(){if(gpu)printf("render h=%d",gpu->handle);}
int main(){alloc_gpu();free_gpu();render();return 0;}