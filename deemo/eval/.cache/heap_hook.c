
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static FILE*_log;
static void _open_log(void){
    const char*p=getenv("HOOK_LOG");
    if(p)_log=fopen(p,"w");
    if(!_log)_log=stderr;
}
__attribute__((constructor))static void _init(void){_open_log();}
void*malloc(size_t s){void*(*r)(size_t)=dlsym(RTLD_NEXT,"malloc");void*p=r(s);
    if(_log)fprintf(_log,"MALLOC %p %zu\n",p,s);return p;}
void free(void*p){void(*r)(void*)=dlsym(RTLD_NEXT,"free");
    if(_log)fprintf(_log,"FREE %p\n",p);r(p);}
void*realloc(void*p,size_t s){void*(*r)(void*,size_t)=dlsym(RTLD_NEXT,"realloc");
    void*q=r(p,s);if(_log)fprintf(_log,"REALLOC %p->%p %zu\n",p,q,s);return q;}
