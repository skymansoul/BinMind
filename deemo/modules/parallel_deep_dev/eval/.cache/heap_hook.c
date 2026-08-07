
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static FILE *g_log;
static void open_log(void){
    const char *p = getenv("HOOK_LOG");
    if (p) g_log = fopen(p, "w");
    if (!g_log) g_log = stderr;
}
__attribute__((constructor)) static void init_hook(void){ open_log(); }
void *malloc(size_t s){ void *(*r)(size_t)=dlsym(RTLD_NEXT,"malloc");
    void *p = r(s); if(g_log) fprintf(g_log,"MALLOC %p %zu\n",p,s); return p; }
void *calloc(size_t n,size_t s){ void *(*r)(size_t,size_t)=dlsym(RTLD_NEXT,"calloc");
    void *p = r(n,s); if(g_log) fprintf(g_log,"MALLOC %p %zu\n",p,n*s); return p; }
void *realloc(void *p,size_t s){ void *(*r)(void*,size_t)=dlsym(RTLD_NEXT,"realloc");
    void *q = r(p,s); if(g_log) fprintf(g_log,"REALLOC %p %p %zu\n",p,q,s); return q; }
void free(void *p){ void (*r)(void*)=dlsym(RTLD_NEXT,"free");
    if(g_log) fprintf(g_log,"FREE %p\n",p); r(p); }
void *memcpy(void *d,const void *s,size_t n){
    void *(*r)(void*,const void*,size_t)=dlsym(RTLD_NEXT,"memcpy");
    void *q = r(d,s,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
void *memmove(void *d,const void *s,size_t n){
    void *(*r)(void*,const void*,size_t)=dlsym(RTLD_NEXT,"memmove");
    void *q = r(d,s,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
void *memset(void *d,int c,size_t n){
    void *(*r)(void*,int,size_t)=dlsym(RTLD_NEXT,"memset");
    void *q = r(d,c,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
char *strcpy(char *d,const char *s){
    char *(*r)(char*,const char*)=dlsym(RTLD_NEXT,"strcpy");
    char *q = r(d,s); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,strlen(s)+1); return q; }
char *strncpy(char *d,const char *s,size_t n){
    char *(*r)(char*,const char*,size_t)=dlsym(RTLD_NEXT,"strncpy");
    char *q = r(d,s,n); if(g_log) fprintf(g_log,"MEMCPY %p %zu\n",d,n); return q; }
