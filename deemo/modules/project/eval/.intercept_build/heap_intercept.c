// heap_intercept.c: LD_PRELOAD内存操作拦截
// 编译: gcc -shared -fPIC -o libheap_intercept.so heap_intercept.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#define LOG_FILE "heap_trace.log"
static FILE* _log = NULL;
static void* (*_real_malloc)(size_t) = NULL;
static void* (*_real_calloc)(size_t,size_t) = NULL;
static void* (*_real_realloc)(void*,size_t) = NULL;
static void (*_real_free)(void*) = NULL;
static void* (*_real_memcpy)(void*,const void*,size_t) = NULL;
static void* (*_real_memset)(void*,size_t,int) = NULL;
static void _init_log(void) {
  if (!_log) { _log = fopen(LOG_FILE,"a"); setvbuf(_log,NULL,_IONBF,0); }
}
void* malloc(size_t n) {
  if(!_real_malloc) _real_malloc = dlsym(RTLD_NEXT,"malloc");
  void *p = _real_malloc(n); _init_log();
  fprintf(_log,"ALLOC %p %zu\n",p,n); return p;
}
void* calloc(size_t nmemb,size_t sz) {
  if(!_real_calloc) _real_calloc = dlsym(RTLD_NEXT,"calloc");
  void *p = _real_calloc(nmemb,sz); _init_log();
  fprintf(_log,"ALLOC %p %zu\n",p,nmemb*sz); return p;
}
void* realloc(void* old,size_t n) {
  if(!_real_realloc) _real_realloc = dlsym(RTLD_NEXT,"realloc");
  void *p = _real_realloc(old,n); _init_log();
  fprintf(_log,"FREE %p 0\n",old);
  fprintf(_log,"ALLOC %p %zu\n",p,n); return p;
}
void free(void* p) {
  if(!_real_free) _real_free = dlsym(RTLD_NEXT,"free");
  _init_log(); fprintf(_log,"FREE %p 0\n",p); _real_free(p);
}
void* memcpy(void* dst,const void*src,size_t n) {
  if(!_real_memcpy) _real_memcpy = dlsym(RTLD_NEXT,"memcpy");
  _init_log(); fprintf(_log,"WRITE %p %zu\n",dst,n);
  return _real_memcpy(dst,src,n);
}
void* memset(void* dst,int c,size_t n) {
  if(!_real_memset) _real_memset = dlsym(RTLD_NEXT,"memset");
  _init_log(); fprintf(_log,"WRITE %p %zu\n",dst,n);
  return _real_memset(dst,c,n);
}
