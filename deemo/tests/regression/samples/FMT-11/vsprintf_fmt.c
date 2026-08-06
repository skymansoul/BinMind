#include <stdio.h>
#include <stdarg.h>
/* vsprintf variant */
void vlog(const char *fmt, ...) { char b[256]; va_list ap; va_start(ap,fmt); vsprintf(b,fmt,ap); va_end(ap); }
int main(int argc, char **argv) { if(argc>1) vlog(argv[1]); return 0; }