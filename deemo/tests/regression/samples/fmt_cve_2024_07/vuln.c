/* FMT: vsnprintf wrapper */
#include <stdio.h>
#include <stdarg.h>
void logit(const char *fmt, ...) { char buf[512]; va_list ap; va_start(ap,fmt); vsnprintf(buf,512,fmt,ap); va_end(ap); printf("%s",buf); }
int main(int argc, char **argv) { if(argc>1) logit(argv[1]); return 0; }
