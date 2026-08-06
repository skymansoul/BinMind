#include <stdio.h>
#include <stdarg.h>
void vlog(const char *f, ...) { va_list a; va_start(a,f);
vprintf(f,a); va_end(a); }
int main(int argc, char **argv) { if(argc<2)return 1;
vlog(argv[1]); return 0; }
