/* FMT-0015: Format string via wrapper chain */
#include <stdio.h>
#include <stdarg.h>
void my_vprintf(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); }
int main(int argc, char **argv) { if (argc>1) my_vprintf(argv[1]); return 0; }
