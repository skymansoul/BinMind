#include <stdio.h>
#include <string.h>
/* Format string: user input as format arg */
void log_event(const char*msg){fprintf(stderr,msg);/* BUG: fmt string */}
int main(int c,char**v){if(c>1)log_event(v[1]);return 0;}