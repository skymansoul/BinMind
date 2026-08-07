#include <stdio.h>
void log_user(char *s) { printf(s); }
int main(int c,char**v) { if(c>1)log_user(v[1]); return 0; }
