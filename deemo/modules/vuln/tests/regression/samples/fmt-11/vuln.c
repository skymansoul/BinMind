#include <stdio.h>
#include <stdlib.h>
void die(char *m) { fprintf(stderr,"%s",m); exit(1); }
int main(int c,char**v) { if(c<2)die("usage\n"); die(v[1]); return 0; }
