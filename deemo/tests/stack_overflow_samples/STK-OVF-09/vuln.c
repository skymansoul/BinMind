#include <string.h>
void safe(char*s){char b[256];strncpy(b,s,255);b[255]=0;}
int main(int c,char**v){if(c>1)safe(v[1]);return 0;}