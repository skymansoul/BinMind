#include <stdio.h>
#include <string.h>
void ws_log(char*frame){printf(frame);}
int main(int c,char**v){if(c>1)ws_log(v[1]);return 0;}