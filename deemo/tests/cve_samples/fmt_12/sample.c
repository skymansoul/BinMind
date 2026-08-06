#include <stdio.h>
#include <string.h>
void mqtt_log(char*topic){fprintf(stderr,topic);}
int main(int c,char**v){if(c>1)mqtt_log(v[1]);return 0;}