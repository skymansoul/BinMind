/* GENERIC-race-rename CWE-362: rename竞态——目标文件在检查后被替换 */
#include <stdio.h>
void rn_race(char*o,char*n){if(fopen(o,"r")){rename(o,n);}}
int main(int c,char**v){rn_race(c>1?v[1]:"a",c>2?v[2]:"b");return 0;}
