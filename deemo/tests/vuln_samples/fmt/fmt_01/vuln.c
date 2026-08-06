/* CVE-2024-21817 CWE-134: printf直接使用用户输入作为格式串 */
#include <stdio.h>
void lu(char*in){printf(in);}
int main(int c,char**v){lu(c>1?v[1]:"guest");return 0;}
