/* format_string_14 — sprintf作为格式参数传播 */
#include <stdio.h>
int main(int argc,char**argv){char buf[256];sprintf(buf,argc>1?argv[1]:"%%s","data");puts(buf);return 0;}
