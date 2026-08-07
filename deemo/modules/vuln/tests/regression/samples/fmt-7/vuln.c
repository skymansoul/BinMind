/* FMT-7: snprintf格式化字符串来自网络 */
#include <stdio.h>
#include <unistd.h>
int main() { char fmt[64],buf[256]; read(0,fmt,63); snprintf(buf,256,fmt); return 0; }
