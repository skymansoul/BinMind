/* SAFE-correct-check SAFE: 正确边界检查——负面测试，不应检出 */
#include <stdlib.h>
#include <string.h>
char* safe_cp(const char* s, size_t mx) {
    size_t l=strlen(s); if(l>=mx)l=mx-1;
    char* b=malloc(l+1); if(!b)return 0; memcpy(b,s,l); b[l]=0; return b;
}
int main(int c, char** v) { char* p=safe_cp(c>1?v[1]:"t",128); free(p); return 0; }
