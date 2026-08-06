/* CVE-2022-1015 — Linux nftables expression stack overflow / CWE-121 */
#include <string.h>
void nft_parse_expression(char *expr, int expr_len) {
    char buf[256];
    int copy_len = expr_len > 256 ? expr_len : 256; /* BUG: always copies at least 256, can overflow */
    memcpy(buf, expr, copy_len);
}
int main(void) { char e[512]; memset(e,'I',512); nft_parse_expression(e,512); return 0; }
