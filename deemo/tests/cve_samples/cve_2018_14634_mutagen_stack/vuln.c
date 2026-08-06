/* CVE-2018-14634 — Linux kernel create_elf_tables stack overflow / CWE-121 */
#include <string.h>
#include <stdlib.h>
void elf_auxv_setup(char *envp, int env_len) {
    char stack_buf[256];
    if (env_len <= 256) memcpy(stack_buf, envp, env_len); /* BUG: off-by-one? Actually integer overflow in size calc */
    else memcpy(stack_buf, envp, 512); /* overflow when len>256 */
}
int main(void) { char *e = malloc(512); memset(e,'E',512); elf_auxv_setup(e,512); free(e); return 0; }
