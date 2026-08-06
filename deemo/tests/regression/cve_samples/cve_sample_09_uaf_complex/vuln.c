/* CVE-mimic: Complex UAF via race-condition-like pattern
 * Real CVE: CVE-2024-1086 (kernel UAF in nf_tables)
 * Compile: gcc -o vuln vuln.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct node { int id; char *name; };
struct node *g_ptr = NULL;
void create(char *name) {
    g_ptr = malloc(sizeof(struct node));
    g_ptr->id = 1; g_ptr->name = strdup(name);
}
void destroy(void) { free(g_ptr->name); free(g_ptr); }
void use_after(void) { printf("Node: %s
", g_ptr->name); }  /* UAF */
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    create(argv[1]); destroy(); use_after();
    return 0;
}