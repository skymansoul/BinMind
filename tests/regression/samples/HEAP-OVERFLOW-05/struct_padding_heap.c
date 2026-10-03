#include <stdlib.h>
#include <string.h>
/* Struct padding confusion: sizeof includes padding */
struct record { char name[32]; int id; char pad[4]; };
void copy_records(struct record *dst, char *src, int n) {
  dst=malloc(sizeof(struct record)*n);
  memcpy(dst, src, n*40);  /* sizeof(struct record)=40, but memcpy may copy 44 */
  free(dst);
}
int main() { struct record *r; char s[400]; copy_records(r,s,10); return 0; }