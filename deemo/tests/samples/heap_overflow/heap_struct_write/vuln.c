/**
 * heap_struct_write - Heap overflow via struct field overrun
 *
 * Defines a struct with a fixed-size char array field (name[16]).
 * A heap-allocated instance of the struct has strcpy called on the
 * name field with a long user-supplied string, overflowing past the
 * field boundary into adjacent struct members and heap metadata.
 *
 * This tests whether a tool can perform struct-aware analysis --
 * understanding that writing past name[16] corrupts the adjacent
 * fields (id, score) and potentially heap chunk metadata.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln <name_string>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_SIZE 16

/* Struct with a fixed-size buffer for name, followed by other fields */
typedef struct {
    char name[NAME_SIZE];  // VULN-GUARD: 16-byte fixed buffer
    int  id;               // Corrupted when name overflows
    double score;          // Corrupted when name overflows
} record_t;

int main(int argc, char **argv) {
    record_t *rec;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        fprintf(stderr, "  (Try a name longer than %d characters)\n", NAME_SIZE - 1);
        return 1;
    }

    /* Allocate a record on the heap */
    rec = (record_t *)malloc(sizeof(record_t));  // VULN-GUARD: sizeof(record_t) bytes
    if (!rec) {
        perror("malloc");
        return 1;
    }

    /* Initialize all fields to known values */
    memset(rec, 0, sizeof(record_t));
    rec->id = 42;
    rec->score = 99.5;

    printf("Before: id=%d, score=%.1f\n", rec->id, rec->score);

    /* VULNERABLE: strcpy copies argv[1] into rec->name with no bounds
     * check. If the input exceeds NAME_SIZE-1 characters (15 + null),
     * the overflow corrupts rec->id, then rec->score, then heap metadata.
     * A struct-aware tool must recognize that name[16] is embedded in
     * a larger struct and track field-level bounds. */
    strcpy(rec->name, argv[1]);  // VULN: unbounded strcpy into struct field

    /* After overflow, adjacent fields are corrupted */
    printf("After:  name='%s', id=%d, score=%.1f\n",
           rec->name, rec->id, rec->score);
    printf("(If id != 42 or score != 99.5, the overflow corrupted adjacent fields)\n");

    free(rec);
    return 0;
}
