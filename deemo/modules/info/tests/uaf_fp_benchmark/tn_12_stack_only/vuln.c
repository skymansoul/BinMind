/* UAF TN (safe) sample */
typedef struct { int v; } obj_t;
int main(void) {
    obj_t s = {0};
    s.v = 12;
    return 0;
}
