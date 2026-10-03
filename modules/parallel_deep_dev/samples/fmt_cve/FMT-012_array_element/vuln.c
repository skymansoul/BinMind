#include <stdio.h>
#include <string.h>

static void arr_trigger(const char *input)
{
    char *slots[4];
    slots[0] = (char *)input;
    printf(slots[0]);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    arr_trigger(argv[1]);
    return 0;
}
