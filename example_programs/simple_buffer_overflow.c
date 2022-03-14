#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define GUARD_VALUE 0xFEEDCAFE
#define BUF_SIZE 32

int main() {
    // We want direct control over memory layout, so put things in a struct so the compiler doesn't pull a fast one on us
    // It tends to reorganize the variables so that the guard value is before the buffer in memory.
    struct {
        char buf[BUF_SIZE];
        uint32_t guard;
    } locals;
    locals.guard = GUARD_VALUE;

    gets(locals.buf);

    if (locals.guard != GUARD_VALUE) {
        printf("Hacking detected! 0x%08x\n", locals.guard);
        abort();
    }

    // Add a second crash for demo purposes
    if (locals.buf[0] != 'A') {
        printf("Second crash triggered");
        abort();
    }

    printf("Echo: %s", locals.buf);

    return 0;
}
