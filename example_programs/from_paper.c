#include <assert.h>

void foobar(int a, int b) {
    int x = 1, y = 0;

    if (a != 0) {
        y = 3+ x;
        if (b == 0){
            x = 2*( a + b );
        }
    }
    assert(x - y != 0);
}

int main() {
    foobar(3, 5);
    return 3;
}