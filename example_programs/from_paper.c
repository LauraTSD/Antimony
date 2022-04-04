#include <assert.h>

int foobar(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

int main() {
    int res = foobar(3, 5);
    return res;
}


