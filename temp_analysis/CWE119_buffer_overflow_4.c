#include <stdio.h>
#include <string.h>

// Juliet Test Suite v1.3 - CWE-119 Buffer Overflow Sample 4
void bad_func_4(char *src) {
    char buffer[24];
    // Vulnerable: unsafe strcpy may overflow buffer
    strcpy(buffer, src);
    printf("Content: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        bad_func_4(argv[1]);
    }
    return 0;
}
