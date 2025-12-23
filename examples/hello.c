#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    // The sidecar passes: argv[1] = "--tahini-secret", argv[2] = <hex-secret>
    if (argc < 3 || strncmp(argv[1], "--tahini-secret", 16) != 0) {
        fprintf(stderr, "usage: %s --tahini-secret <secret>\n", argv[0]);
        return 1;
    }
    
    // print the tahini secret
    printf("tahini secret: %s\n", argv[2]);
    printf("hello, world!\n");
    return 0;
}