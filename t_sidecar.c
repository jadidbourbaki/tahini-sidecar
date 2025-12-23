#include <string.h>
#include "sidecar_t.h"

/* the trusted function that can be called from the untrusted application */
void ecall_hello_world(const char* message) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "Enclave says: %s\n", message);
    ocall_print_string(buffer);
}

