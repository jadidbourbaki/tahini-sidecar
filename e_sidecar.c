#include "sidecar_t.h"
#include <string.h>

void ecall_hello_from_enclave(void) {
    const char* message = "Hello from Intel SGX enclave!\n";
    ocall_print(message);
}

