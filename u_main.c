#include "sidecar_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sgx_urts.h>
#include "sidecar.h"
#include "u_util.h"

// ocall_syscall is a wrapper to the Linux syscall interface
long ocall_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    return syscall(syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);
}

// ocall_copy_byte is a minimal single-byte copy to untrusted memory
void ocall_copy_byte(void* dest, uint8_t byte) {
    *((char*)dest) = (char)byte;
}

int main(int argc, char* argv[]) {
    if (!validate_user()) {
        fprintf(stderr, "error in sidecar: permission denied (must be in user group %s)\n", TAHINI_SIDECAR_OWNERS_GROUP);
        return EXIT_FAILURE;
    }

    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = sgx_create_enclave(
        TAHINI_ENCLAVE_FILE,
        SGX_DEBUG_FLAG,
        NULL,
        NULL,
        &eid,
        NULL
    );

    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "failed to create enclave. error code: 0x%x\n", ret);
        return EXIT_FAILURE;
    }
    
    // Build buffer with null-separated arguments for the enclave
    // Format: argv[0]\0argv[1]\0...argv[argc-1]\0
    size_t argv_buffer_size = 0;
    for (int i = 0; i < argc; i++) {
        argv_buffer_size += strlen(argv[i]) + 1; // +1 for null terminator
    }
    
    char* argv_buffer = malloc(argv_buffer_size);
    if (!argv_buffer) {
        fprintf(stderr, "failed to allocate memory for argv buffer\n");
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }
    
    size_t offset = 0;
    for (int i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]);
        memcpy(argv_buffer + offset, argv[i], len);
        argv_buffer[offset + len] = '\0';
        offset += len + 1;
    }
    
    sgx_status_t retval;
    ret = ecall_launch_service(eid, &retval, argc, argv_buffer_size, argv_buffer);
    
    free(argv_buffer);

    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        fprintf(stderr, "FAILED: [enclave error code: 0x%x] [retval: 0x%x]\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }
    
    sgx_destroy_enclave(eid);
    
    return EXIT_SUCCESS;
}