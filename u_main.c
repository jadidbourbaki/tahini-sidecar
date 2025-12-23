#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"
#include "sidecar_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

/* OCall implementation */
void ocall_print(const char* str) {
    printf("%s", str);
}

int main(int argc, char* argv[]) {
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int updated = 0;

    printf("Creating enclave...\n");

    /* Create the enclave */
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave. Error code: 0x%x\n", ret);
        return -1;
    }

    printf("Enclave created successfully!\n");
    printf("Calling enclave function...\n");

    /* Call the enclave function */
    ret = ecall_hello_from_enclave(eid);
    if (ret != SGX_SUCCESS) {
        printf("Failed to call enclave function. Error code: 0x%x\n", ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    printf("Destroying enclave...\n");
    sgx_destroy_enclave(eid);
    
    printf("Done!\n");
    return 0;
}

