#include "sidecar_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sgx_urts.h>
#include "sidecar.h"

// ocall_print: just your everyday stdout
void ocall_print(const char* str) {
    printf("%s", str);
}

// ocall_read_file_chunk: reads a chunk of the binary file from disk
void ocall_read_file_chunk(
    const char* path,
    size_t offset,
    uint8_t* buffer,
    size_t chunk_size,
    size_t* bytes_read
) {
    // note: this could definitely be faster by not opening and closing the file for each chunk
    // but a one-time performance gain at startup is not a big win for us, large services
    // have a long startup time anyway.
    FILE* f = fopen(path, "rb");
    if (!f) {
        *bytes_read = 0;
        return;
    }
    
    // Seek to offset
    if (fseek(f, offset, SEEK_SET) != 0) {
        fclose(f);
        *bytes_read = 0;
        return;
    }
    
    // Read chunk
    *bytes_read = fread(buffer, 1, chunk_size, f);
    fclose(f);
}

// Convert binary to hex string
void bin_to_hex(const uint8_t* bin, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i*2, "%02x", bin[i]);
    }
    hex[len*2] = '\0';
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <service_binary> [args...]\n", argv[0]);
        fprintf(stderr, "example: %s /usr/bin/my_service --arg1 value1\n", argv[0]);
        return 1;
    }
    
    const char* service_binary = argv[1];
    
    printf("tahini sidecar: initializing...\n");
    
    // create enclave
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = sgx_create_enclave(
        ENCLAVE_FILE,
        SGX_DEBUG_FLAG,
        NULL,
        NULL,
        &eid,
        NULL
    );
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "failed to create enclave. error code: 0x%x\n", ret);
        return 1;
    }
    
    printf("tahini sidecar: computing binary hash (inside enclave)...\n");
    
    // initialize enclave and let it hash the binary itself
    ret = ecall_hash(eid, service_binary);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "failed to initialize and hash binary. error code: 0x%x\n", ret);
        sgx_destroy_enclave(eid);
        return 1;
    }
    
    printf("tahini sidecar: generating credentials...\n");
    
    // generate credentials
    uint8_t secret_key[KEY_SIZE], public_key[PUBKEY_SIZE];
    ret = ecall_generate_credentials(eid, secret_key, KEY_SIZE, public_key, PUBKEY_SIZE);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "failed to generate credentials. error code: 0x%x\n", ret);
        sgx_destroy_enclave(eid);
        return 1;
    }
    
    // convert secret to hex for command line argument
    char secret_hex[KEY_SIZE * 2 + 1];
    bin_to_hex(secret_key, KEY_SIZE, secret_hex);
    
    printf("tahini sidecar: launching service binary...\n");
    
    // Build argv for exec
    // format: <service_binary> --tahini-secret <hex-secret> [original args...]
    char** exec_argv = malloc((argc + 2) * sizeof(char*));
    if (!exec_argv) {
        fprintf(stderr, "failed to allocate memory for exec argv\n");
        sgx_destroy_enclave(eid);
        return 1;
    }
    
    exec_argv[0] = (char*)service_binary;
    exec_argv[1] = "--tahini-secret";
    exec_argv[2] = secret_hex;
    
    // copy remaining arguments
    for (int i = 2; i < argc; i++) {
        exec_argv[i + 1] = argv[i];
    }
    exec_argv[argc + 1] = NULL;
    
    // note: we don't destroy the enclave before exec because exec replaces
    // the process. The enclave will be destroyed when the process exits.
    
    // execute service binary
    execvp(service_binary, exec_argv);
    
    // should not reach here
    perror("execvp failed");
    free(exec_argv);
    sgx_destroy_enclave(eid);
    return 1;
}