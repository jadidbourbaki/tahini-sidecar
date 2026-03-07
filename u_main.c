#include "sidecar_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>
#include "sidecar.h"
#include "u_util.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <service-binary> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (!validate_user()) {
        fprintf(stderr, "error: permission denied (must be in group %s)\n", TAHINI_SIDECAR_OWNERS_GROUP);
        return EXIT_FAILURE;
    }

    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = sgx_create_enclave(TAHINI_ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "failed to create enclave (0x%x)\n", ret);
        return EXIT_FAILURE;
    }

    // Step 1: hash the service binary into a memfd (TOCTOU-safe)
    int binary_fd = -1;
    sgx_status_t retval;
    ret = ecall_hash_binary(eid, &retval, argv[1], &binary_fd);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS || binary_fd < 0) {
        fprintf(stderr, "ecall_hash_binary failed (ret=0x%x retval=0x%x)\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    // Step 2: generate ECDH credentials inside the enclave
    uint8_t secret_key[TAHINI_KEY_SIZE];
    uint8_t public_key[TAHINI_PUBKEY_SIZE];
    ret = ecall_generate_credentials(eid, &retval, secret_key, TAHINI_KEY_SIZE, public_key, TAHINI_PUBKEY_SIZE);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        fprintf(stderr, "ecall_generate_credentials failed (ret=0x%x retval=0x%x)\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    // Step 3: get QE3 target info (DCAP) so the report targets the Quoting Enclave
    sgx_target_info_t qe_target_info;
    memset(&qe_target_info, 0, sizeof(qe_target_info));
    quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "sgx_qe_get_target_info failed (0x%x)\n", (unsigned)qe3_ret);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    // Step 4: create attestation report targeting QE3, binding binary hash + public key
    sgx_report_t report;
    uint8_t binary_hash[TAHINI_HASH_SIZE];
    uint8_t pubkey_out[TAHINI_PUBKEY_SIZE];
    ret = ecall_get_attestation_report(eid, &retval, &qe_target_info, &report,
                                       binary_hash, TAHINI_HASH_SIZE,
                                       pubkey_out, TAHINI_PUBKEY_SIZE);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        fprintf(stderr, "ecall_get_attestation_report failed (ret=0x%x retval=0x%x)\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    sgx_destroy_enclave(eid);

    // Step 5: generate ECDSA/DCAP quote from the report
    struct enclave_quote eq = get_enclave_quote(&report);
    if (eq.error != 0) {
        fprintf(stderr, "get_enclave_quote failed\n");
        return EXIT_FAILURE;
    }

    // Print attestation artifacts to stderr so service stdout is clean
    char hash_hex[TAHINI_HASH_SIZE * 2 + 1];
    bin_to_hex(binary_hash, TAHINI_HASH_SIZE, hash_hex);
    fprintf(stderr, "tahini binary hash: %s\n", hash_hex);

    char quote_hex[eq.quote_size * 2 + 1];
    bin_to_hex(eq.quote, eq.quote_size, quote_hex);
    fprintf(stderr, "tahini quote (%u bytes): %s\n", eq.quote_size, quote_hex);

    free_enclave_quote(&eq);

    // Step 6: exec the service binary from the memfd (exact bytes we hashed)
    char secret_hex[TAHINI_KEY_SIZE * 2 + 1];
    bin_to_hex(secret_key, TAHINI_KEY_SIZE, secret_hex);

    // Build argv: [binary_path, "--tahini-secret", secret_hex, service_args..., NULL]
    int svc_argc = argc - 1;
    char** svc_argv = malloc((size_t)(svc_argc + 3) * sizeof(char*));
    if (!svc_argv) {
        fprintf(stderr, "failed to allocate argv\n");
        return EXIT_FAILURE;
    }
    svc_argv[0] = argv[1];
    svc_argv[1] = "--tahini-secret";
    svc_argv[2] = secret_hex;
    for (int i = 2; i < argc; i++) {
        svc_argv[i + 1] = argv[i];
    }
    svc_argv[svc_argc + 2] = NULL;

    lseek(binary_fd, 0, SEEK_SET);
    syscall(SYS_execveat, binary_fd, "", svc_argv, NULL, AT_EMPTY_PATH);
    fprintf(stderr, "execveat failed: %s\n", strerror(errno));
    free(svc_argv);
    return EXIT_FAILURE;
}