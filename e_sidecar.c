#include "sidecar_t.h"
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_tservice.h>
#include <string.h>

#include "sidecar.h"

// the state we store in the enclave
static uint8_t stored_hash[HASH_SIZE] = {0};
static uint8_t public_key_commitment[HASH_SIZE] = {0};  // Hash of full public key for attestation report
static sgx_ec256_public_t full_public_key = {0};  // Full public key (64 bytes: x + y)
static sgx_ec256_private_t private_key = {0};
static int initialized = 0;

#define CHUNK_SIZE 4096

// ecall_hash: hashes the binary inside the enclave
sgx_status_t ecall_hash(const char* binary_path) {
    if (!binary_path) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // initialize the SHA-256 context
    sgx_sha_state_handle_t sha_handle;
    sgx_status_t ret = sgx_sha256_init(&sha_handle);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // read file in chunks via OCALL and hash inside enclave
    uint8_t buffer[CHUNK_SIZE];
    size_t offset = 0;
    size_t bytes_read = 0;
    
    // read the file in chunks and hash inside the enclave
    do {
        bytes_read = 0;
        ocall_read_file_chunk(binary_path, offset, buffer, sizeof(buffer), &bytes_read);
        
        if (bytes_read > 0) {
            ret = sgx_sha256_update(buffer, bytes_read, sha_handle);
            // todo: the error handling here could be improved
            if (ret != SGX_SUCCESS) {
                sgx_sha256_close(sha_handle);
                return ret;
            }
            offset += bytes_read;
        }
    } while (bytes_read == sizeof(buffer)); // Continue if we read a full chunk
    
    // finalize the hash
    ret = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*)stored_hash);
    sgx_sha256_close(sha_handle);
    
    if (ret == SGX_SUCCESS) {
        initialized = 1;
    }
    
    return ret;
}

// ecall_generate_credentials: generates ECDH key pair and sends to caller
sgx_status_t ecall_generate_credentials(
    uint8_t* secret_key_out,
    size_t secret_key_len,
    uint8_t* public_key_out,
    size_t public_key_len
) {
    if (!initialized) {
        return SGX_ERROR_UNEXPECTED;
    }
    
    if (secret_key_len != KEY_SIZE || public_key_len != PUBKEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Open ECC context for NIST P-256
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Generate ECDH key pair (NIST P-256)
    ret = sgx_ecc256_create_key_pair(&private_key, &full_public_key, ecc_handle);
    if (ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecc_handle);
        return ret;
    }
    
    sgx_ecc256_close_context(ecc_handle);
    
    // Compute hash of full public key for attestation report binding
    // The sgx_report_data_t structure is 64 bytes total. We use:
    // - 32 bytes for the binary hash (stored_hash)
    // - 32 bytes for the public key commitment (hash of full public key)
    // This cryptographically binds the full 64-byte public key in the report
    // while fitting within the 64-byte report_data constraint
    ret = sgx_sha256_msg((const uint8_t*)&full_public_key, sizeof(sgx_ec256_public_t), 
                          (sgx_sha256_hash_t*)public_key_commitment);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Serialize private key (32 bytes) - copy directly
    memcpy(secret_key_out, private_key.r, KEY_SIZE);
    
    // Return full public key (64 bytes: x + y coordinates)
    // Serialize: first 32 bytes are x-coordinate, next 32 bytes are y-coordinate
    memcpy(public_key_out, full_public_key.gx, KEY_SIZE);
    memcpy(public_key_out + KEY_SIZE, full_public_key.gy, KEY_SIZE);
    
    return SGX_SUCCESS;
}

// ecall_get_attestation_report: get attestation report with hash + public key for remote attestation
sgx_status_t ecall_get_attestation_report(
    const sgx_target_info_t* target_info,
    sgx_report_t* report,
    uint8_t* binary_hash_out,
    size_t hash_len,
    uint8_t* public_key_out,
    size_t pubkey_len
) {
    if (!initialized) {
        return SGX_ERROR_UNEXPECTED;
    }
    
    if (hash_len != HASH_SIZE || pubkey_len != PUBKEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Copy hash and public key commitment to report data
    // sgx_report_data_t is 64 bytes total, structured as:
    // - report_data.d[0..31]: binary hash (32 bytes)
    // - report_data.d[32..63]: public key commitment (32 bytes, hash of full 64-byte public key)
    // We can't fit the full 64-byte public key because we need 32 bytes for the binary hash,
    // leaving only 32 bytes remaining. Using a hash commitment cryptographically binds the
    // full public key in the attestation report. The full 64-byte public key is returned separately.
    sgx_report_data_t report_data = {0};
    memcpy(report_data.d, stored_hash, HASH_SIZE);
    memcpy(report_data.d + HASH_SIZE, public_key_commitment, HASH_SIZE);
    
    // Generate attestation report
    sgx_status_t ret = sgx_create_report(target_info, &report_data, report);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Return hash and full public key (64 bytes: x + y)
    memcpy(binary_hash_out, stored_hash, HASH_SIZE);
    memcpy(public_key_out, full_public_key.gx, KEY_SIZE);
    memcpy(public_key_out + KEY_SIZE, full_public_key.gy, KEY_SIZE);
    
    return SGX_SUCCESS;
}
