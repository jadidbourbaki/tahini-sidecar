#ifndef SIDECAR_H
#define SIDECAR_H

#define HASH_SIZE 32  // SHA-256 hash size
#define KEY_SIZE 32   // Private key size in bytes
#define PUBKEY_SIZE 64  // Full public key size in bytes (NIST P-256: 32 bytes x + 32 bytes y)
#define ENCLAVE_FILE "enclave.signed.so"

#endif // SIDECAR_H