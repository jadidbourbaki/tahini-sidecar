#ifndef TAHINI_SIDECAR_H
#define TAHINI_SIDECAR_H

// TAHINI_HASH_SIZE is the SHA-256 hash size
#define TAHINI_HASH_SIZE 32  
// TAHINI_KEY_SIZE is the private key size in bytes
#define TAHINI_KEY_SIZE 32  
// TAHINI_PUBKEY_SIZE is the full public key size in bytes for NIST P-256 (32 bytes x + 32 bytes y)
#define TAHINI_PUBKEY_SIZE 64 
// TAHINI_ENCLAVE_FILE is the path to the enclave file
// We assume the sidecar is run from the repo root so the enclave is in bazel-bin/enclave.signed.so.
#define TAHINI_ENCLAVE_FILE "bazel-bin/enclave.signed.so"

// CHUNK_SIZE is the size of the chunk to read the binary in
#define TAHINI_CHUNK_SIZE 4096

// Syscall numbers for x86-64 Linux
#define TAHINI_SYSCALL_OPEN 2
#define TAHINI_SYSCALL_LSEEK 8
#define TAHINI_SYSCALL_READ 0
#define TAHINI_SYSCALL_CLOSE 3
#define TAHINI_SYSCALL_EXECVE 59
#define TAHINI_SYSCALL_EXECVEAT 322
#define TAHINI_AT_EMPTY_PATH 0x1000
#define TAHINI_SYSCALL_MEMFD_CREATE 319
#define TAHINI_SYSCALL_MMAP 9
#define TAHINI_SYSCALL_WRITE 1
#define TAHINI_SYSCALL_SET 12

// mmap flags
#define TAHINI_MMAP_PROT_READ 1
#define TAHINI_MMAP_PROT_WRITE 2
#define TAHINI_MMAP_MAP_PRIVATE 2
#define TAHINI_MMAP_MAP_ANONYMOUS 32

// File open flags
#define TAHINI_FILE_OPEN_FLAG_RDONLY 0
#define TAHINI_FILE_OPEN_FLAG_SEEK_SET 0

// mmap flags and constants
#define TAHINI_MMAP_PROT_READ 1
#define TAHINI_MMAP_PROT_WRITE 2
#define TAHINI_MMAP_MAP_PRIVATE 2
#define TAHINI_MMAP_MAP_ANONYMOUS 32
#define TAHINI_MMAP_MAP_FAILED ((void*)-1)

#endif // TAHINI_SIDECAR_H