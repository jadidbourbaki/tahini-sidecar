# Tahini Sidecar

<img src="share/cover.png" width="150"></img>

A lightweight attestation sidecar that is part of the [Tahini Project](https://space.babman.io/projects/compliance.html) led by Dr. Kinan Albab's
[SPACE Lab](https://space.babman.io/index.html) at Boston University. The Tahini sidecar implements a mani-
fest attestation protocol that remote services must deploy in a TEE and point to the
service binary they desire to deploy. The sidecar performs the
following steps: (i) it hashes the service binary and stores that
hash, (ii) it launches the binary outside the TEE by calling
`exec` via the underlying operating system, (iii) it passes some
secret credentials to the binary during launch via command
line arguments.

### Manifest attestation protocol
When callers first establish a connection with the remote service, Tahini uses the remote
attestation capabilities of the TEE to verify that it is running
the unmodified Tahini sidecar. Then, it retrieves from the
sidecar the hash of the binary it launched as well as some
public credentials. Tahini compares the binary hash with the
the certificates that the caller developers approved previously,
and produces an error if it does not recognize the binary hash.
Finally, it establishes a secure connection with the binary
using the credentials it receives from the sidecar.
Tahini avoids TEE-related runtime overheads: Only the
sidecar runs within the TEE, which only performs operation during service launch and when callers first establish a connection with the remote. The service code itself as well as any RPC invocations by the callers do not execute within the
TEE. Tahini achieves this because: (i) It trusts the underlying
operating systems and remote users with root access, and thus
does not need to protect against malicious attacks that corrupt
the service memory or code after it is launched or exfiltrates
secrets from it. (ii) The sidecar enables the binary and the
callers to establish a secure connection. Only the launched
binary possesses the secret credentials required to establish
this connection and decrypt its communication, which verifies
to callers that they are communicating with the valid binary.

## TEE Interface Design

Tahini's security model is based on trusting the underlying OS and users with root access. For the design of our TEE interface,
this translates to three concrete expectations: 1) The OS will not maliciously corrupt service memory or code after launch.
2) The OS will not exfiltrate secrets from running processes, and 3) The OS will correctly execute the binary we request via `execvp()` 
which we call in our code.

Due to these assumptions, the Tahini sidecar avoids the TEE runtime overhead of running the service binary inside the enclave, while still providing cryptographic guarantees about what binary was launched.

The following steps happen *inside* the Intel SGX enclave: 1) The SHA-256 hash of the service binary is computed inside the enclave using SGX's trusted crypto library (`sgx_sha256_*`). We trust the root user running the sidecar to provide correct file contents and launch the correct binary. The enclave's role is to provide cryptographic proof to remote callers about what the root user intended to launch, not to protect against the root user themselves. It protectd remote callers by proving what binary the privileged deployer, i.e. root user, intended to launch. 2) Secret keys are generated using SGX's secure random number generator (`sgx_read_rand`), ensuring they cannot be observed or predicted by the untrusted host. 3) The SGX attestation report cryptographically binds the binary hash and public key, proving that a genuine SGX enclave computed these values. The OS cannot forge or modify this report.

The following steps happen *outside* the Intel SGX enclave: 1) The enclave reads the service binary via `ocall_read_file_chunk()`, which executes in untrusted code. The OS could theoretically provide different file contents than what exists on disk. This is where our assumption that root users and the underlying OS is trusted comes in. The enclave can only be launched by root users and we trust them to provide the right binary. 2) The service binary is launched via `execvp()` in untrusted code. The OS could theoretically launch a different binary than the one that was hashed, but again in our threat model we trsut the underlying OS.

Given our threat model of trusting the OS and root users, this design provides the necessary security guarantees:

1. If the OS lies about file contents during the OCALL, the enclave will hash whatever it receives. The resulting hash will not match the expected certificate that callers have pre-approved, causing the connection to be rejected. The OS cannot forge a hash collision (cryptographically infeasible with SHA-256).

2. The SGX attestation report proves that i) A genuine SGX enclave computed the hash ii) The hash was computed from data the enclave received (even if that data was incorrect, and iii) The public key was generated securely inside the enclave.

3. Only the launched binary receives the secret key via command-line arguments. If the OS launches a different binary, that binary won't have the secret key and cannot establish the secure connection with callers.

4. If the OS attempts to launch a different binary than what was hashed, callers will detect this because 1) the hash in the attestation report won't match the expected certificate, or 2) The wrong binary won't have the secret key and cannot authenticate.

However, to reiterate, this design does **not** protect against 1) A malicious OS that provides incorrect file contents during hashing, 2) A malicious OS that launches a different binary than requested, 3) Memory corruption or code injection after the service binary is launched, and 4) Root users inspecting or modifying running processes.

As mentioned earlier, these limitations are acceptable given our threat model, which explicitly trusts the OS and root users. The enclave's role is to provide cryptographic proof of what binary was intended to be launched, not to enforce execution of that specific binary.

## Setup

Build with Docker:

```bash
docker build -t tahini-sidecar .
```

Run on Docker (with volume mount for development):

```bash
docker run -it --rm -v $(pwd):/workspace tahini-sidecar
```

Inside the container, build and run:

```bash
make
./sidecar
```

## Example Usage

Take a look at the simple hello world service in `examples/`. You can use the Makefile in `examples/` to build it and then
launch it using the tahini sidecar:

```bash
root@a79f4bfe91f4:/workspace/tahini-sidecar# ./sidecar examples/hello                                                                           
tahini sidecar: initializing...                                                                                                                 
tahini sidecar: computing binary hash (inside enclave)...                                                                                       
tahini sidecar: generating credentials...                                                                                                       
tahini sidecar: launching service binary...
tahini secret: 685d6d8cfa409dfb0a968747cb720c5de832393c541dc35827a07194e9caf507
hello, world!
```

Try modifying the service code or binary to see how the secret generated by the tahini sidecar changes:

modification:

```bash
git diff
diff --git a/examples/hello.c b/examples/hello.c
index e69d534..b3a1c13 100644
--- a/examples/hello.c
+++ b/examples/hello.c
@@ -10,6 +10,6 @@ int main(int argc, char* argv[]) {
     
     // print the tahini secret
     printf("tahini secret: %s\n", argv[2]);
-    printf("hello, world!\n");
+    printf("hello, world!!\n");
     return 0;
-}
\ No newline at end of file
+}
```

New secret:

```bash
root@a79f4bfe91f4:/workspace/tahini-sidecar# ./sidecar examples/hello
tahini sidecar: initializing...
tahini sidecar: computing binary hash (inside enclave)...
tahini sidecar: generating credentials...
tahini sidecar: launching service binary...
tahini secret: dbd7e4f76995ce05716a1399c778306ef918834bc48433cd15e7f5194b145814
hello, world!!
```

## Convention

We prefix all untrusted code with `u_` and all enclave code with `e_`. Other than that,
`sidecar.edl` is the enclave definition language file that defines the interface,
`sidecar.lds` is the linker script for the enclave, `sidecar.config.xml` is the 
configuration of the enclave, and `Makefile` is just your everyday Makefile.

## Execution mode

To run in simulation mode, set `SGX_MODE=SIM`. To run on actual SGX hardware, set `SGX_MODE=HW` and install the SGX driver.
