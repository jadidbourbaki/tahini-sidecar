# Remote Attestation Flow

The control flow is essentially the following. The sidecar produces an SGX report inside the enclave and the untrusted layer turns it into an ECDSA quote via Intel SGX DCAP. A remote client verifies the quote using a collateral, which is the TCB info, CRLs, and the PCK certificate chain.

Here is what the untrusted part of the sidecar does, step by step:

1. Hash the binary with `ecall_hash_binary` by streaming the service binary into a memfd while computing SHA-256 inside the enclave.
2. Generate credentials using `ecall_generate_credentials` by creating an ECDH key pair inside the enclave.
3. Get Quoting Enclave v3 (QE3) target info using the untrusted side calls from Intel SGX's DCAP attestation API, i.e., `sgx_qe_get_target_info()` to obtain the Quoting Enclave's identity.
4. Create the Intel SGX report with `ecall_get_attestation_report` which calls `sgx_create_report(qe_target_info, report_data)` where `report_data` = binary hash (32 B) || H(public key) (32 B). The report targets QE3.
5. Generate the ECDSA quote using untrusted side calls from Intel SGX's DCAP attestation API with `sgx_qe_get_quote(&report)`. The DCAP Quote Library loads the Quoting Enclave (QE3), verifies the report, and produces an ECDSA-P256 quote.
6. Print the quote, essentially, the hex-encoded quote and binary hash are printed to stderr.
7. Execute the underlying service. `execveat(memfd, ...)` replaces the process with the service, passing the secret via `--tahini-secret`.

## Client Verification

The client receives the quote and verifies it using collateral. On Azure confidential VMs, collateral comes from [Azure Trusted Hardware Identity Management](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management). The `az-dcap-client` QPL (installed in the docker image when `AZURE=1`) handles this transparently.

## Running End-to-End on Azure

Set up a confidential Intel SGX VM using this [guide](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal) from Microsoft Azure. Clone this repository in the VM.

Then build the docker:

```bash
bazel run //:docker_build -- --build-arg SGX_MODE=HW --build-arg AZURE=1
```

And then run the docker. We have a script, `docker-run.sh`, that auto-detects SGX devices.

```bash
bazel run //:docker_run
```