# Tahini Sidecar

<img src="share/cover.png" width="150"></img>

A lightweight attestation sidecar that is part of the [Tahini Project](https://space.babman.io/projects/compliance.html) led by Dr. Kinan Albab's
[SPACE Lab](https://space.babman.io/index.html) at Boston University. 

## Setup and running with Docker

The sidecar requires the **Intel SGX SDK** (x86_64 Linux). The easiest way to build and run is with the provided Docker image, which includes the SDK in simulation mode.

### 1. Build the Docker image

From the repo root:

```bash
bazel run //:docker_build
```

### 2. Run the container

Your repo is mounted at `/workspace` so you can edit locally and build inside the container.

```bash
bazel run //:docker_run
```

### 3. Inside the container: build with Bazel

The container has `SGX_SDK` and `SGX_MODE=SIM` set. Build the sidecar, signed enclave, and example:

```bash
bazel build //:sidecar_bin //:enclave_signed //examples:hello
```

### 4. Run the sidecar with the example service

From the container shell (you’re in `/workspace`):

```bash
./bazel-bin/sidecar ./bazel-bin/examples/hello
```

You should see something like:

```
tahini secret: 82569dba350c98ea4189a31eb9191fc9147a1428055034cfd8475ccd76a8c9ea
hello, world!
```

To run the sidecar with another binary, pass its path as the first argument:

```bash
./bazel-bin/sidecar /path/to/your/service/binary
```

## Sync to a remote host

To sync the repo to a remote x86_64 host (e.g. a Linode instance) for building or running there:

```bash
bazel run //:sync -- <ip_address>
```

This rsyncs the repo to `/root/tahini-sidecar` on the remote. Run the sync from your local repo root so the script can find the git root.

**On the remote host**, use the **exact synced path** (e.g. `cd /root/tahini-sidecar`) so `MODULE.bazel` is present—then run `./infra/install.sh` and Bazel. Otherwise Bazel will report “not invoked from within a workspace”:

```bash
ssh root@<ip_address>
cd /root/tahini-sidecar
./infra/install.sh
bazel run //:docker_build
# or: bazel build //:sidecar_bin //:enclave_signed //examples:hello
```

`infra/install.sh` installs Bazelisk to `/usr/local/bin/bazel` (uses `sudo` if needed). Sync verifies `MODULE.bazel` exists locally and on the remote so the workspace is valid.

## Example: changing the service changes the secret

The sidecar hashes the service binary and binds it to the attestation. If you change the example and rebuild, the secret and reported hash change. Try editing `examples/hello.c` (e.g. change the printed string), then:

```bash
bazel build //examples:hello //:sidecar_bin //:enclave_signed
./bazel-bin/sidecar ./bazel-bin/examples/hello
```

You’ll get a different `tahini secret` and hash, so clients can detect that the binary changed.

## Convention

We prefix all untrusted code with `u_` and all enclave code with `e_`. Other than that,
`sidecar.edl` is the enclave definition language file that defines the interface,
`sidecar.lds` is the linker script for the enclave, and `sidecar.config.xml` is the
configuration of the enclave. The project is built with **Bazel** (see `BUILD`, `MODULE.bazel`, and `WORKSPACE`).

## Execution mode

The Docker image runs in simulation mode (`SGX_MODE=SIM`) by default. To run on actual SGX hardware, use an environment with the SGX driver, set `SGX_MODE=HW`, and ensure `SGX_SDK` points at the SDK.
