# Tahini Sidecar

<img src="share/cover.png" width="150"></img>

A lightweight attestation sidecar that is part of the [Tahini Project](https://space.babman.io/projects/compliance.html) led by Dr. Kinan Albab's
[SPACE Lab](https://space.babman.io/index.html) at Boston University.

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

## Convention

We prefix all untrusted code with `u_` and all enclave code with `e_`. Other than that,
`sidecar.edl` is the enclave definition language file that defines the interface,
`sidecar.lds` is the linker script for the enclave, `sidecar.config.xml` is the 
configuration of the enclave, and `Makefile` is just your everyday Makefile.

## Execution mode

To run in simulation mode, set `SGX_MODE=SIM`. To run on actual SGX hardware, set `SGX_MODE=HW` and install the SGX driver.
