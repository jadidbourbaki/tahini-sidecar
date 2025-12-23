# Simple Intel SGX Hello World in Simulation Mode
# Works on any x86_64 server (Intel or AMD)

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    ocaml \
    ocamlbuild \
    automake \
    autoconf \
    libtool \
    wget \
    python3 \
    libssl-dev \
    git \
    cmake \
    perl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Intel SGX SDK
WORKDIR /tmp
RUN git clone https://github.com/intel/linux-sgx.git && \
    cd linux-sgx && \
    make preparation && \
    make sdk && \
    make sdk_install_pkg && \
    cd linux/installer/bin && \
    ./sgx_linux_x64_sdk_*.bin --prefix /opt/intel && \
    cd /tmp && \
    rm -rf linux-sgx

# Set up SGX environment
ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH=$SGX_SDK/bin:$SGX_SDK/bin/x64:$PATH
ENV PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH=$SGX_SDK/sdk_libs

# Set simulation mode
ENV SGX_MODE=SIM

# Source SGX environment in bashrc so it's available in interactive shells
RUN echo 'source $SGX_SDK/environment' >> /root/.bashrc

WORKDIR /workspace

# Default command - interactive shell for development
# Mount your source directory: docker run -it -v $(pwd):/workspace tahini-sidecar
CMD ["/bin/bash"]
