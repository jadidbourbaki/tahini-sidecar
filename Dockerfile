# Simple Intel SGX Hello World in Simulation Mode
# Works on any x86_64 server (Intel or AMD)

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    libssl-dev \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Intel SGX SDK using prebuilt installer (much faster than building from source)
WORKDIR /tmp
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.27/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.27.100.1.bin && \
    chmod +x sgx_linux_x64_sdk_2.27.100.1.bin && \
    ./sgx_linux_x64_sdk_2.27.100.1.bin --prefix /opt/intel && \
    rm -f sgx_linux_x64_sdk_2.27.100.1.bin

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
