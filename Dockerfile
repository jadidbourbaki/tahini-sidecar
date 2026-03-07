# Tahini Sidecar — Intel SGX ECDSA/DCAP attestation
#
# Default: SGX_MODE=SIM (works on any x86_64 host, no real attestation)
# Azure DCsv3: build with --build-arg SGX_MODE=HW --build-arg AZURE=1
#   docker build --build-arg SGX_MODE=HW --build-arg AZURE=1 -t tahini-sidecar .

FROM ubuntu:22.04

ARG SGX_MODE=SIM
ARG AZURE=0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    libssl-dev \
    unzip \
    gnupg \
    apt-transport-https \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
    && chmod +x /usr/local/bin/bazel

# Intel SGX repo (DCAP quote library + runtime)
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSLO https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    mv intel-sgx-deb.key /etc/apt/keyrings/intel-sgx-keyring.asc && \
    echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' \
        > /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        libsgx-quote-ex libsgx-dcap-ql libsgx-dcap-ql-dev \
        libsgx-enclave-common libsgx-urts \
    && rm -rf /var/lib/apt/lists/*

# Azure DCAP client — replaces Intel's default QPL with one that talks to Azure THIM.
# Only installed when AZURE=1; on non-Azure hosts the Intel default QPL is used.
RUN if [ "$AZURE" = "1" ]; then \
        curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg && \
        echo 'deb [signed-by=/etc/apt/keyrings/microsoft.gpg arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main' \
            > /etc/apt/sources.list.d/microsoft.list && \
        apt-get update && apt-get install -y --no-install-recommends az-dcap-client && \
        rm -rf /var/lib/apt/lists/* ; \
    fi

# Intel SGX SDK
WORKDIR /tmp
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.27/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.27.100.1.bin && \
    chmod +x sgx_linux_x64_sdk_2.27.100.1.bin && \
    ./sgx_linux_x64_sdk_2.27.100.1.bin --prefix /opt/intel && \
    rm -f sgx_linux_x64_sdk_2.27.100.1.bin

ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH=$SGX_SDK/bin:$SGX_SDK/bin/x64:$PATH
ENV PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH=$SGX_SDK/sdk_libs

ENV SGX_MODE=${SGX_MODE}

RUN groupadd sidecar-owners && usermod -aG sidecar-owners root

RUN echo 'source $SGX_SDK/environment' >> /root/.bashrc

WORKDIR /workspace

CMD ["/bin/bash"]
