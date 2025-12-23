# tahini sidecar

A lightweight attestation sidecar that is part of the broader [tahini project](https://space.babman.io/projects/compliance.html) that is part of Dr. Kinan Albab's [SPACE Lab](https://space.babman.io/index.html) at Boston University.

# required dependencies

You first need to set up the Intel SGX SDK on Linux. We assume you are using Ubuntu in
this tutorial.

## the intel sgx sdk 

Some prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3 wget
```

Now create the installation directory:

```bash
sudo mkdir -p /opt/intel
```

Download SGX SDK (replace with latest version from Intel's website). For Ubuntu 20.04/22.04:

```bash
wget https://download.01.org/intel-sgx/sgx-linux/2.21/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.21.100.2.bin
```

Make it executable

```bash
chmod +x sgx_linux_x64_sdk_*.bin
```

Run installer (default installs to /opt/intel/sgxsdk)

```bash
sudo ./sgx_linux_x64_sdk_*.bin
```

Finally, source the environment:

```bash
echo 'source /opt/intel/sgxsdk/environment' >> ~/.bashrc
source ~/.bashrc
```

Helpful link: [Intel's SGX Downloads](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/downloads.html)

## the install sgx driver


(Important note!!! ) The SGX driver is required for hardware-based SGX. For simulation mode (development/testing), you can skip this step.

```bash
sudo apt-get install -y linux-headers-$(uname -r)
wget https://download.01.org/intel-sgx/sgx-linux/2.21/distro/ubuntu22.04-server/sgx_linux_x64_driver_*.bin
chmod +x sgx_linux_x64_driver_*.bin
sudo ./sgx_linux_x64_driver_*.bin
```

## install go

```bash
sudo apt-get install -y golang-go
```

## double-check the setup

intel sgx sdk:

```bash
sgx_edger8r --version
```

go installation:

```bash
go version
```

gcc installation:

```bash
gcc --version
```

# building

first, generate the enclave signing key (if not already present). we will try to 
make sure this is already present though.

```bash
openssl genrsa -out Enclave_private.pem -3 3072
```

next, build the application:

```bash
make
```

# running

It's as simple as:

```bash
make run
```

Or run directly:

```bash
./sidecar
```