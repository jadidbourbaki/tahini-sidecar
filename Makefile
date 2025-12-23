SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifneq ($(SGX_MODE), HW)
	URTS_LIBRARY_NAME := sgx_urts_sim
else
	URTS_LIBRARY_NAME := sgx_urts
endif

UNTRUSTED_SRC_FILES := u_main.c
UNTRUSTED_INCLUDE_PATHS := -I$(SGX_SDK)/include -I.

UNTRUSTED_C_FLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(UNTRUSTED_INCLUDE_PATHS)
UNTRUSTED_LINK_FLAGS := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(URTS_LIBRARY_NAME) -lpthread

UNTRUSTED_BINARY_NAME := sidecar

ifneq ($(SGX_MODE), HW)
	TRTS_LIBRARY_NAME := sgx_trts_sim
	SERVICE_LIBRARY_NAME := sgx_tservice_sim
else
	TRTS_LIBRARY_NAME := sgx_trts
	SERVICE_LIBRARY_NAME := sgx_tservice
endif

CRYPTO_LIBRARY_NAME := sgx_tcrypto

TRUSTED_SRC_FILES := e_sidecar.c
TRUSTED_INCLUDE_PATHS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I.

TRUSTED_C_FLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(TRUSTED_INCLUDE_PATHS)
TRUSTED_LINK_FLAGS := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(TRTS_LIBRARY_NAME) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(CRYPTO_LIBRARY_NAME) -l$(SERVICE_LIBRARY_NAME) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=sidecar.lds

TRUSTED_BINARY_NAME := enclave.so
SIGNED_TRUSTED_BINARY_NAME := enclave.signed.so

.PHONY: all run clean

all: $(UNTRUSTED_BINARY_NAME) $(SIGNED_TRUSTED_BINARY_NAME)

run: all
	@echo "Running in $(SGX_MODE) mode..."
	./$(UNTRUSTED_BINARY_NAME)

	-Wl,--version-script=sidecar.lds

######## Untrusted (App) Objects ########
sidecar_u.c: $(SGX_EDGER8R) sidecar.edl
	@$(SGX_EDGER8R) --untrusted sidecar.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

sidecar_u.o: sidecar_u.c
	@$(CC) $(UNTRUSTED_C_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

u_main.o: u_main.c sidecar_u.c
	@$(CC) $(UNTRUSTED_C_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(UNTRUSTED_BINARY_NAME): sidecar_u.o u_main.o
	@$(CC) $^ -o $@ $(UNTRUSTED_LINK_FLAGS)
	@echo "LINK =>  $@"

######## Trusted (Enclave) Objects ########
sidecar_t.c: $(SGX_EDGER8R) sidecar.edl
	@$(SGX_EDGER8R) --trusted sidecar.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

sidecar_t.o: sidecar_t.c
	@$(CC) $(TRUSTED_C_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

e_sidecar.o: e_sidecar.c sidecar_t.c
	@$(CC) $(TRUSTED_C_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(TRUSTED_BINARY_NAME): sidecar_t.o e_sidecar.o
	@$(CC) $^ -o $@ $(TRUSTED_LINK_FLAGS)
	@echo "LINK =>  $@"

$(SIGNED_TRUSTED_BINARY_NAME): $(TRUSTED_BINARY_NAME)
	@if [ ! -f sidecar_private.pem ]; then \
		echo "Generating enclave signing key..."; \
		openssl genrsa -out sidecar_private.pem -3 3072; \
	fi
	@$(SGX_ENCLAVE_SIGNER) sign -key sidecar_private.pem -enclave $(TRUSTED_BINARY_NAME) -out $@ -config sidecar.config.xml
	@echo "SIGN =>  $@"

clean:
	@rm -f $(UNTRUSTED_BINARY_NAME) $(TRUSTED_BINARY_NAME) $(SIGNED_TRUSTED_BINARY_NAME) *.o sidecar_t.* sidecar_u.* sidecar_private.pem
