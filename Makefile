######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else
	SGX_ARCH := x64
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS := -O0 -g -DDEBUG
	SGX_EDGER8R_FLAGS := -debug
else
	SGX_COMMON_CFLAGS := -O2 -DNDEBUG
	SGX_EDGER8R_FLAGS :=
endif

SGX_COMMON_CFLAGS += -m64 -Wall -Wextra

######## Include paths ########
SGX_INCLUDE := -I$(SGX_SDK)/include
SGX_LIBRARY_PATH := -L$(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## Enclave Settings ########
Enclave_Name := sidecar_enclave
Enclave_Config_File := Enclave.config.xml
Enclave_Signing_Key := Enclave_private.pem

######## App Settings ########
App_Name := sidecar
App_Go_Files := u_sidecar.go
App_Include_Paths := -I. -I$(SGX_SDK)/include

######## Enclave Source Files ########
Enclave_C_Files := t_sidecar.c
Enclave_Include_Paths := -I. -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc

######## Flags ########
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(Enclave_Include_Paths)

######## Libraries ########
App_Link_Flags := $(SGX_LIBRARY_PATH) -L. -lsgx_urts -lsgx_uae_service -lpthread -ldl
Enclave_Link_Flags := $(SGX_LIBRARY_PATH) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_SDK)/lib64 -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections -Wl,--version-script=Enclave.lds

######## Objects ########
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

######## Generated Files ########
Enclave_EDL := sidecar.edl
Enclave_EDL_H := sidecar_t.h
Enclave_EDL_C := sidecar_t.c
App_EDL_H := sidecar_u.h
App_EDL_C := sidecar_u.c

######## Targets ########
.PHONY: all clean run

all: $(App_Name) $(Enclave_Name).signed.so

######## Enclave Objects ########
t_sidecar.o: t_sidecar.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

######## EDL Generation ########
$(Enclave_EDL_H) $(Enclave_EDL_C): $(Enclave_EDL)
	@$(SGX_EDGER8R) $(SGX_EDGER8R_FLAGS) --trusted $(Enclave_EDL) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App_EDL_H) $(App_EDL_C): $(Enclave_EDL)
	@$(SGX_EDGER8R) $(SGX_EDGER8R_FLAGS) --untrusted $(Enclave_EDL) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

######## App Linking ########
$(App_Name): $(App_EDL_H) $(App_EDL_C)
	@CGO_CFLAGS="-I. -I$(SGX_SDK)/include" \
	 CGO_LDFLAGS="$(SGX_LIBRARY_PATH) -L. -lsgx_urts -lsgx_uae_service -lpthread -ldl $(App_EDL_C)" \
	 go build -o $@ $(App_Go_Files)
	@echo "LINK =>  $@"

######## Enclave Linking ########
$(Enclave_Name).so: $(Enclave_EDL_H) $(Enclave_EDL_C) t_sidecar.o
	@$(CC) t_sidecar.o $(Enclave_EDL_C) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Signing ########
$(Enclave_Name).signed.so: $(Enclave_Name).so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Signing_Key) -enclave $(Enclave_Name).so -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

######## Clean ########
clean:
	@rm -f $(App_Name) $(Enclave_Name).so $(Enclave_Name).signed.so
	@rm -f t_sidecar.o
	@rm -f $(Enclave_EDL_H) $(Enclave_EDL_C) $(App_EDL_H) $(App_EDL_C)
	@echo "CLEAN =>  done"

run: all
	@./$(App_Name)
