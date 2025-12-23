package main

/*
#cgo CFLAGS: -I. -I/opt/intel/sgxsdk/include
#cgo LDFLAGS: -L/opt/intel/sgxsdk/lib64 -lsgx_urts -lsgx_uae_service -lpthread -ldl

#include <stdlib.h>
#include "sgx_urts.h"
#include "sidecar_u.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// OCall function - called from enclave
//
//export ocall_print_string
func ocall_print_string(str *C.char) {
	fmt.Print(C.GoString(str))
}

func main() {
	var eid C.sgx_enclave_id_t = 0
	var token C.sgx_launch_token_t
	var updated C.int = 0

	// Create enclave
	enclavePath := C.CString("sidecar_enclave.signed.so")
	defer C.free(unsafe.Pointer(enclavePath))

	ret := C.sgx_create_enclave(
		enclavePath,
		C.SGX_DEBUG_FLAG,
		&token,
		&updated,
		&eid,
		nil,
	)

	if ret != C.SGX_SUCCESS {
		fmt.Printf("Failed to create enclave: 0x%x\n", ret)
		return
	}

	fmt.Println("Enclave created successfully!")

	// Call enclave function
	message := C.CString("Hello from Go untrusted app!")
	defer C.free(unsafe.Pointer(message))

	C.ecall_hello_world(eid, message)

	// Destroy enclave
	C.sgx_destroy_enclave(eid)

	fmt.Println("Enclave destroyed. Goodbye!")
}
