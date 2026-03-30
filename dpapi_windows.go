//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// dataBlob mirrors the Windows DATA_BLOB structure used by CryptUnprotectData.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// decryptWithDPAPI decrypts data using the Windows Data Protection API (DPAPI).
// It calls CryptUnprotectData from Crypt32.dll to perform the decryption.
func decryptWithDPAPI(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data provided to DPAPI decrypt")
	}

	crypt32 := syscall.NewLazyDLL("Crypt32.dll")
	kernel32 := syscall.NewLazyDLL("Kernel32.dll")
	cryptUnprotectData := crypt32.NewProc("CryptUnprotectData")
	localFree := kernel32.NewProc("LocalFree")

	input := dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}
	var output dataBlob

	ret, _, err := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&output)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.pbData))) //nolint:errcheck

	result := make([]byte, output.cbData)
	copy(result, unsafe.Slice(output.pbData, output.cbData))
	return result, nil
}
