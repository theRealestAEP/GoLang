package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io/ioutil"
	"os"
	// "log"
	"flag"
	"fmt"
	// "os/exec"
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
	return decrypt(data, passphrase)
}

func main() {
	FilePTR := flag.String("file", "blank", "File to be appened")
	flag.Parse()

	if *FilePTR == "blank"{
		fmt.Println("usage: -file [inputFile Path]")
		return
	}

	file := *FilePTR

	decryptFile(file, key)

	// cmdOutput, err := exec.Command(file).Output()
    // if err != nil {
    //     log.Fatal(err)
    // }

    // fmt.Printf("%s", cmdOutput)
	
}
