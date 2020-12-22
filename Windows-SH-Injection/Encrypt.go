package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	// "path/filepath"
	"fmt"
	"flag"
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

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
} 

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func main() {

	FilePTR := flag.String("file", "blank", "File to be appened")
	flag.Parse()

	if *FilePTR == "blank"{
		fmt.Println("usage: -file [inputFile Path]")
		return
	}

	file := *FilePTR

	dat, _ := ioutil.ReadFile(file)
	
    // if err != nil {
	// 	panic(err)
	// }

	encryptFile(file, dat, key)
}
