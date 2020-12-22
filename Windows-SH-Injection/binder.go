package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"bufio"
	"flag"
	"fmt"
)

func main() {
	firstFile := flag.String("first", "blank", "first file you want to bind")
	secondFile := flag.String("second", "blank", "File to be appened")
	outputFile := flag.String("output", "output", "File to be appened")


	flag.Parse()

	if *firstFile == "blank" || *secondFile == "blank" {
		fmt.Println("Usage: -first file1 -second file2 -output outputName")
		return
	}

	files := []string{*firstFile, *secondFile} //ROUGH but just change these to the files you want to bind

	// files := []string{"Stub-win.exe", "PayloadSH"} //ROUGH but just change these to the files you want to bind

	var buf bytes.Buffer
	for _, file := range files {
		b, err := ioutil.ReadFile(file)
		if err != nil {
			// handle error
		}

		buf.Write(b)
	}

	err := ioutil.WriteFile(*outputFile, buf.Bytes(), 0644)
	if err != nil {
		// handle error
	}
}


func RetrieveROM(filename string) ([]byte, error) {
    file, err := os.Open(filename)

    if err != nil {
        return nil, err
    }
    defer file.Close()

    stats, statsErr := file.Stat()
    if statsErr != nil {
        return nil, statsErr
    }

    var size int64 = stats.Size()
    bytes := make([]byte, size)

    bufr := bufio.NewReader(file)
    _,err = bufr.Read(bytes)

    return bytes, err
}
