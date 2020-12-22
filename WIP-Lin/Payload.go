package main

import (
    // "fmt"
    // "log"
    "os"
)

func main() {
	f, _ := os.Create("PayloadTEST.txt")
    f.Write([]byte("This is a mad crazy payload, SEND ME 9999 BTC to 7ea7d2b63442fa7f9a4b21829e9a4775ba96f4d2b7c2e8c55b5d261635fa9c91 RASOMWARE RASOMWARE RASOMWARE RASOMWARE COMPUTER LOCKED "))
    f.Close()
}