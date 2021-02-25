package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/faiface/beep"
	"github.com/faiface/beep/mp3"
	"github.com/faiface/beep/speaker"
	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	CreateProcess      = kernel32.NewProc("CreateProcessA")
	CloseHandle        = kernel32.NewProc("CloseHandle")
	GetModuleFileNameA = kernel32.NewProc("GetModuleFileNameA")
	CREATE_NO_WINDOW   = 0x08000000
)

func delMe() {
	var buf []byte
	size := uint32(1024)
	buf = make([]byte, size)
	var handle syscall.Handle = 0

	GetModuleFileNameA.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size))

	buf = bytes.Trim(buf, "\x00")
	pathC := string(buf)

	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)

	final := os.Getenv("windir") + `\system32\cmd.exe /C del /f ` + pathC

	cmd := syscall.StringToUTF16Ptr(final)

	err2 := syscall.CreateProcess(nil, cmd, nil, nil, false, uint32(CREATE_NO_WINDOW), nil, nil, si, pi)
	if err2 != nil {
		panic(err2)
	}
	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)

	CloseHandle.Call(hProcess)
	CloseHandle.Call(hThread)

}

func finalMessage() string {

	text := `
	_                __  _    _                 _   _      _  
	/  |_|  /\  |\ | /__ |_   | \  /\    \    / / \ |_) |  | \ 
	\_ | | /--\ | \| \_| |_   |_/ /--\    \/\/  \_/ | \ |_ |_/ 
																								 
	_ ___                      _  __  __       __  _ 
	|\/| \_/   |_  |  |\ |  /\  |    |\/| |_ (_  (_   /\  /__ |_ 
	|  |  |    |  _|_ | \| /--\ |_   |  | |_ __) __) /--\ \_| |_ 
																 
	__  _   _   _   _       _ 
	/__ / \ / \ | \ |_) \_/ |_ 
	\_| \_/ \_/ |_/ |_)  |  |_ 
							   .
	`

	return text
}

func main() {

	data := getHexString()
	f, _ := hex.DecodeString(data)
	prep := ioutil.NopCloser(bytes.NewReader(f)) //make it into a reader closer

	final := finalMessage()

	fmt.Println(final)

	streamer, format, err := mp3.Decode(prep)
	if err != nil {
		log.Fatal(err)
	}
	defer streamer.Close()

	speaker.Init(format.SampleRate, format.SampleRate.N(time.Second/10))

	done := make(chan bool)
	speaker.Play(beep.Seq(streamer, beep.Callback(func() {
		done <- true
	})))

	<-done

	delMe()
}
