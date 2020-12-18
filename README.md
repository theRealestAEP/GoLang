How to build
mac & linux stub coming soon 

windows stub:
GOOS=windows GOARCH=amd64 go build Stub-win.go 

binder:
go build binder.go 

Encrypt:
go build encrypt.go

Decrypt:
go build decrypt.go

How to use 

Encrypt your Shellcode payload -(PAYLOADSH is already encrypted dont encrypt it twice)
./Encrypt -file PathToShellCode


Bind the files
./binder -first Stub-win.exe -second PayloadSH -output test.exe

Decrypt
./Decrypt -file PathToShellCode


NOTE
if you change anything in the stub make sure you build first and then adjust the the bytes to skip var as it needs to know how many prepeneded bytes to skip. 

PayloadSH is the shellcode of Payload.go (Payload.exe) IT IS ALREADY ENCRYPTED