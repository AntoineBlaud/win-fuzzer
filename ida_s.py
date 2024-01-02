from idautils import *
from idaapi import *
from idc import *
from ida_name import *
import os
import socket


# connect to the listener
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to listener...")
s.connect(("localhost", 1338))
s.send("[+] Script started\n".encode())
auto_wait()
# rebase program to 0x0
offset = idaapi.get_imagebase()
idaapi.rebase_program(-offset, MSF_NOFIX)

def func_disasm(func):
    disasm = ""
    for line in FuncItems(func):
        disasm += GetDisasm(line) + "\n"
    return disasm

def check_syscall(func_disasm):
    patterns = [
        "int     2Eh",
        "syscall"
    ]
    for line in func_disasm.split("\n"):
        for pattern in patterns:
            if pattern in line:
                return True
    return False


try:
    for func in Functions():
        addr = get_func(func).start_ea
        name = get_func_name(addr)
        disasm = func_disasm(func)
        # check is syscall 
        if check_syscall(disasm):
            s.send(f"{name} {hex(addr)}\n".encode())
            
except Exception as e:
    s.send(str(e).encode())
        
s.close()
exit() 

