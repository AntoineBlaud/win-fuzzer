import subprocess
import argparse
import pefile
import socket
import os
import sys
import tempfile
import shutil
import json
import re

# python sys_scanner.py config.json output.json


lib_func_with_syscalls = {}


def is_32bit_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        return pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]
    except pefile.PEFormatError:
        return False


def list_libraries(lib_path):
    libraries = []
    if os.path.isdir(lib_path):
        for file in os.listdir(lib_path):
            # check dll or exe
            if file.endswith(".dll") or file.endswith(".exe"):
                libraries.append(file)
    return libraries


def collect_headers(headers_dir):
    headers_str = ""
    header_files = []
    if not os.path.isdir(headers_dir):
        raise Exception("Header path is not a directory")
    for file in os.listdir(headers_dir):
        # check dll or exe
        if file.endswith(".h"):
            print("Found header file: " + file)
            header_files.append(file)
            headers_str += open(os.path.join(headers_dir, file), "r").read() + "\n"
    return header_files, headers_str


parser = argparse.ArgumentParser(description="IDA Pro Headless Syscall Scanner")
parser.add_argument("config", metavar="config", type=str, help="config file")
parser.add_argument("output", metavar="output", type=str, help="output json file")

args = parser.parse_args()
config = json.load(open(args.config, "r"))

ida_root_dir = config["ida_root_dir"]
script_path = os.path.dirname(os.path.realpath(__file__)) + "\\ida_s.py"
libs_dir = config["libs_dir"]
headers_dir = config["headers_dir"]
output_path = args.output
current_dir = os.getcwd()


# setup a listener to receive the script output from ida
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", 1338))
s.listen()


# list libraries to scan
libraries = list_libraries(libs_dir)

for lib in libraries:
    # create a temporary directory for ida to work in
    temp_dir = tempfile.mkdtemp()
    # copy library to temporary directory
    clibs_dir = os.path.join(libs_dir, lib)
    shutil.copy(clibs_dir, temp_dir)
    clibs_dir = os.path.join(temp_dir, lib)
    # go to temporary directory
    os.chdir(temp_dir)
    if is_32bit_pe(clibs_dir):
        ida_exe = f"{ida_root_dir}\\\\ida.exe"
    else:
        ida_exe = f"{ida_root_dir}\\\\ida64.exe"

    print("Scanning {}".format(clibs_dir))

    lib_func_with_syscalls[lib] = []

    cmd = ['"{}"'.format(ida_exe), "-c", "-A", "-a", f'-S"{script_path}" {clibs_dir}']
    cmd = " ".join(cmd)
    print("Running: {}".format(cmd))
    # run headless ida
    subprocess.call(cmd)
    # wait for ida script to finish
    print("Waiting for IDA script output...")
    conn, addr = s.accept()
    print("[+] New client {}".format(addr))
    while True:
        # check connection status
        data = conn.recv(65535)
        if not data:
            break
        data = data.decode()
        data = data.split("\n")
        for line in data:
            if "[+]" in line:
                print(line)
                continue
            try:
                func_name, func_addr = line.split(" ")
            except ValueError:
                print(line)
            lib_func_with_syscalls[lib].append((func_name, int(func_addr, 16)))

    conn.close()


# collect header files
headers_files, headers_str = collect_headers(headers_dir)
lib_func_with_syscalls_args = {}

for lib, functions in lib_func_with_syscalls.items():
    lib_func_with_syscalls_args[lib] = {}

    for func_name, func_addr in functions:
        index = headers_str.find(func_name)

        if index == -1:
            lib_func_with_syscalls_args[lib][func_name] = {
                "args": [],
                "addr": func_addr,
            }
            continue

        # make some replacements on arguments
        func_def = headers_str[index:]
        func_def = func_def[: func_def.find(";")]
        func_def = (
            func_def.replace("\t", "")
            .replace("  ", " ")
            .replace(", ", ",")
            .replace(" ,", ",")
        )
        func_def = func_def[::-1].replace(")", "", 1)[::-1]
        paren_index = func_def.find("(")
        func_def = func_def[:paren_index] + "," + func_def[paren_index + 1 :]
        func_def = [arg.strip() for arg in func_def.split(",\n")]

        # remove empty arguments
        if len(func_def) == 2 and func_def[1] == "":
            lib_func_with_syscalls_args[lib][func_name] = {
                "args": [],
                "addr": func_addr,
            }
        # add the arguments
        else:
            lib_func_with_syscalls_args[lib][func_name] = {
                "args": func_def[1:],
                "addr": func_addr,
            }

for lib, functions in lib_func_with_syscalls_args.items():
    for func, args in functions.items():
        print(f"{lib} {func} {args}")

# move back to the original directory
os.chdir(current_dir)
print(f"Saving output to {output_path}")
json.dump(lib_func_with_syscalls_args, open(output_path, "w"))
