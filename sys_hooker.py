import argparse
import json
import frida
import sys
import random
import threading
import time
import os

# python frida_sys_interceptor.py lib_func_syscalls.json


global_var = """
var sys_data = $$sys_data$$;
var funcs_map = {};
var register_args = ["rcx", "rdx", "r8", "r9"];
"""

common = """
function lib_includes(libname, liblist) {
  for (var i = 0; i < liblist.length; i++) {
    if (libname.toLowerCase() == liblist[i].toLowerCase()) {
      return true
    }
  }
  return false
}

function func_includes(funcname, funclist) {
  for (var i = 0; i < funclist.length; i++) {
    if (funcname.toLowerCase() == funclist[i].toLowerCase()) {
      return true
    }
  }
  return false
}

function mutate_buf(ptr, size, arg_i) {
  let buf = Memory.readByteArray(ptr, size);
  let buf_view = new Uint8Array(buf);
  // deep copy buf
  let new_buf = new ArrayBuffer(size);
  let new_buf_view = new Uint8Array(new_buf);
  for (let i = 0; i < size; i++) {
      if (Math.random() < 0.9) {
        new_buf_view[i] = buf_view[i];
      }else{
        new_buf_view[i] = buf_view[i] + Math.floor(Math.random() * 10) - 5;
        }
    }
  Memory.writeByteArray(ptr, new_buf_view);
  console.log("Mutating buffer arg " + arg_i);
  console.log("From:");
  console.log(buf);
  console.log("To:");
  console.log(new_buf);
}

function mutate_args(args, f_args_infos) {
  for (let i = 0; i < f_args_infos.length; i++) {
    let arg_info = f_args_infos[i].toLowerCase();
    if(Math.random() > 0.05){
        continue;
    }
    if (arg_info.includes("in") && arg_info.includes("buf")) {
      mutate_buf(args[i], 0x50, i);
    }
    else if (arg_info.includes("in") && arg_info.includes("*")) {
      mutate_buf(args[i], 0x20, i);
    }
    else if (arg_info.includes("pvoid")) {
      mutate_buf(args[i], 0x20 , i);
    }
    else if (arg_info.includes("_in_reads_")) {
      mutate_buf(args[i], 0x50,);
    }
  }
}

"""

process_module = """
setTimeout(function() {
  Process.enumerateModules({
    onMatch: function(module) {
      //console.log("Found " + module.name + " at " + module.base);
      if (lib_includes(module.name, Object.keys(sys_data))) {
        let exports = module.enumerateExports();
        let module_name = module.name.toLowerCase();
        for (let f_name in sys_data[module_name]) {
          // call random function
          
          let infos = sys_data[module_name][f_name];
          let ea = infos["addr"]
          ea = module.base.add(ptr(ea));
          funcs_map[ea] = [f_name, module.name]
          try {
            //console.log("Hooking " + f_name + " at " + ea);
            Interceptor.attach(ea, {
              onEnter: function(args) {
                let f_name = funcs_map[this.context.pc][0];
                let module_name = funcs_map[this.context.pc][1];
                console.log(f_name); 
                let rcx = this.context.rcx;
                let rdx = this.context.rdx;
                let r8 = this.context.r8;
                let r9 = this.context.r9;
                let syscall_args = [rcx, rdx, r8, r9];
                let arg_index = 0;
                let stack_arg = Memory.readPointer(this.context.rsp.add(arg_index * Process.pointerSize));
                while (stack_arg != 0 && arg_index < 4) {
                  stack_arg = Memory.readPointer(this.context.rsp.add(arg_index * Process.pointerSize));
                  syscall_args.push(stack_arg);
                  arg_index++;
                }
                let f_args_infos = sys_data[module_name][f_name]["args"];
                for (let i = 0; i < syscall_args.length; i++) {
                  let arg_info = "";
                  if (i < f_args_infos.length) {
                    arg_info = f_args_infos[i];
                  }
                  console.log("Arg " + i + ": " + " " + arg_info + " " + syscall_args[i]);
                }
                mutate_args(syscall_args, f_args_infos);
                
              }
            });
          } catch (e) {
            console.log("Error: " + e);
          }
        }
      }
    },
    onComplete: function() {
    }
  });
}, 500);
"""




def clean(exe):
    # powershell command to kill all notepad processes
    os.system("taskkill /f /im {}".format(exe))


def match(args):
    valid_matches = [
        ["in", "buf"],
        ["in", "*"],
        ["PVOID"],
        ["_in_reads_"],
        ["_out_writes_bytes_"],
    ]

    for match in valid_matches:
        for arg in args:
            arg = arg.lower()
            if all([x in arg for x in match]):
                return True
    return False


def match_func_name(f_name):
    invalid_matches = [
        "free",
        "alloc",
        "malloc",
        "realloc",
        "copy",
        "move",
        "duplicate",
        "dup",
        "token",
        "hook",
        "call"
    ]
    for match in invalid_matches:
        if match in f_name.lower():
            return False
    return True


def filter(sys_data):
    filtered_sys_data = {}
    for lib in sys_data:
        filtered_sys_data[lib] = {}
        for f_name, f_info in sys_data[lib].items():
            if not match_func_name(f_name):
                print(f"Skipping {f_name}")
                continue
            args = f_info["args"]
            if match(args):
                filtered_sys_data[lib][f_name] = sys_data[lib][f_name]
                print(f"Keeping {f_name}")
    return filtered_sys_data


def replace_all(text, dic_vars):
    for i, j in dic_vars.items():
        text = text.replace(i, j)
    return text


def build_script(dict_vars):
    script = replace_all(global_var, dict_vars)
    script += common
    script += process_module
    return script
  
def async_launch(script, path, pids, i):
    # spawn process and pause it
    try:
      pid = frida.spawn(path)
      session = frida.attach(pid)
      script_s = session.create_script(script)
      script_s.load()
      # wait for script to finish to hook
      time.sleep(1)
      print("Resuming {} with pid {}".format(path, pid))
      frida.resume(pid)
      pids[i] = pid
    except Exception as e:
      pass

def fuzzer_thread(script, process_to_fuzz):

    MAX_THREADS = 4
    pids = [0] * MAX_THREADS
    INTERVAL = 3
    exe = process_to_fuzz["name"]
    path = process_to_fuzz["path"]
    try:
        while True:
            for i in range(MAX_THREADS):
                async_launch(script, path, pids, i)
            # wait 15 seconds
            time.sleep(INTERVAL)
            # detach and kill processes
            clean(exe)

    except KeyboardInterrupt:
          clean(exe)
          sys.exit(0)


parser = argparse.ArgumentParser(description="Function definitions")
parser.add_argument("config", metavar="config", type=str, help="Json file containing function definitions")
parser.add_argument(
    "sys_data",
    metavar="sys_data",
    type=str,
    help="Json file containing function definitions",
)
parser.add_argument(
    "p_index",
    metavar="p_index",
    type=int,
    help="Process index to fuzz",
)
args = parser.parse_args()
sys_data = json.load(open(args.sys_data, "r"))
programs = json.load(open(args.config, "r"))["programs"]
process_to_fuzz = programs[args.p_index]


sys_data = filter(sys_data)
dict_vars = {
    "$$sys_data$$": json.dumps(sys_data),
}
script = build_script(dict_vars)

with open("debug_script.js", "w") as f:
    f.write(script)

fuzzer_thread(script, process_to_fuzz)
