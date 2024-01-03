import argparse
import json
import frida
import sys
import random
import threading
import time
import os



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

function mutate_n(n, ratio){
  return n + Math.floor(Math.random() * ratio) - ratio/2;
}

function mutate_buf(ptr, size, arg_i) {
  let buf = Memory.readByteArray(ptr, size);
  let buf_view = new Uint8Array(buf);
  // deep copy buf
  let new_buf = new ArrayBuffer(size);
  let new_buf_view = new Uint8Array(new_buf);
  for (let i = 0; i < size; i++) {
      if (Math.random() < 0.7) {
        new_buf_view[i] = buf_view[i];
      }else{
        new_buf_view[i] = mutate_n(buf_view[i], 10)
        }
    }
  Memory.writeByteArray(ptr, new_buf_view);
  console.log("Mutating buffer arg " + arg_i);
  console.log("From:");
  console.log(buf);
  console.log("To:");
  console.log(new_buf);
}

function mutate_args(context, args, f_args_infos) {
  let syscall_args = ["rcx", "rdx", "r8", "r9"];
  for (let i = 0; i < args.length; i++) {
    if (Math.random() < 0.1) {
        try{
          Memory.readPointer(args[i]) 
          mutate_buf(Memory.readPointer(args[i]), 0x100, i);
        }catch(e){
          continue;
        }
    }
    else if (i < syscall_args.length && Math.random() < 0.01 ) {
        let reg_name = syscall_args[i];
        // convert to int
        let reg_val = parseInt(args[i]);
        let new_val = mutate_n(reg_val, 10000);
        context[reg_name] = new_val;
        let hex_val = "0x" + new_val.toString(16);
        console.log("Mutating " + reg_name + " from " + args[i] + " to " + hex_val);
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
                mutate_args(this.context, syscall_args, f_args_infos);
                
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
        for f_name in sys_data[lib]:
          if match_func_name(f_name):
            filtered_sys_data[lib][f_name] = sys_data[lib][f_name]
    return filtered_sys_data


def replace_all(text, dic_vars):
    for i, j in dic_vars.items():
        text = text.replace(i, j)
    return text


def build_script(sys_data):
    dict_vars = {
        "$$sys_data$$": json.dumps(sys_data),
    }
    script = replace_all(global_var, dict_vars)
    script += common
    script += process_module
    with open("debug_script.js", "w") as f:
        f.write(script)
    return script
  
def random_pick(funcs_map):
    DESIRED_FUNCS = 100
    r_funcs_map = {}
    for lib in funcs_map:
        p = (1 / len(funcs_map[lib])) * DESIRED_FUNCS
        r_funcs_map[lib] = {}
        for f_name, f_infos in funcs_map[lib].items():
            if random.random() < p:
              r_funcs_map[lib][f_name] = f_infos
    return r_funcs_map
  
def async_launch(script, path):
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
    except Exception as e:
      pass

def fuzzer_thread(sys_data, process_to_fuzz):

    MAX_THREADS = 4
    INTERVAL = 2
    exe = process_to_fuzz["name"]
    path = process_to_fuzz["path"]
    try:
        while True:
            for i in range(MAX_THREADS):
                # pick 100 random functions for each library
                r_funcs_map = random_pick(filter(sys_data))
                script = build_script(r_funcs_map)
                async_launch(script, path)
            # wait 
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
fuzzer_thread(sys_data, process_to_fuzz)
