# Win-fuzzer

## Overview

Win-fuzzer is a Windows fuzzing tool designed to efficiently discover vulnerabilities by launching and hooking system calls in `ntdll.dll` and `win32u.dll` using Frida. The tool allows you to modify buffer values and arguments through a mutation function to test the robustness of the target application.

## Prerequisites

Before using Win-fuzzer, make sure you have the following dependencies installed:

- Python
- Frida
- IDA (Interactive Disassembler)

## Setup

1. Clone the Win-fuzzer repository to your local machine.


2. Edit the `config.json` file to configure the necessary settings for your environment.

3. Run the system call scanner to generate a list of available system calls and save them to `syscalls.json`.

```bash
python sys_scanner.py config.json syscalls.json
```

4. Launch the system call hooker with the specified configuration and system call list. Optionally, provide the target program (e.g., `$PROG`) (0, 1, 2, 3, etc.).

```bash
python sys_hooker.py config.json syscalls.json $PROG
```

Alternatively, you can use the provided batch file for convenience:

```bash
.\launcher.bat
```

## Usage

1. Edit the `config.json` file to customize the configuration parameters according to your testing requirements.

2. Run the system call scanner to identify available system calls and create the `syscalls.json` file.

3. Launch the system call hooker to intercept and modify system calls. Optionally, provide the target program and choose a mutation level.

4. Observe the behavior of the target program and analyze the results to identify potential vulnerabilities.
