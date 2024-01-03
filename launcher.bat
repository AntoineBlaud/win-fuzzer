@echo off
setlocal enabledelayedexpansion

REM Set the ITER variable to the desired value
set ITER=4

REM Run the command in a loop until ITER is reached
for /L %%i in (0,1,%ITER%) do (
    start "Program %%i"  python sys_hooker.py config.json syscalls.json %%i
)

echo All Programs Launched
pause