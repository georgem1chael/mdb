# mdb - Minimal Debugger

mdb is a lightweight debugger for Linux x86_64 non-pie binaries built using ptrace.

## Features
- Load ELF symbols using libelf
- Set breakpoints (symbol or address)
- Continue execution
- Single-step execution (si)
- Disassemble instructions using Capstone
- Inspect execution flow at runtime

## Commands
- b <symbol|*addr> : set breakpoint
- l                : list breakpoints
- d <n>            : delete breakpoint
- r                : run program
- c                : continue execution
- si               : single-step
- disas            : disassemble at RIP
- q                : quit

## Build
gcc -Wall mdb.c -lelf -lcapstone -o mdb

## Example
./mdb ./test
(mdb) b main
(mdb) r
(mdb) disas
(mdb) si

## Tech
- ptrace
- libelf
- capstone
