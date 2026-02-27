## About
Packy is a simple packer/protector which encrypts text segment using xor, and injects decryptor stub using either code cave or PT\_NOTE injection.  
It also strips the binary so that a simple `objdump -d` won't output anything.

## Usage
`python packy.py <path> [options]`

Options:
- `-e`, `--entropy`  show entropy of text segment

## Example
```sh
[crusom@crusom packy]$ cat a.c
#include <stdio.h>
int main(){
  puts("hello world");
}
[crusom@crusom packy]$ gcc a.c -o a
[crusom@crusom packy]$ ./a
hello world
[crusom@crusom packy]$ python packy.py ./a
[crusom@crusom packy]$ ./a
hello world
[crusom@crusom packy]$ ./a_patched
hello world
[crusom@crusom packy]$ objdump -d ./a
./a:     file format elf64-x86-64

Disassembly of section .init:

0000000000001000 <_init>:
    1000:       f3 0f 1e fa             endbr64
    1004:       48 83 ec 08             sub    $0x8,%rsp
    1008:       48 8b 05 c1 2f 00 00    mov    0x2fc1(%rip),%rax        # 3fd0 <__gmon_start__>
    100f:       48 85 c0                test   %rax,%rax
    1012:       74 02                   je     1016 <_init+0x16>
<... lots of code>
[crusom@crusom packy]$ objdump -d ./a_patched

./a_patched:     file format elf64-x86-64
[crusom@crusom packy]$ readelf -a a_patched | grep point
  Entry point address:               0x1161
[crusom@crusom packy]$ objdump -D -b binary -m i386:x86-64 ./a_patched
<...>
    1161:       48 8d 35 98 fe ff ff    lea    -0x168(%rip),%rsi        # 0x1000
    1168:       48 c7 c1 61 01 00 00    mov    $0x161,%rcx
    116f:       80 74 0e ff 55          xorb   $0x55,-0x1(%rsi,%rcx,1)
    1174:       e2 f9                   loop   0x116f
    1176:       48 83 c6 40             add    $0x40,%rsi
    117a:       ff e6                   jmp    *%rsi
<...>
```
