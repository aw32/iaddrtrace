# iaddrtrace

Use ptrace to singlestep a program and print the trace of instruction addresses.
Start addresses are turned into breakpoints.
Tracer is detached after stop addresses.


## Program structure

The program uses the `ptrace` API to trace the tracee child process.
Once ptrace is setup, the tracee process is interrupted and the tracer notified.
The tracer process uses `waitpid` to wait for the tracee interrupt.
Now the tracer can use `ptrace` to inspect and manipulate the tracee process.
When the tracer is done it can continue the tracee process and wait for the next event.


## Usage

```
    iaddrtrace [options] [--] program [arguments]
    Options:
        -s ADDR     -- Comma-separated list of addresses to start the output in hex
        -d ADDR     -- Comma-separated list of addresses to stop the output in hex
        -o FILE     -- Use FILE instead of stdout
        -m FILE     -- Write /proc/PID/maps to FILE
        -n          -- Spin instead of waiting
        -i          -- Print memory at address
        -k          -- Kill tracee on trace end
        -p          -- Keep ASLR on
```

`-m`
At the end of the trace, the contents of /proc/$PID/maps will be printed to save the mapped segments of the loaded libraries.
This helps to link the printed addresses to the libraries.
The content is appended to the given file.

`-n`
Usually the tracer waits for the next tracee event by calling `waitpid`.
However, the tracer is blocked by the call and is woken up once the event arrives.
Since the tracer is waiting, the kernel scheduler may add delay when waking up the tracer process.
By using the non-blocking `waitpid` call, the tracer immediatelly continues without waiting for an event.
Now the tracer can loop on the `waitpid` call, without being suspended for a longer time.
This minimizes the waiting time for the tracer process at the expense of an increase in user and kernel time,
that is spend in unsuccessful `waitpid` calls.

`-i`
This option reads 8 bytes from memory pointed to by the instruction pointer EIP.
The bytes are written in hex.
The bytes should contain the opcode for the next instruction and subsequent bytes.
The bytes need to be decoded to get the instruction length and the instruction mnemonic.

`-k`
Once the trace is finished, the tracer detaches from the tracee process.
Now the tracee can continue execution without interrupt.
Alternatively, the tracee process can be killed.

`-p`
Address space layout randomization (ASLR) is used as security feature to randomize the position of loaded segments.
Deactivating ASLR leads to more deterministic segment positions.
Use this option to keep it turned on.


## Examples

### Create address trace and map to objdump instructions

Create trace for `sleep`:
```
$ ./iaddrtrace -i -m sleep.maps -o sleep.trace sleep 1
$ cat sleep.trace # excerpt
7ffff7d9f36f ffd1498bbe080100
555555556000 f30f1efa4883ec08
555555556004 4883ec08488b0511
555555556008 488b05115f000048
55555555600f 4885c07402ffd048
```
The trace contains the address of the next instruction and the bytes located at the address.

Check which binaries/libraries are loaded:
The loaded libraries are listed in the maps file:
```
$ cat sleep.maps # excerpt
555555556000-555555559000 r-xp 00002000 103:03 25440903                  /usr/bin/sleep
7ffff7d72000-7ffff7d9e000 r--p 00000000 103:03 25431522                  /usr/lib/libc.so.6
7ffff7fc6000-7ffff7fc8000 r--p 00000000 103:03 25431499                  /usr/lib/ld-linux-x86-64.so.2
```

Create objdumps:
```
$ objdump -w -d /usr/bin/sleep > sleep.objdump
$ objdump -w -d /usr/lib/libc.so.6 > libc.so.6.objdump
$ objdump -w -d /usr/lib/ld-linux-x86-64.so.2 > ld-linux-x86-64.so.2.objdump
$ cat sleep.objdump # excerpt
0000000000002000 <.init>:
    2000:       f3 0f 1e fa             endbr64 
    2004:       48 83 ec 08             sub    $0x8,%rsp
    2008:       48 8b 05 11 5f 00 00    mov    0x5f11(%rip),%rax        # 0x7f20
    200f:       48 85 c0                test   %rax,%rax
```

The `addr2asm_trace.py` tool can be used to link the addresses to the instructions from the objdumps:
```
$ python addr2asm_trace.py --prepend-address sleep.maps sleep.trace libc.so.6.objdump sleep.objdump ld-linux-x86-64.so.2.objdump > sleep.instr
$ cat sleep.instr # excerpt
7ffff7d9f36f:     ff d1                	call   *%rcx
555555556000:     f3 0f 1e fa          	endbr64
555555556004:     48 83 ec 08          	sub    $0x8,%rsp
555555556008:     48 8b 05 11 5f 00 00 	mov    0x5f11(%rip),%rax        # 0x7f20
55555555600f:     48 85 c0             	test   %rax,%rax
```

### Create trace for throughput analysis with `llvm-mca`

Example code with nested loops:
```
#include <stdio.h>

int main(int argc, char** argv) {

    double x[10];
    double y[10];
    double z[10];

    // initialize
    for (unsigned int i=0; i<10; i++) {
        x[i] = i;
        y[i] = i*i;
    }

    // compute
    for (unsigned int i=0; i<10; i++) {
        for (unsigned int j=0; j<10; j++) {
            z[i] = x[i] + y[j];
        }
    }

    // output
    for (unsigned int i=0; i<10; i++) {
        printf("%e ", z[i]);
    }
    printf("\n");
    
    return 0;
}
```
Compile
```
$ clang -o example example.c
```
Find address range of interest
```
$ objdump --visualize-jumps=extended-color -d example
[..]
    11df:	             00 00 00 
    11e2:	/----------> 83 bd e8 fe ff ff 0a 	cmpl   $0xa,-0x118(%rbp)
    11e9:	|  /-------- 0f 83 6e 00 00 00    	jae    125d <main+0x10d>
    11ef:	|  |         c7 85 e4 fe ff ff 00 	movl   $0x0,-0x11c(%rbp)
    11f6:	|  |         00 00 00 
    11f9:	|  |     /-> 83 bd e4 fe ff ff 0a 	cmpl   $0xa,-0x11c(%rbp)
    1200:	|  |  /--|-- 0f 83 3e 00 00 00    	jae    1244 <main+0xf4>
    1206:	|  |  |  |   8b 85 e8 fe ff ff    	mov    -0x118(%rbp),%eax
    120c:	|  |  |  |   f2 0f 10 44 c5 a0    	movsd  -0x60(%rbp,%rax,8),%xmm0
    1212:	|  |  |  |   8b 85 e4 fe ff ff    	mov    -0x11c(%rbp),%eax
    1218:	|  |  |  |   f2 0f 58 84 c5 50 ff 	addsd  -0xb0(%rbp,%rax,8),%xmm0
    121f:	|  |  |  |   ff ff 
    1221:	|  |  |  |   8b 85 e8 fe ff ff    	mov    -0x118(%rbp),%eax
    1227:	|  |  |  |   f2 0f 11 84 c5 00 ff 	movsd  %xmm0,-0x100(%rbp,%rax,8)
    122e:	|  |  |  |   ff ff 
    1230:	|  |  |  |   8b 85 e4 fe ff ff    	mov    -0x11c(%rbp),%eax
    1236:	|  |  |  |   83 c0 01             	add    $0x1,%eax
    1239:	|  |  |  |   89 85 e4 fe ff ff    	mov    %eax,-0x11c(%rbp)
    123f:	|  |  |  \-- e9 b5 ff ff ff       	jmp    11f9 <main+0xa9>
    1244:	|  |  \--/-X e9 00 00 00 00       	jmp    1249 <main+0xf9>
    1249:	|  |     \-> 8b 85 e8 fe ff ff    	mov    -0x118(%rbp),%eax
    124f:	|  |         83 c0 01             	add    $0x1,%eax
    1252:	|  |         89 85 e8 fe ff ff    	mov    %eax,-0x118(%rbp)
    1258:	\--|-------- e9 85 ff ff ff       	jmp    11e2 <main+0x92>
    125d:	   \-------> c7 85 e0 fe ff ff 00 	movl   $0x0,-0x120(%rbp)
    1264:	             00 00 00
[..]
```
For example `0x11e2` to `0x125d` should contain the nested loop.
```
$ objdump -p example
LOAD off    0x0000000000001000 vaddr 0x0000000000001000 paddr 0x0000000000001000 align 2**12
     filesz 0x00000000000002e9 memsz 0x00000000000002e9 flags r-x
```
The LOAD entry shows that the segment is mapped at the same offset (relative to the base address) as in the binary.
To find the final address, you can do a test trace or halt the program in `gdb`.
See below for a discussion on address mapping.
The destination address range for the segment:
```
555555555000-555555556000 r-xp 00001000
```
Now create a trace:
```
$ iaddrtrace -s 5555555551e2 -d 55555555525d -o example_f.trace -m example_f.maps ./example
```
Now use `objdump` to disassemble the instructions:
```
$ objdump -w -d ./example > example.objdump
```
Use the `addr2asm_trace.py` script to map the addresses to the disassembly:
```
$ python addr2asm_trace.py --print-instructions example.maps example.trace example.objdump > example.ins
```
You can count the `addsd` instructions (or a specific address in the trace) used to compute the sum.
This can be used to double check the trace:
```
$ grep addsd example.ins | wc -l
100
$ grep 555555555218 example.trace | wc -l
100
```
For branches the objdump instructions contain the immediate numbers and offsets relative to the target sections.
These need to be preprocessed for `llvm-mca`:
```
# Turns 'jmp    11f9 <main+0xa9>' into 'jmp    0x11f9 #<main+0xa9>'
$ sed -i 's/\([0-9a-h]*\) \(<[^>]*>\)/0x\1 #\2/' example.ins
```
The assembly can now be passed to `llvm-mca` for throughput analysis:
```
$ llvm-mca --march=x86-64 --mcpu=skx < example.ins
Iterations:        100
Instructions:      130300
Total Cycles:      36566
Total uOps:        162400

Dispatch Width:    6
uOps Per Cycle:    4.44
IPC:               3.56
Block RThroughput: 365.5
[..]
```

### Create trace for throughput analysis with `iaca`

The process is similar to `llvm-mca`, however `iaca` accepts binary instead of source code.
For this, instead of instructions, the raw opcodes need to be mapped to the trace addresses.
```
$ python ../addr2asm_trace.py --prepend-bin "bb 6f 00 00 00   64 67 90" --append-bin "bb de 00 00 00   64 67 90" --print-opcodes-bin example.bin example.maps example.trace example.objdump
```
This creates a binary file `example.bin` containing the binary opcodes of the traced instructions.
The binary is prefixed/suffixed with a magic byte sequence that marks the region that `iaca` will analyze.
```
$ iaca -arch SKX example.bin
[..]
Throughput Analysis Report
--------------------------
Block Throughput: 429.00 Cycles       Throughput Bottleneck: Backend
Loop Count:  22
[..]
```



## Address mapping:

The loader loads segments from the program binary and linked libraries into the address space of the process.
This happens at the start of the process or at runtime, when the process loads further libraries.
In the above example from the sleep binary the segment at the offset `00002000` is mapped into the process
address space at the position `555555556000-555555559000`:
```
address                   perms offset   dev    inode                     pathname
555555556000-555555559000 r-xp  00002000 103:03 25440903                  /usr/bin/sleep
```
Objdump decoded the instruction from the binary at the offset `2004`:
```
    2004:       48 83 ec 08             sub    $0x8,%rsp
```
In the trace the instruction is located the address `555555556004`:
```
555555556004 4883ec08488b0511
```
The bytes contain the instruction opcode `4883ec08`.
By using the python script the address from the trace can be mapped to the instructions decoded by objdump:
```
555555556004:     48 83 ec 08           sub    $0x8,%rsp
```
Objdump shows the `LOAD` entry in the program header, that defines how the segment is mapped:
```
$ objdump -p /bin/sleep
    LOAD off    0x0000000000002000 vaddr 0x0000000000002000 paddr 0x0000000000002000 align 2**12
         filesz 0x0000000000002c41 memsz 0x0000000000002c41 flags r-x
```
Depending on the executable, segments are mapped to different base addresses in the virtual address space of the process.

For static executables the OS/compiler/linker decide the base address.
See [Stackoverflow: Why Linux/gnu linker chose address 0x400000?](https://stackoverflow.com/questions/14314021/why-linux-gnu-linker-chose-address-0x400000).
```
# File:
ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 4.4.0, not stripped
# Readelf:
Type:                              EXEC (Executable file)
# Mapping for statically linked example
00401000-0048e000 r-xp 00001000
```
For dynamically linked executables it depends if the program is compiled as 'position independent executable (PIE)'.
```
# File:
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, not stripped
# Readelf:
Type:                              DYN (Position-Independent Executable file)
# Mapping for PIE
555555555000-555555556000 r-xp 00001000
```
The kernel decides the base address for the mapping.
See [Stackoverflow: How is the address of the text section of a PIE executable determined in Linux?](https://stackoverflow.com/questions/51343596/how-is-the-address-of-the-text-section-of-a-pie-executable-determined-in-linux).

Dynamically linked programs can also be compiled without position independent code (PIC):
```
$ gcc -fno-pic -o example_nopic example.c
# File:
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, not stripped
# Readelf:
Type:                              EXEC (Executable file)
# Mapping for non-PIE
00401000-00402000 r-xp 00001000
```

### Address space layout randomization (ASLR):

Depending on the os configuration, the segments are mapped at random locations in the process address space.
ASLR is a security feature, but makes address mapping difficult.
`iaddrtrace` uses the `personality` API to turn off ASLR for the tracee.
This can also be done using the `setarch` tool.


### Alternatives to check the address mapping:

```
# shows list of libraries dynamically linked at compile time
$ ldd /usr/bin/sleep

# shows sections in program header
$ setarch -R objdump -p /usr/bin/sleep

# stops at `main` and prints mapped sections
$ setarch -R gdb -ex "b -force-condition main" -ex "run 1" -ex "maintenance info sections" /bin/sleep

# shows dynamic mappings
$ setarch -R env LD_DEBUG=all env LD_DEBUG_OUTPUT=ld.log ld.so /bin/sleep 1

# only shows mappings at runtime
$ setarch -R strace -e openat,mmap /bin/sleep 1
```




## References

* [Writing a Linux Debugger](https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)
* [LLVM-MCA](https://llvm.org/docs/CommandGuide/llvm-mca.html)
* [Intel Architecture Code Analyzer (IACA)](https://www.intel.com/content/www/us/en/developer/articles/tool/architecture-code-analyzer.html)
