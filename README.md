# VChat TRUN: Bypassing DEP with ROP Intro
> [!NOTE]
> - The following exploit and its procedures are based on an original [Blog](https://fluidattacks.com/blog/bypassing-dep/) from fluid attacks.
> - Disable Windows *Real-time protection* at *Virus & threat protection* -> *Virus & threat protection settings*.
> - Don't copy the *$* sign when copying and pasting a command in this tutorial.
> - Offsets may vary depending on what version of VChat was compiled, the version of the compiler used, and any compiler flags applied during the compilation process.
___
This exploit will focus on the basics of [Return Oriented Programming](https://dl.acm.org/doi/10.1145/2133375.2133377), this is a technique used in buffer overflows to overcome the protections provided by Non-eXecutable (NX) memory segments enabled with protections like [Data Execution Protection (DEP)](https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention) in Windows. We know from [VCHAT_DEP_Intro](https://github.com/DaintyJet/VChat_DEP_Intro) that attempting to execute code within a non-executable memory segment leads to an exception being raised. However, you may have noticed that we did get back to the stack containing the shellcode when the `RETN` instruction from the function we overflowed was executed; this is possible since the `RETN` instruction was code from the **code/text segment** of *essfunc.dll*, *vchat.exe* or some other library which contain executable code. This means by manipulating the stack, we can *chain* together segments of pre-existing code known as *gadgets* to gain control over the system. These gadgets when properly chained together allow us to preform exploits on systems with non-executable memory segments, ROP chains can often be used as a first stage to disable protections on the target machine to allow further exploitation.


> [!IMPORTANT]
> Please set up the Windows and Linux systems as described in [SystemSetup](./SystemSetup/README.md)!
## What is Return Oriented Programming (ROP)
Before proceeding with the exploitation process, we should understand Return-Oriented Programming (ROP) and how to perform an attack using the ROP method. This not only requires knowledge of how the stack works and the basics of assembly used so far but also a better understanding of how function calls and returns work. 

> [!IMPORTANT]
> With regards to calling a function the exact conventions used differ from architecture to architecture, however the basic principles if not the [complexity](https://dl.acm.org/doi/10.1145/3545948.3545997) are maintained.

### Understanding function calls
The end goal of a ROP chain, more often than not, is to call a function, often to configure the current process to enable further exploitation rather than chaining gadgets to directly run an exploit. For example, this could be disabling protections like those on the stack memory page that prevent direct execution of shellcode. Function calls and their characteristics such as how we need to load arguments onto the stack or registers and how the return value is passed back to the calling function differ from architecture to architecture. Generally, in order to make a function call, we will need to setup the arguments for the target function; depending on the architecture, this could be pushing values to the stack or loading values into specific registers. In the case of the 32-bit x86 architecture our VChat server runs on, to make a function call, we need to push all of the arguments for the function onto the stack as has been done in the previous exploits.

For example if we have made a function call to `recv(SOCKET s, char* buff, int len, int flags)` in the [VChat_KSTET_MULTI](https://github.com/DaintyJet/VChat_KSTET_Multi) shellcode, we will have created the following stack on an *x86* 32-bit architecture once the call instruction has been executed.

> [!NOTE]
> In a x86-64, 64-bit architecture, these arguments would need to be stored on the stack, which increases complexity as additional gadgets are required to do these operations, which increases complexity.

<img src="Images/I4.png" width=400>

We have highlighted the function arguments in orange, the return address in red and the base pointer which is used to access the function arguments and local variables is highlighted in purple. The return address, old ebp, and local variables are created at the time of, or after the call instruction has been executed.

> [!NOTE]
> A *gadget* refer to a segment of exiting code that can be used in an exploit to perform a specific action. This could be a gadget that loads a value into a register before returning, or it can make a call to an address specified in a register before performing some actions; these are any usable segments of code in the target program. Generally each gadget will end with a `RETN` statement so we can chain them together and execute them in sequence.

We need to setup the stack in a way to make a series of function calls in the x86 architecture as all the function arguments are located on the stack; this is not too difficult as a buffer overflow vulnerability often directly writes to the stack. When performing a ROP attack we may find writing to registers and later writing those register values to onto the stack with a *gadget* an easier method as this can help prevent us from mangling the ROP chain during its execution. If we were on a different architecture, such as x86-64, where registers store some of the function arguments, this might make the ROP chains more complicated. When we enter into the function, the *prolog* will save the old `EBP` (Base pointer) value on the stack for us, so all we need to be concerned with after loading the arguments onto the stack is the return address that the function will return to on completion allowing us to chain calls together. If we are able to build the stack in such a way, we can chain together functions and, more often, *gadgets* by the return values we place onto the stack.

### Understanding returns
Function returns are slightly more complicated than they may first appear, they do use the `RETN` instruction to revert the control flow back to the caller, or in our case change the control flow to an address we specify. However, before this, the function resets the stack pointer to clear the local variables and will reset the base pointer so the calling function is able to access its arguments and local variables after the callee has returned. The *callee* does not remove the arguments that were placed on the stack, we would need to locate a *gadget* to clean up the arguments passed to the callee if and be the links between each of the function calls in the chain we are creating.

Below is an example function epilog, in addition to a before and after image of a stack for a call made to the `recv(SOCKET s, char* buff, int len, int flags)` function.
```s
mov	esp, ebp    ; Reset the stack pointer to be located above the local variables, pointing to the old base pointer
pop	ebp         ; load the old base pointer address so the caller can access its arguments and local variables
retn            ; Jump to the return address that has been placed on the stack (ESP)

; This may be shortened with the x86 instruction 'leave' which has the same effect
leave           ; Adjust the ESP register to point to EBP, and load the old EBP address on the stack into the EBP register 
retn            ; Jump to the return address that has been placed on the stack (ESP)
```

<img src="Images/I5.png" width=800>

> [!NOTE]
> The values on the stack from the previous call are still there after the `RET` instruction. However, once the `ESP` is adjusted to be above those values, we can consider them removed for the most part, as future operations on the stack will overwrite them. If the program were to exit or perform any additional operations on the stack, it is possible those values could remain for some time.

We could create a chain such as the following to perform the recv call and then return the control flow back to the stack. This is **idealized** for simplicity, generally, these chains are more complex and rather than directly calling a function after loading arguments onto the stack and then using a series of pop instructions to clear them, more often than not, we will build the arguments and target addresses further down the stack by loading them into registers and pushing them onto the stack, later using those created values to call the target function.


<img src="Images/I6.png" width=800>

The above image shows an idealized ROP chain, where we set the stack such that we call the `recv` function first with a return address to a ROP gadget with the following signature:
```
pop eax
pop eax
pop eax
pop eax
retn
```
> [!NOTE]
> This is made up for simplicity; it is unlikely this kind of gadget would exist in all systems nor would this ROP chain be especially useful; a more realistic gadget could be ```add esp,0x10``` followed by a `retn`, however, in either case, this is an *idealized* ROP chain to give an idea of how they work!

This allows us to return control flow to shell code injected after our ROP Gadget (at the higher addresses), as we would likely place the address of a `JMP ESP` gadget such that once the pop gadget finishes, it will return onto the stack through the `JMP ESP` instruction. Often, we will use a tool that allows us to construct a ROP chain.

## Pre-Exploitation
We will be exploiting the [TRUN](https://github.com/DaintyJet/VChat_TRUN) command for simplicity. For a more detailed overview of the initial analysis and exploitation of TRUN, please see the writeup. Because of this, we will not go over the compilation or exploration of `TRUN` as in-depth as in previous examples.

1. Open Immunity Debugger.

	<img src="Images/I1.png" width=800>

    * Note that you may need to launch it as the *Administrator* this is done by right-clicking the icon found in the Windows search bar or on the desktop as shown below:

	<img src="Images/I1b.png" width = 200>

2. Attach VChat: There are two options!
   1. When the VChat is already Running:
        1. Click File -> Attach.

			<img src="Images/I2a.png" width=200>

		2. Select VChat.

			<img src="Images/I2b.png" width=500>

   2. When VChat is not already Running:  -- This is the most reliable option!
        1. Click File -> Open, Navigate to VChat.

			<img src="Images/I3-1.png" width=800>

        2. Click Debug -> Run.

			<img src="Images/I3-2.png" width=800>

        3. Notice that a Terminal was opened when you clicked "Open". Now you should see the program output in the displayed terminal.

			<img src="Images/I3-3.png" width=800>

3. Ensure that the execution is not paused; click the red arrow (Top Left).

	<img src="Images/I3-4.png" width=800>

## Exploit: ROP By Hand
Now we will generate a ROP chain by hand, this will hopefully provide greater clarity as to how a ROP chain works, and how we can construct them. First we will need to have a goal, in this case we should load a specific value into a register so we can see clearly if our "exploit" has succeeded. If we are able to do this, we can eventually do a full exploit (Often with the help of some tools!). We will attempt to write the value `0xabcdabba` into a register, as it is commonly used. The `EAX` register is a good choice for this, as the convention on x86 systems is that the return value of a function is stored in the `EAX` register gadgets like the command `POP EAX` followed by a `RETN` are not impossible to find.

> [!IMPORTANT]
> The offsets and addresses shown in the following screenshots may differ from those used in the python and ruby code in this repository. This is because the offsets change slightly between the Windows 10 version of VChat compiled with GCC and the Windows 11 version compiled with the Visual Studio compiler.

1. We first need to plan out the shell code we want to execute in order to perform this operation; below is a simple set of assembly instructions we could have used in previous exploits:
	```
	xor eax, eax           ; Clear out the EAX register, we do not know what may be stored there
	add eax, 0xabcdabb9    ; Add set eax = 0 + 0xabcdabb9 (One off from the goal so we can make the chain more interesting)
	inc eax                ; Get final value of eax
	```
2. We now need to find the address of a `RETN` instruction we will inject into our stack to overwrite the original return address so we can start the ROP chain. To test this, we can make our exploit file reflect [exploit0.py](./SourceCode/exploit0.py), which will inject the shellcode as we have done in past exploits to observe the behavior of the `RETN` instruction.
	1. Open VChat and attach it to the Immunity Debugger, as has been done in the past. Then, run the following command in the interpreter at the bottom.
		```
		!mona find -type instr -s "retn" -p 20 -o
		```
		* `!mona`: Run mona.py commands.
		* `find`: Locate something withing the binary which has been loaded into Immunity debugger.
		* `-type`: Specify the type of the object string we are searching for.
			* `asc`: Search for an asci string.
			* `bin`: Search for a binary string.
			* `ptr`: Search for a pointer (memory address).
			* `instr`: Search for an instruction.
			* `file`: Search for a file.
		* `-s "<String>"`: Specify the string we are searching for.
		* `-p <number>`: Limit amount of output to the number we specify (May need to increase this to find instructions at an executable location).
		* `-o`: Omit OS modules.

		<img src="Images/I7.png" width=800>

		* We can see the output contains some valid choices, as *essfunc.dll* does not have ASLR enabled choosing one of those addresses allows us to maintain better portability as it will not change between executions. In this case I chose `0x6250508F`.

	2. Now we can generate the assembly we previously discussed in [shellcode0.asm](./SourceCode/shellcode0.asm) using the `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb` program on the *Kali Linux* system.

		https://github.com/user-attachments/assets/b32db3c5-0c81-4ff9-95f3-5ca7e60a5121

	3. Next modify the address we overwrite in the exploit code to reflect [exploit0.py](./SourceCode/exploit0.py), with the basic instructions assembled from before and observe the results.

		https://github.com/user-attachments/assets/42fb9fb9-8293-4b94-b9cc-3fcc0a484c7d

		1. Click on the black button highlighted below, and enter the address we decided in the previous step.

			<img src="Images/I8.png" width=600>

		2. Set a breakpoint at the desired address (right-click); in this case, I chose `0x6250508F`.

			<img src="Images/9.png" width=600>

		3. Observe the EIP register it has the value `0xB905C031` this is a mix of our shell code `\x31\xc0` from the `XOR EAX,EAX` instruction and `\x05\xb9` is a part of the `ADD eax,0xabcdabb9` instruction.

			<img src="Images/I10.png" width=600>

3. We can see if we write a *return address* 4-bytes after the address of the `RETN` instruction, we will once again gain control of the execution flow, so now we need to find an address for this location. Since we are unlikely to find an instruction like `ADD eax,0xabcdabba`, we would be better off looking for an instruction that uses the stack to set the value of a register. Luckily, we can look for an instruction like `POP EAX` followed by a `RETN`.

	https://github.com/user-attachments/assets/bf6b245b-7248-41f2-96bf-eb8c226e4767


	1. Open VChat and attach it to the Immunity Debugger as has been done in the past, right click the CPU view and select *essfunc.dll*.

		<img src="Images/I11.png" width=600>

	2. Use the `CTL+S` keybind to open the command sequence search option and search for the `POP EAX` and `RETN` sequence.

		<img src="Images/I12.png" width=600>

	3. Extract the address of the `POP EAX` instruction.

4. Now we can modify our exploit code to reflect [exploit1.py](./SourceCode/exploit1.py) and verify that the code is executed.

	https://github.com/user-attachments/assets/bcdfbe11-4651-4293-adfa-35b1f980c09a

	1. Click on the black button highlighted below, and enter in the address we decided earlier.

		<img src="Images/I8.png" width=600>

	2. Set a breakpoint at the desired address (right-click). In this case, I chose `0x6250508F`, the address of our `RETN` instruction.

		<img src="Images/9.png" width=600>

	3. Observe the flow of control. We should return to the `POP EAX` and `RETN` sequence. Notice that the stack has the data we wanted to load, `0xABCDABB9`. Once we step through the `POP EAX` instruction, we will see it has been loaded into the `EAX` register.

		<img src="Images/I13.png" width=600>

5. Now we can search for an `INC EAX` instruction. After this, we do not care what happens as we will have achieved the desired value `0xABCDABB9`. If we were concerned with what occurred after this, we would have simply put the `0xABCDABBA` value onto the stack and used the `RETN` value to jump to another gadget. 

	https://github.com/user-attachments/assets/e4312d62-0598-4f76-9520-38e9d5310a55

	1. Open VChat and attach it to the Immunity Debugger, as you have in the past. Right-click the CPU view and select *essfunc.dll*.

		<img src="Images/I11.png" width=600>

	2. Use the `CTL+S` keybind to open the command sequence search option and search for the `POP EAX` and `RETN` sequence.

		<img src="Images/I14.png" width=600>

	3. Alternatively, you could use the following command.
		```
		!mona find -type instr -s "INC EAX" -p 10
		```
		* `!mona`: Run mona.py commands.
		* `find`: Locate something withing the binary which has been loaded into Immunity debugger.
		* `-type`: Specify the type of the object string we are searching for.
			* `asc`: Search for an asci string.
			* `bin`: Search for a binary string.
			* `ptr`: Search for a pointer (memory address).
			* `instr`: Search for an instruction.
			* `file`: Search for a file.
		* `-s "<String>"`: Specify the string we are searching for.
		* `-p <number>`: Limit the amount of output to the number we specify.
6. Now we can add this address to our exploit as shown in [exploit2.py](./SourceCode/exploit2.py)

	https://github.com/user-attachments/assets/03f9628a-4795-4c4f-a57e-c18f7d96a9d5

	1. Click on the black button highlighted below, and enter in the address we decided earlier.

		<img src="Images/I8.png" width=600>

	2. Set a breakpoint at the desired address (right-click). In this case, I chose `0x6250508F`, the address of our `RETN` instruction.

		<img src="Images/9.png" width=600>

	3. Observe the flow of control. We should first return to the `POP EAX` and `RETN` sequence. Then, due to the address we have placed onto the stack, we should jump to the `INC EAX` instruction.

		<img src="Images/15.png" width=600>

## Attack Mitigation Table
In this section, we will discuss the effects a variety of defenses would have on *this specific attack* on the VChat server; specifically we will be discussing their effects on a buffer overflow that directly overwrites a return address in order to execute a chain of gadgets to disable protections on the stack and attempts to execute shellcode that has been written to the stack. We will make a note that these mitigations may be bypassed if the target application contains additional vulnerabilities.

First, we will examine the effects of individual defenses on this exploit, and then we will examine the effects of a combination of these defenses on the VChat exploit.

The mitigations we will be using in the following examination are:
* [Buffer Security Check (GS)](https://github.com/DaintyJet/VChat_Security_Cookies): Security Cookies are inserted on the stack to detect when critical data such as the base pointer, return address or arguments have been overflowed. Integrity is checked on function return.
* [Data Execution Prevention (DEP)](https://github.com/DaintyJet/VChat_DEP_Intro): Uses paged memory protection to mark all non-code (.text) sections as non-executable. This prevents shellcode on the stack or heap from being executed, as an exception will be raised.
* [Address Space Layout Randomization (ASLR)](https://github.com/DaintyJet/VChat_ASLR_Intro): This mitigation makes it harder to locate where functions and datastructures are located as their region's starting address will be randomized. This is only done when the process is loaded, and if a DLL has ASLR enabled it will only have it's addresses randomized again when it is no longer in use and has been unloaded from memory.
* [SafeSEH](https://github.com/DaintyJet/VChat_SEH): This is a protection for the Structured Exception Handing mechanism in Windows. It validates that the exception handler we would like to execute is contained in a table generated at compile time.
* [SEHOP](https://github.com/DaintyJet/VChat_SEH): This is a protection for the Structured Exception Handing mechanism in Windows. It validates the integrity of the SEH chain during a runtime check.
* [Control Flow Guard (CFG)](https://github.com/DaintyJet/VChat_CFG): This mitigation verifies that indirect calls or jumps are performed to locations contained in a table generated at compile time. Examples of indirect calls or jumps include function pointers being used to call a function, or if you are using `C++` virtual functions, which would be considered indirect calls as you index a table of function pointers.
* [Heap Integrity Validation](https://github.com/DaintyJet/VChat_Heap_Defense): This mitigation verifies the integrity of a heap when operations are performed on the heap itself, such as allocations or frees of heap objects.
### Individual Defenses: VChat Exploit
|Mitigation Level|Defense: Buffer Security Check (GS)|Defense: Data Execution Prevention (DEP)|Defense: Address Space Layout Randomization (ASLR) |Defense: SafeSEH| Defense: SEHOP | Defense: Heap Integrity Validation| Defense: Control Flow Guard (CFG)|
|-|-|-|-|-|-|-|-|
|No Effect| |X | |X |X | X| X| X|
|Partial Mitigation| | |X | | | | |
|Full Mitigation|X| | | | | | | |

---
|Mitigation Level|Defenses|
|-|-|
|No Effect|Data Execution Prevention (DEP), Address Space Layout Randomization, SafeSEH, SEHOP, Heap Integrity Validation, and Control Flow Guard (CFG) |
|Partial Mitigation|Address Space Layout Randomization|
|Full Mitigation|Buffer Security Checks (GS) |
* `Defense: Buffer Security Check (GS)`: This mitigation strategy proves effective against stack-based buffer overflows that overwrite a function's return address or arguments. This is because the randomly generated security cookie is placed before the return address, and its integrity is validated before the return address is loaded into the `EIP` register. As the security cookie is placed before the return address, in order for us to overflow the return address, we would have to corrupt the security cookie, allowing us to detect the overflow.
* `Defense: Data Execution Prevention (DEP)`: ROP chains bypass the DEP protections and are, therefore, ineffective.
* `Defense: Address Space Layout Randomization (ASLR)`: This defense partially mitigates this attack as it may randomize the addresses gadgets used in the ROP chain are located at. When enabled, this may be bypassed if all addresses are in external dependencies such as DLLs, which may not have their addresses randomized between executions unless the system reboots.
* `Defense: SafeSEH`: This does not affect our exploit as we do not leverage Structured Exception Handling.
* `Defense: SEHOP`: This does not affect our exploit as we do not leverage Structured Exception Handling.
* `Defense: Heap Integrity Validation`: This does not affect our exploit as we do not leverage the Windows Heap.
* `Defense: Control Flow Guard`: This does not affect our exploit as we do not leverage indirect calls or jumps.
> [!NOTE]
> `Defense: Buffer Security Check (GS)`: If the application improperly initializes the global security cookie or contains additional vulnerabilities that can leak values on the stack, then this mitigation strategy can be bypassed.
### Combined Defenses: VChat Exploit
|Mitigation Level|Defense: Buffer Security Check (GS)|Defense: Data Execution Prevention (DEP)|Defense: Address Layout Randomization (ASLR) |Defense: SafeSEH| Defense: SEHOP | Defense: Heap Integrity Validation| Defense: Control Flow Guard (CFG)|
|-|-|-|-|-|-|-|-|
|Defense: Buffer Security Check (GS)|X|**No Increase**: ROP Chains are used to bypass DEP.|**Increased Security**: ASLR increases the randomness of the generated security cookie and makes it harder to use ROP Gadgets reliably.|**No Increase**: The SEH feature is not exploited.|**No Increase**: The SEH feature is not exploited.|**No Increase**: The Windows Heap is not exploited.|**No Increase**: Indirect Calls/Jumps are not exploited.| |

> [!NOTE]
> We omit repetitive rows representing ineffective mitigation strategies as their cases are already covered.
## essfunc.dll Code
This section will discuss the [essfunc.dll](https://github.com/xinwenfu/vchat/blob/main/Server/essfunc.c) source code. This will not discuss the VChat code that handles the *TRUN* command as previously discussed [before](https://github.com/DaintyJet/VChat_TRUN/tree/main/).

The *essfunc.dll* code is contained in the [essfunc.c](https://github.com/xinwenfu/vchat/blob/main/Server/essfunc.c) code file. This library does not contain much in terms of functional code. There are a number of *EssentialFuncX* functions that contain assembly or code vulnerable to buffer overflows. This code is included to make the task of generating ROP Gadgets and finding useful instructions such as `JMP ESP` easier!

Below is a snippet of code from the essfunc.c file:
```c
void EssentialFunc2() {
	__asm__("jmp *%esp\n\t"
		"jmp *%eax\n\t"
		"pop %eax\n\t"
		"pop %eax\n\t"
		"ret");
}
```
This code uses the [GNU C Inline-Assembly](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html); using this in non-breaking ways is a fairly complicated endeavor, but in this case, the use and existence of these functions is to provide assembly instructions that may be used in our exploits and some that may provide useful gadgets when crafting ROP chains. Otherwise, they are not directly used in the VChat server from a basic overview.

## Test code
1. [exploit0.py](./SourceCode/exploit0.py): This code performs an overflow jumping to a `RETN` instruction.
2. [exploit1.py](./SourceCode/exploit1.py): This code adds a gadget containing a `POP EAX` and `RETN` instruction to the chain.
3. [exploit2.py](./SourceCode/exploit2.py): This code adds an instruction `INC EAX` to the chain.

## References
[[1] mona.py – the manual](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)

[[2] StackGuard: Automatic Adaptive Detection and Prevention of Buffer-Overflow Attacks](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)
