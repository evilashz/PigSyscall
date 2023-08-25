# PigSyscall



- Indirect Syscall

- Using Exception Directory to get SSNs

- Mask Syscall Stub in static file

- Dynamic decrypt stub and make Call

  

-----

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/imagesimage-20230825141014709.png)

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/imagesimage-20230825140928943.png)

> Pic from : https://conference.hitb.org/hitbsecconf2022sin/materials/D1T1%20-%20EDR%20Evasion%20Primer%20for%20Red%20Teamers%20-%20Karsten%20Nohl%20&%20Jorge%20Gimenez.pdf

-----

### Usage

Only support x64，C++ 17, Visual Studio

```c++
#include "PIGSyscall.hpp"

static auto& syscall = pigsyscall::syscall::get_instance();

#define NtAllocateVirtualMemory_Hashed  0x067D7D4F

int main() {

    void* allocation = nullptr;
    SIZE_T size = 0x1000;

    syscall.CallSyscall(NtAllocateVirtualMemory_Hashed,
        (HANDLE)-1,
        &allocation,
        0,
        &size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);


    getchar();
    
	return 0;
}

```

-----

### Todo (~~Maybe~~)

- HWBP Support
- argument spoofing
- make a trampoline of call through kernel32/user32

-----

### Reference

@Moriarty of RedCore

https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5faf4800-645d-49d1-9457-2ac40eb467bd

https://github.com/crummie5/FreshyCalls

https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/

