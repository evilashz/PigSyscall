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