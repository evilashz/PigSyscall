#ifndef PIG_SYSCALL_HPP_
#define PIG_SYSCALL_HPP_

#include <intrin.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "native.hpp"
#include "util.hpp"

//填进去hash，避免出来string
// constexpr uint32_t hash
//using SyscallMap = std::unordered_map<uint32_t, uint32_t>;
//第一个存API Name，第二个则为SSN
using SyscallMap = std::unordered_map<uint32_t, uint32_t>;   //unordered_map使用hash表，查找效率快

using NtStatus = uint32_t;
extern uint8_t encrypted_manual_syscall_stub[];
extern uint8_t encrypted_masked_syscall_stub[];


namespace pigsyscall {

class syscall {

private:

    static inline SyscallMap syscall_map;

    static void ExtractSSNs() noexcept;
    
    // Private constructor
    syscall() noexcept {
        ExtractSSNs();
    };

    uintptr_t FindSyscallOffset() noexcept;
    
    template<typename... ServiceArgs>
    NtStatus InternalCaller(uint32_t syscall_no, uintptr_t stub_addr, ServiceArgs... args) noexcept {


    using StubDef = NtStatus(__stdcall*)(uint32_t, ServiceArgs...);
    StubDef stub = reinterpret_cast<decltype(stub)>(stub_addr);
    //decrypt stub
    //strlen maybe not beauty?
    pigsyscall::utils::CryptPermute((PVOID)stub_addr, strlen((char*)stub_addr), FALSE);
    NtStatus return_value = stub(syscall_no, std::forward<ServiceArgs>(args)...);   //完美转发，是指std::forward会将输入的参数原封不动地传递到下一个函数中

    return 1;
}

public:

    // Disable any other constructor or assignment operator
    syscall(const syscall&) = delete;
    syscall& operator=(const syscall&) = delete;
    syscall(syscall&&) = delete;
    syscall& operator=(syscall&&) = delete;

    // Singleton instance getter
    // 单例模式构造
    static inline syscall& get_instance() noexcept {
        static syscall instance{};
        return instance;
    }

    [[nodiscard]] uint32_t GetSyscallNumber(uint32_t stub_name_hashed);

    template<typename... ServiceArgs>
    NtStatus CallSyscall(uint32_t stub_name_hashed, ServiceArgs... args) {
        uint32_t syscall_no;
        uintptr_t stub_addr;
        uintptr_t syscall_inst_addr;

        syscall_no = GetSyscallNumber(stub_name_hashed);
        syscall_inst_addr = FindSyscallOffset();

        // If the syscall instruction has not been found, use the direct stub. To use the masked stub
        // we need the instruction to be in the original stub.
        if (!syscall_inst_addr) {
            return InternalCaller(syscall_no, reinterpret_cast<uintptr_t>(&encrypted_manual_syscall_stub), std::forward<ServiceArgs>(args)...);
        }

        return InternalCaller(syscall_no, reinterpret_cast<uintptr_t>(&encrypted_masked_syscall_stub), syscall_inst_addr, std::forward<ServiceArgs>(args)...);
    }
};

}// namespace pigsyscall

#endif //PIG_SYSCALL_HPP_
