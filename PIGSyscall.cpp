#include "pigsyscall.hpp"
#include "util.hpp"

//stub in .text section
#define ALLOC_ON_CODE \
_Pragma("section(\".text\")") \
__declspec(allocate(".text"))


#define HASH(API)		(utils::_HashStringRotr32A((PCHAR) API))

//ALLOC_ON_CODE unsigned char manual_syscall_stub[] = {
//    0x48, 0x89, 0xC8,                                    // mov rax, rcx
//    0x48, 0x89, 0xD1,                                    // mov rcx, rdx
//    0x4C, 0x89, 0xC2,                                    // mov rdx, r8
//    0x4D, 0x89, 0xC8,                                    // mov r8, r9
//    0x4C, 0x8B, 0x4C, 0x24, 0x28,                        // mov r9, [rsp+28h]
//    0x49, 0x89, 0xCA,                                    // mov r10, rcx
//    0x48, 0x83, 0xC4, 0x08,                              // add rsp, 8
//    0x0F, 0x05,                                          // syscall
//    0x48, 0x83, 0xEC, 0x08,                              // sub rsp, 8
//    0xC3                                                 // ret
//};

ALLOC_ON_CODE unsigned char encrypted_manual_syscall_stub[] = {

    0x07, 0xb0, 0xe0, 0x07, 0xb0, 0x40, 0x85, 0xb0, 0xed, 0x9b, 0xb0, 0xe0, 0x85, 0xf5, 0x85, 0xdb, 
    0x48, 0xc9, 0xb0, 0x33, 0x07, 0x4f, 0x37, 0xf4, 0x5d, 0x21, 0x07, 0x4f, 0xff, 0xf4, 0x1d
};

// 充当一个 trampoline 到另一个系统调用
//ALLOC_ON_CODE unsigned char masked_syscall_stub[] = {
//    0x41, 0x55,                                          // push r13          //入栈
//    0x41, 0x56,                                          // push r14          //入栈
//    0x49, 0x89, 0xD6,                                    // mov r14, rdx      //第二个参数 是syscall指令地址
//    0x49, 0x89, 0xCD,                                    // mov r13, rcx      //第一个参数 是SSN
//    0x4C, 0x89, 0xC1,                                    // mov rcx, r8       //真正的第1个参数 
//    0x4C, 0x89, 0xCA,                                    // mov rdx, r9       //真正的第2个参数 
//    0x4C, 0x8B, 0x44, 0x24, 0x38,                        // mov r8, [rsp+38h]   //真正的第3个参数 
//    0x4C, 0x8B, 0x4C, 0x24, 0x40,                        // mov r9, [rsp+40h]   //真正的第4个参数 
//    0x48, 0x83, 0xC4, 0x28,                              // add rsp, 28h        //栈顶指针向下移动 堆栈平衡
//    0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00,            // lea r11, [rip+0x0C] ----
//    0x41, 0xFF, 0xD3,                                    // call r11               |  //调用
//    0x48, 0x83, 0xEC, 0x28,                              // sub rsp, 28h           |  //栈顶指针向上移动 堆栈平衡
//    0x41, 0x5E,                                          // pop r14                |  //
//    0x41, 0x5D,                                          // pop r13                |  //还原上下文
//    0xC3,                                                // ret                    |
//                                                                                   |
//    0x4C, 0x89, 0xE8,                                    // mov rax, r13      <----   //SSN
//    0x49, 0x89, 0xCA,                                    // mov r10, rcx              //
//    0x41, 0xFF, 0xE6                                     // jmp r14                   //jmp到syscall指令进入x64快速系统调用
//};

ALLOC_ON_CODE unsigned char encrypted_masked_syscall_stub[] = {

    0xd3, 0xab, 0xd3, 0x89, 0xc9, 0xb0, 0x73, 0xc9, 0xb0, 0x6c, 0x85, 0xb0, 0xfc, 0x85, 0xb0, 0x33,
    0x85, 0xf5, 0x45, 0xdb, 0xb1, 0x85, 0xf5, 0x85, 0xdb, 0xaa, 0x07, 0x4f, 0x37, 0x48, 0x85, 0x6d,
    0x2d, 0x7f, 0x41, 0x41, 0x41, 0xd3, 0x3d, 0x6f, 0x07, 0x4f, 0xff, 0x48, 0xd3, 0x42, 0xd3, 0x66,
    0x1d, 0x85, 0xb0, 0x14, 0xc9, 0xb0, 0x33, 0xd3, 0x3d, 0x03
};

ALLOC_ON_CODE unsigned char WorkCallback_stub[] = {

    0x48, 0x89, 0xd3,                                       // mov rbx, rdx
    0x48, 0x8b, 0x03,                                       // mov rax, QWORD PTR[rbx]
    0x48, 0x8b, 0x4b, 0x08,                                 // mov rcx, QWORD PTR[rbx + 0x8]
    0x48, 0x8b, 0x53, 0x10,                                 // mov rdx, QWORD PTR[rbx + 0x10]
    0x4c, 0x8b, 0x43, 0x18,                                 // mov r8,  QWORD PTR [rbx+0x18]
    0x4c, 0x8b, 0x4b, 0x20,                                 // mov r9,  QWORD PTR[rbx + 0x20]

    0x4c, 0x8b, 0x53, 0x30,                                 // mov r10, QWORD PTR[rbx + 0x30]
    0x4c, 0x89, 0x54, 0x24, 0x30,                           // mov QWORD PTR[rsp + 0x30], r10
    0x4c, 0x8b, 0x53, 0x28,                                 // mov r10, QWORD PTR [rbx+0x28]
    0x4c, 0x89, 0x54, 0x24, 0x28,                           // mov QWORD PTR[rsp + 0x28], r10

    0xff, 0xe0                                              // jmp rax

};


//MDSec get SSN and save to map
void pigsyscall::syscall::ExtractSSNs() noexcept {  
    const auto peb = reinterpret_cast<native::PEB*>(__readgsqword(0x60));
    const auto ntdll_ldr_entry = reinterpret_cast<native::LdrDataEntry*>(peb->Ldr->InLoadOrderModuleList.Flink->Flink);
    const auto ntdll_base = reinterpret_cast<uintptr_t>(ntdll_ldr_entry->DllBase);
    const auto dos_header = reinterpret_cast<native::DOSHeader*>(ntdll_base);
    const auto nt_headers = reinterpret_cast<native::NTHeaders64*>(ntdll_base + dos_header->e_lfanew);

    const auto
        export_dir = reinterpret_cast<native::ExportDirectory*>(ntdll_base + nt_headers->OptionalHeader.DataDirectory[native::kExport].VirtualAddress);

    //runtime function table
    const auto
        runtimefunctable = reinterpret_cast<native::RuntimeFunctionTable*>(ntdll_base + nt_headers->OptionalHeader.DataDirectory[native::kException].VirtualAddress);

    const auto functions_table = reinterpret_cast<uint32_t*>(ntdll_base + export_dir->AddressOfFunctions);
    const auto names_table = reinterpret_cast<uint32_t*>(ntdll_base + export_dir->AddressOfNames);
    const auto names_ordinals_table = reinterpret_cast<uint16_t*>(ntdll_base + export_dir->AddressOfNameOrdinals);

    int ssn = 0;

    for (size_t i = 0; i < runtimefunctable[i].BeginAddress; i++)
    {
        for (size_t j = 0; j < export_dir->NumberOfFunctions; j++)
        {
            if (functions_table[names_ordinals_table[j]] == runtimefunctable[i].BeginAddress) {
                auto function_name = reinterpret_cast<PCHAR>(ntdll_base + names_table[j]);

                //insert to map
                syscall_map.insert({ HASH(function_name), ssn });

                // if this is a syscall, increase the ssn value.
                if (*(USHORT*)function_name == 'wZ') ssn++;
            }
        }
    }

}

uintptr_t pigsyscall::syscall::FindSyscallOffset() noexcept {

    INT64 offset = 0;
    BYTE syscall_signature[] = { (BYTE)0x0F, (BYTE)0x05, (BYTE)0xC3 };

    const auto peb = reinterpret_cast<native::PEB*>(__readgsqword(0x60));
    const auto ntdll_ldr_entry = reinterpret_cast<native::LdrDataEntry*>(peb->Ldr->InLoadOrderModuleList.Flink->Flink);
    const auto ntdll_base = reinterpret_cast<uintptr_t>(ntdll_ldr_entry->DllBase);
    const auto dos_header = reinterpret_cast<native::DOSHeader*>(ntdll_base);
    const auto nt_headers = reinterpret_cast<native::NTHeaders64*>(ntdll_base + dos_header->e_lfanew);
    const auto opt_headers = (nt_headers->OptionalHeader);
    INT64 dllSize = opt_headers.SizeOfImage;

    BYTE* currentbytes = (BYTE*)ntdll_base;

    while (TRUE)
    {

        if (*(reinterpret_cast<BYTE*>(currentbytes    )) == syscall_signature[0] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 1)) == syscall_signature[1] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 2)) == syscall_signature[2])
        {
            return ntdll_base + offset;
        }

        offset++;

        if (offset + 3 > dllSize)
            return INFINITE;

        currentbytes = reinterpret_cast<BYTE*>(ntdll_base + offset);
    }


};

//get SSN from map
[[nodiscard]] uint32_t pigsyscall::syscall::GetSyscallNumber(uint32_t function_name_hashed) {
    const auto syscall_entry = syscall_map.find(function_name_hashed);

    if (syscall_entry == syscall_map.end()) {
        throw std::runtime_error(utils::FormatString("[pigsyscall::Syscall::GetSyscallNumber] Function \"%s\" not found!", function_name_hashed));
    }

    return syscall_entry->second;
}

