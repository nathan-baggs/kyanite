#include <chrono>
#include <cstdint>
#include <thread>

#include <Windows.h>

#include "utils.h"

using namespace std::literals;

namespace
{

auto patch_star_init(std::uintptr_t patch_point, std::uintptr_t return_1_actual, std::uintptr_t cmp_address) -> void
{
    log("patching star initialization check at 0x{:x}", patch_point);

    const auto fixed_asm_payload = ::VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ensure(fixed_asm_payload != NULL, "failed to allocate memory for fixed assembly");

    const auto return_1 = return_1_actual - reinterpret_cast<std::uintptr_t>(fixed_asm_payload) - 0x5 - 36;
    const auto return_1_addr = reinterpret_cast<const std::uint8_t *>(&return_1);

    const auto fixed_asm_adjusted = reinterpret_cast<std::uintptr_t>(fixed_asm_payload) - patch_point - 0x5;
    const auto fixed_asm_addr = reinterpret_cast<const std::uint8_t *>(&fixed_asm_adjusted);

    // clang-format off
    const std::uint8_t fixed_asm[] = {
        // original instructions
        0x8b, 0x8d, 0xac, 0xfd, 0xff, 0xff,      // mov ecx,dword ptr [ebp-0x254]
        0x8b, 0x51, 0x1c,                        // mov edx,dword ptr [ecx + 0x1c]
        0xc7, 0x04, 0x82, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [edx + eax*4], 0

        // patched instructions
        0x8b, 0x51, 0x38,                         // mov edx,dword ptr [ecx + 0x38]
        0xc7, 0x04, 0x82, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [edx + eax*4], 0
        0x8b, 0x51, 0x3c,                         // mov edx,dword ptr [ecx + 0x3c]
        0xc7, 0x04, 0x82, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [edx + eax*4], 0

        // jmp back
        0xe9, return_1_addr[0], return_1_addr[1], return_1_addr[2], return_1_addr[3], // jmp return_actual
    };
    // clang-format on

    ensure(
        ::WriteProcessMemory(GetCurrentProcess(), fixed_asm_payload, fixed_asm, sizeof(fixed_asm), NULL),
        "failed to write fixed assembly to process memory");

    std::uint8_t jmp_to_fix[] = {
        0xe9, fixed_asm_addr[0], fixed_asm_addr[1], fixed_asm_addr[2], fixed_asm_addr[3], 0x90};

    const auto patch_point_ptr = reinterpret_cast<std::uintptr_t *>(patch_point);

    auto old_protect = DWORD{};
    ensure(
        ::VirtualProtect(patch_point_ptr, sizeof(jmp_to_fix), PAGE_EXECUTE_READWRITE, &old_protect),
        "failed to change memory protection");

    ensure(
        ::WriteProcessMemory(GetCurrentProcess(), patch_point_ptr, jmp_to_fix, sizeof(jmp_to_fix), NULL),
        "failed to write to process memory");

    ensure(
        ::VirtualProtect(patch_point_ptr, sizeof(jmp_to_fix), old_protect, &old_protect),
        "failed to restore memory protection");

    std::uint8_t nops[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    ensure(
        ::VirtualProtect(reinterpret_cast<void *>(cmp_address), sizeof(nops), PAGE_EXECUTE_READWRITE, &old_protect),
        "failed to change memory protection");

    ensure(
        ::WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(cmp_address), nops, sizeof(nops), NULL),
        "failed to write nops to process memory");

    ensure(
        ::VirtualProtect(reinterpret_cast<void *>(cmp_address), sizeof(nops), old_protect, &old_protect),
        "failed to restore memory protection");
}
}

extern "C"
{

__declspec(dllexport) void *WINAPIV my_new(unsigned int size)
{
    log("my_new called with size {}", size);

    auto *ptr = ::operator new[](size);
    ensure(ptr != nullptr, "failed to allocate memory with new");

    ::memset(ptr, 0, size);

    log("allocated memory at {}", ptr);

    return ptr;
}

__declspec(dllexport) HRESULT WINAPI DirectDrawCreate(GUID FAR *lpGUID, void FAR **lplpDD, IUnknown FAR *pUnkOuter)
{
    log("DirectDrawCreate called");

    patch_star_init(0x100444cf, 0x100444df, 0x1004445d);

    const auto ddraw_dll = ::LoadLibraryA("C:\\Windows\\system32\\ddraw.dll");
    ensure(ddraw_dll != NULL, "failed to load ddraw.dll");

    const auto direct_draw_create =
        reinterpret_cast<decltype(&DirectDrawCreate)>(::GetProcAddress(ddraw_dll, "DirectDrawCreate"));
    ensure(direct_draw_create != NULL, "failed to get address of DirectDrawCreate");

    return direct_draw_create(lpGUID, lplpDD, pUnkOuter);
}

__declspec(dllexport) HRESULT WINAPI DirectDrawEnumerateA(void *lpCallback, LPVOID lpContext)
{
    log("DirectDrawEnumerateA called");

    const auto ddraw_dll = ::LoadLibrary("C:\\windows\\system32\\ddraw.dll");
    ensure(ddraw_dll != NULL, "failed to load ddraw.dll");

    const auto direct_draw_enumerate =
        reinterpret_cast<decltype(&DirectDrawEnumerateA)>(::GetProcAddress(ddraw_dll, "DirectDrawEnumerateA"));
    ensure(direct_draw_enumerate != NULL, "failed to get address of DirectDrawEnumerateA");

    return direct_draw_enumerate(lpCallback, lpContext);
}

DWORD WINAPI DllMain(void *hinstDLL, DWORD fdwReason, void *lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            log("DllMain called with DLL_PROCESS_ATTACH");
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH: break;
    }

    return 1;
}
}
