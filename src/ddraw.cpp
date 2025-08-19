#include <cstdint>

#include <Windows.h>

#include "utils.h"

namespace
{

auto patch_nullptr_check(
    std::uintptr_t patch_point,
    std::uintptr_t return_1_actual,
    std::uintptr_t return_2_actual,
    std::uintptr_t return_3_actual) -> void
{
    log("patching nullptr check at 0x{:x} with return addresses 0x{:x} and 0x{:x}",
        patch_point,
        return_1_actual,
        return_2_actual);

    const auto fixed_asm_payload = ::VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ensure(fixed_asm_payload != NULL, "failed to allocate memory for fixed assembly");

    const auto return_1 = return_1_actual - reinterpret_cast<std::uintptr_t>(fixed_asm_payload) - 0x5 - 4;
    const auto return_1_addr = reinterpret_cast<const std::uint8_t *>(&return_1);

    const auto return_2 = return_2_actual - reinterpret_cast<std::uintptr_t>(fixed_asm_payload) - 0x5 - 13;
    const auto return_2_addr = reinterpret_cast<const std::uint8_t *>(&return_2);

    const auto return_3 = return_3_actual - reinterpret_cast<std::uintptr_t>(fixed_asm_payload) - 0x5 - 18;
    const auto return_3_addr = reinterpret_cast<const std::uint8_t *>(&return_3);

    // clang-format off
    const std::uint8_t fixed_asm[] = {
        0x83, 0xf9, 0x00, // cmp ecx, 0
        0x0f, 0x84, return_1_addr[0], return_1_addr[1], return_1_addr[2], return_1_addr[3], // jne return_1_actual
        0x3b, 0x4d, 0x90, // cmp ecx, [ebp-0x70] ; original instructions
        0x0f, 0x85, return_2_addr[0], return_2_addr[1], return_2_addr[2], return_2_addr[3], // jne return_2_actual
        0xe9, return_3_addr[0], return_3_addr[1], return_3_addr[2], return_3_addr[3], // jmp return_3_actual
    };
    // clang-format on

    ensure(
        ::WriteProcessMemory(GetCurrentProcess(), fixed_asm_payload, fixed_asm, sizeof(fixed_asm), NULL),
        "failed to write fixed assembly to process memory");

    log("allocated memory for fixed assembly at {}", fixed_asm_payload);

    const auto fixed_asm_adjusted = reinterpret_cast<std::uintptr_t>(fixed_asm_payload) - patch_point - 0x5;
    const auto fixed_asm_addr = reinterpret_cast<const std::uint8_t *>(&fixed_asm_adjusted);

    std::uint8_t jmp_to_fix[] = {0xe9, fixed_asm_addr[0], fixed_asm_addr[1], fixed_asm_addr[2], fixed_asm_addr[3]};

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
}
}

extern "C"
{

__declspec(dllexport) HRESULT WINAPI DirectDrawCreate(GUID FAR *lpGUID, void FAR **lplpDD, IUnknown FAR *pUnkOuter)
{
    log("DirectDrawCreate called");

    patch_nullptr_check(0x10044f03, 0x10044f10, 0x10044ea9, 0x10044f08);
    patch_nullptr_check(0x10044fc6, 0x10044fd3, 0x10044f53, 0x10044fcb);

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
